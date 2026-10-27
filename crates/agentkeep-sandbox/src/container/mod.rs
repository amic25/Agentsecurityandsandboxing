//! The container backend: Podman or Docker, driven through its CLI, on a
//! Linux host.
//!
//! The container is built from the same [`LaunchPlan`] as the Linux
//! backend: an empty image (created locally, never pulled), the plan's host
//! paths bind-mounted at the same places, tmpfs where the plan says tmpfs,
//! `--network none`, no capabilities, `no-new-privileges`, a read-only root.
//! PID 1 is agentkeep itself (`__container-init`), bind-mounted from the
//! host, which adds the relay, rlimits, Landlock and agentkeep's seccomp
//! deny-list on top of the runtime's own profile.
//!
//! Linux hosts only: init must be a Linux agentkeep binary from the host,
//! and the proxy, approval and lifeline channels are Unix sockets, which do
//! not cross the VM boundary of Docker Desktop or a remote daemon.
//!
//! Deliberate deviation from passing the environment with `--env-file`:
//! nothing of the command's environment is handed to the runtime. It
//! travels inside the plan file (0600, bind-mounted read-only), exactly as
//! the Linux backend hands its init the plan through a file descriptor.
//! Reasons: (1) PID 1 is agentkeep, and like the Linux init it must start
//! with a clean environment, since `LD_PRELOAD` and friends would be honoured
//! by the dynamic loader for it (threat E2); (2) the env-file format cannot
//! carry a value with a newline, and a value containing
//! `\nLD_PRELOAD=...` would inject a variable; (3) the runtime would keep
//! a copy in its container store, readable through `inspect`.

pub mod args;
pub mod init;
pub mod runtime;

use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, ChildStderr, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::linux::{landlock_rules, sys};
use crate::plan::LaunchPlan;
use crate::probe::{Capabilities, Degradation, Probe};
use crate::{Backend, Error, ExitStatus, SandboxHandle, TimerGuard};

use self::args::{Identity, SessionFiles, Settings};
use self::runtime::{Info, Kind, Runtime};

/// How long the container may take to report `READY`. The first run also
/// imports the empty image.
const STARTUP_TIMEOUT: Duration = Duration::from_mins(2);

/// How much of the runtime's error output is kept for an error message.
const STDERR_KEEP: usize = 64 << 10;

/// The container backend.
#[derive(Debug, Default)]
pub struct ContainerBackend {
    /// What the last probe found, reused by `launch` so the runtime is
    /// asked once per session.
    info: Mutex<Option<Info>>,
}

fn degradations(info: &Info, caps: &Capabilities) -> Vec<Degradation> {
    let rt = info.runtime.kind.name();
    let mut d = Vec::new();
    if !info.rootless {
        d.push(Degradation {
            control: "container_runtime".into(),
            fallback: format!(
                "rootful {rt}: no user namespace; the command runs with the invoking user's host uid"
            ),
            reason: "a container escape is root on the host; prefer rootless Podman".into(),
        });
    }
    if info.gvisor {
        d.push(Degradation {
            control: "gvisor".into(),
            fallback: "runc-class runtime with its seccomp profile plus agentkeep's deny-list"
                .into(),
            reason: format!(
                "runsc is available to {rt} but agentkeep cannot select it yet: the sandbox needs host Unix sockets, which gVisor refuses by default (docs/limitations.md)"
            ),
        });
    }
    if !info.limits {
        d.push(Degradation {
            control: "cgroup".into(),
            fallback: "rlimits: RLIMIT_AS for memory (address space, approximate), RLIMIT_NPROC for pids (per host uid without a user namespace); cpu_percent unenforced".into(),
            reason: format!("{rt} does not enforce memory and pid limits on this host"),
        });
    }
    if caps.landlock_abi == 0 {
        d.push(Degradation {
            control: "landlock".into(),
            fallback: "mount namespace only".into(),
            reason: "kernel has no Landlock (needs 5.13+ with lsm=landlock)".into(),
        });
    }
    if !caps.seccomp {
        d.push(Degradation {
            control: "seccomp".into(),
            fallback: "the runtime's profile only, if any".into(),
            reason: "kernel built without seccomp filter support".into(),
        });
    }
    d
}

fn capabilities(info: &Info) -> Capabilities {
    Capabilities {
        mount_namespace: true,
        pid_namespace: true,
        net_namespace: true,
        landlock_abi: landlock_rules::kernel_abi(),
        seccomp: crate::linux::seccomp_available(),
        cgroup_v2: info.limits,
        rlimits: true,
        no_new_privs: true,
        seatbelt: false,
        container_runtime: Some(info.runtime.kind.name().to_string()),
    }
}

impl Backend for ContainerBackend {
    fn name(&self) -> &'static str {
        "container"
    }

    fn probe(&self) -> Probe {
        match runtime::detect() {
            Err(reason) => Probe::unavailable(reason),
            Ok(info) => {
                let caps = capabilities(&info);
                let degradations = degradations(&info, &caps);
                if let Ok(mut g) = self.info.lock() {
                    *g = Some(info);
                }
                Probe::Available {
                    capabilities: caps,
                    degradations,
                }
            }
        }
    }

    fn launch(&self, plan: &LaunchPlan) -> Result<Box<dyn SandboxHandle>, Error> {
        let cached = self.info.lock().ok().and_then(|g| g.clone());
        let info = match cached {
            Some(i) => i,
            None => runtime::detect().map_err(|reason| Error::Unavailable {
                backend: "container",
                reason,
            })?,
        };
        launch(plan, &info)
    }
}

/// Container names allow `[a-zA-Z0-9][a-zA-Z0-9_.-]*`.
fn container_name(session: &str) -> String {
    let clean: String = session
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("agentkeep-{clean}")
}

/// Who the command runs as, given the runtime's mode (see
/// [`Identity`]).
fn identity(info: &Info, plan: &LaunchPlan) -> Identity {
    match (info.runtime.kind, info.rootless) {
        (Kind::Podman, true) => Identity::KeepId {
            uid: plan.inner_uid,
            gid: plan.inner_gid,
        },
        (Kind::Docker, true) => Identity::User { uid: 0, gid: 0 },
        (_, false) => Identity::User {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
        },
    }
}

/// `/etc/passwd` and `/etc/group` mapping the run-as uid to the plan's
/// user name, as `linux::mounts` writes them.
fn identity_files(plan: &LaunchPlan, (uid, gid): (u32, u32)) -> (String, String) {
    let user = format!(
        "{name}:x:{uid}:{gid}:agentkeep user:{home}:/bin/sh\n",
        name = plan.user_name,
        home = plan.home.display()
    );
    let group = format!("{name}:x:{gid}:\n", name = plan.user_name);
    let (root_user, root_group) = if uid == 0 {
        (String::new(), String::new())
    } else {
        (
            "root:x:0:0:root:/root:/bin/sh\n".to_string(),
            "root:x:0:\n".to_string(),
        )
    };
    (
        format!("{root_user}{user}nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"),
        format!("{root_group}{group}nogroup:x:65534:\n"),
    )
}

fn write_file(path: &Path, content: &[u8], mode: u32) -> Result<(), Error> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| Error::io(format!("create {}", path.display()), e))?;
    f.write_all(content)
        .map_err(|e| Error::io(format!("write {}", path.display()), e))
}

/// The plan init receives: limits the runtime's cgroup enforces are cleared
/// so init does not also impose rlimits for them. `RLIMIT_NPROC` in
/// particular would count every host process of the uid when the
/// container shares the host's user namespace.
fn effective_plan(plan: &LaunchPlan, info: &Info) -> LaunchPlan {
    let mut p = plan.clone();
    if info.limits {
        p.limits.memory = None;
        p.limits.pids = None;
    }
    p
}

/// Write the session files into `plan.root_base` (a fresh 0700 directory
/// of the supervisor's session) and bind the lifeline socket.
fn prepare_session(
    plan: &LaunchPlan,
    info: &Info,
    ids: (u32, u32),
) -> Result<(SessionFiles, UnixListener), Error> {
    let base = &plan.root_base;
    if !base.is_dir() {
        return Err(Error::Plan(format!(
            "root_base {} is not a directory",
            base.display()
        )));
    }
    let files = SessionFiles {
        plan: base.join("plan.json"),
        lifeline: base.join("lifeline.sock"),
        empty: base.join("empty"),
        bin: base.join("bin"),
        passwd: base.join("passwd"),
        group: base.join("group"),
    };
    write_file(
        &files.plan,
        effective_plan(plan, info).to_json()?.as_bytes(),
        0o600,
    )?;
    write_file(&files.empty, b"", 0o444)?;
    let (passwd, group) = identity_files(plan, ids);
    write_file(&files.passwd, passwd.as_bytes(), 0o644)?;
    write_file(&files.group, group.as_bytes(), 0o644)?;
    fs::create_dir(&files.bin).map_err(|e| Error::io("create shim directory", e))?;
    if let Some(shim) = &plan.shim {
        for cmd in &shim.commands {
            if cmd.contains('/') || cmd.is_empty() {
                continue;
            }
            std::os::unix::fs::symlink(args::EXE, files.bin.join(cmd))
                .map_err(|e| Error::io(format!("shim {cmd}"), e))?;
        }
    }
    fs::set_permissions(&files.bin, fs::Permissions::from_mode(0o755))
        .map_err(|e| Error::io("chmod shim directory", e))?;
    let listener =
        UnixListener::bind(&files.lifeline).map_err(|e| Error::io("bind lifeline socket", e))?;
    // Polled while the runtime starts, so a failed start is noticed.
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::io("lifeline nonblocking", e))?;
    Ok((files, listener))
}

/// Copies the runtime CLI's stderr to ours. Until the container reports
/// `READY` it only buffers, so a failed start becomes one error message
/// instead of interleaved noise; afterwards it passes everything through.
struct StderrRelay {
    state: Arc<Mutex<RelayState>>,
    thread: Option<JoinHandle<()>>,
}

enum RelayState {
    Buffer(Vec<u8>),
    Pass,
}

impl StderrRelay {
    fn start(mut stderr: ChildStderr) -> Self {
        let state = Arc::new(Mutex::new(RelayState::Buffer(Vec::new())));
        let st = Arc::clone(&state);
        let thread = std::thread::Builder::new()
            .name("agentkeep-runtime-stderr".into())
            .spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    let n = match stderr.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let Ok(mut g) = st.lock() else { break };
                    match &mut *g {
                        RelayState::Buffer(v) => {
                            let room = STDERR_KEEP.saturating_sub(v.len());
                            v.extend_from_slice(&buf[..n.min(room)]);
                        }
                        RelayState::Pass => {
                            let _ = std::io::stderr().write_all(&buf[..n]);
                        }
                    }
                }
            })
            .ok();
        Self { state, thread }
    }

    /// Flush what was buffered and pass everything through from now on.
    fn release(&self) {
        if let Ok(mut g) = self.state.lock() {
            if let RelayState::Buffer(v) = &*g {
                let _ = std::io::stderr().write_all(v);
            }
            *g = RelayState::Pass;
        }
    }

    /// Wait for the stream to end; return what was buffered, if anything.
    fn finish(&mut self) -> String {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        match self.state.lock().as_deref() {
            Ok(RelayState::Buffer(v)) => String::from_utf8_lossy(v).trim().to_string(),
            _ => String::new(),
        }
    }
}

/// Read one status line from init, giving up at `deadline`.
fn read_status(stream: &UnixStream, deadline: Instant) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    let mut s = stream;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("timed out waiting for the container to start".into());
        }
        s.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        match s.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if line.len() < 64 << 10 => line.push(byte[0]),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("reading container status: {e}")),
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Start the container and wait until init reports `READY`.
///
/// Every failure path removes the container before returning, so nothing
/// is left behind.
#[allow(clippy::too_many_lines)] // the startup handshake reads best in one place
fn launch(plan: &LaunchPlan, info: &Info) -> Result<Box<dyn SandboxHandle>, Error> {
    // A container outlives an interrupted supervisor, so Ctrl-C must not
    // kill the supervisor mid-start. This is what `agentkeep run` installs
    // right after launch anyway; doing it first closes the window.
    crate::linux::install_supervisor_signals();

    let rt = info.runtime.clone();
    runtime::ensure_image(&rt).map_err(Error::Setup)?;

    let ident = identity(info, plan);
    let (files, listener) = prepare_session(plan, info, ident.ids())?;
    let settings = Settings {
        kind: rt.kind,
        identity: ident,
        tty: std::io::stdin().is_terminal(),
        image: runtime::IMAGE.to_string(),
        name: container_name(&plan.session_id),
        limits: info.limits,
        swap_limit: info.swap_limit,
        cgroup_v2: info.cgroup_v2,
        ncpu: info.ncpu,
        landlock_abi: if plan.landlock {
            landlock_rules::kernel_abi()
        } else {
            0
        },
        files,
    };
    let host = |p: &Path| fs::metadata(p).ok().map(|m| m.is_dir());
    let argv = args::build(plan, &settings, &host)?;
    let name = settings.name.clone();

    let mut child = rt
        .command()
        .args(&argv)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::io(format!("start {}", rt.path.display()), e))?;
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        rt.force_remove(&name);
        return Err(Error::Setup("runtime stderr unavailable".into()));
    };
    let mut relay = StderrRelay::start(stderr);

    // Clean up and describe a failed start.
    let fail = |child: &mut Child, relay: &mut StderrRelay, why: String| -> Error {
        let _ = child.kill();
        let status = child.wait().ok();
        rt.force_remove(&name);
        let stderr = relay.finish();
        let code = status
            .and_then(|s| s.code())
            .map(|c| format!(" (exit {c})"))
            .unwrap_or_default();
        Error::Setup(if stderr.is_empty() {
            format!("{why}{code}")
        } else {
            format!("{why}{code}: {stderr}")
        })
    };

    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                return Err(fail(
                    &mut child,
                    &mut relay,
                    format!("lifeline accept: {e}"),
                ));
            }
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                let why = format!("{} run failed before the container started", rt.kind.name());
                return Err(fail(&mut child, &mut relay, why));
            }
            Ok(None) => {}
            Err(e) => return Err(fail(&mut child, &mut relay, format!("wait: {e}"))),
        }
        let sig = sys::PENDING_SIGNAL.load(Ordering::SeqCst);
        if sig != 0 {
            return Err(fail(
                &mut child,
                &mut relay,
                format!("interrupted by signal {sig} while starting"),
            ));
        }
        if Instant::now() >= deadline {
            let why = format!(
                "the container did not start within {}s",
                STARTUP_TIMEOUT.as_secs()
            );
            return Err(fail(&mut child, &mut relay, why));
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    // Nothing else may connect: the agent can see the socket file.
    drop(listener);
    let _ = stream.set_nonblocking(false);

    let line = match read_status(&stream, deadline) {
        Ok(l) => l,
        Err(why) => return Err(fail(&mut child, &mut relay, why)),
    };
    if line != "READY" {
        let why = line.strip_prefix("ERR ").map_or_else(
            || "container init exited before reporting".to_string(),
            ToString::to_string,
        );
        return Err(fail(&mut child, &mut relay, why));
    }
    let _ = stream.set_read_timeout(None);
    relay.release();

    Ok(Box::new(ContainerHandle {
        runtime: rt,
        name,
        child,
        lifeline: Some(stream),
        relay,
        timed_out: Arc::new(AtomicBool::new(false)),
        status: None,
    }))
}

/// A running container.
///
/// The handle holds the lifeline: dropping it (or the supervisor dying)
/// makes init kill everything in the container.
pub struct ContainerHandle {
    runtime: Runtime,
    name: String,
    child: Child,
    lifeline: Option<UnixStream>,
    relay: StderrRelay,
    timed_out: Arc<AtomicBool>,
    status: Option<ExitStatus>,
}

impl ContainerHandle {
    fn cli_pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap_or(0)
    }
}

impl SandboxHandle for ContainerHandle {
    /// Host PID of the runtime CLI process that owns the container.
    fn pid(&self) -> i32 {
        self.cli_pid()
    }

    fn wait(&mut self) -> Result<ExitStatus, Error> {
        if let Some(s) = self.status {
            return Ok(s);
        }
        let raw = loop {
            match sys::wait_pid(self.cli_pid()) {
                Ok(raw) => break raw,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => {
                    // Forward a termination request to init, which passes
                    // it to the command.
                    let sig = sys::PENDING_SIGNAL.swap(0, Ordering::SeqCst);
                    if sig != 0 {
                        let _ = self
                            .runtime
                            .quiet(&["kill", "--signal", "TERM", &self.name]);
                    }
                }
                Err(e) => return Err(Error::io("wait for container runtime", e)),
            }
        };
        let decoded = sys::decode_status(raw);
        // The CLI exits after the runtime removed the container (`--rm`).
        // If it was killed instead, the container may still exist.
        if matches!(decoded, ExitStatus::Signal(_)) {
            drop(self.lifeline.take());
            let _ = self.runtime.quiet(&["kill", &self.name]);
            self.runtime.force_remove(&self.name);
        }
        drop(self.lifeline.take());
        let _ = self.relay.finish();
        let status = if self.timed_out.load(Ordering::SeqCst) {
            ExitStatus::WallTimeExceeded
        } else {
            decoded
        };
        self.status = Some(status);
        Ok(status)
    }

    fn kill(&self) -> Result<(), Error> {
        if self.runtime.quiet(&["kill", &self.name]) {
            Ok(())
        } else {
            Err(Error::Setup(format!(
                "`{} kill {}` failed",
                self.runtime.kind.name(),
                self.name
            )))
        }
    }

    fn kill_after(&self, after: Duration) -> TimerGuard {
        let (tx, rx) = mpsc::channel::<()>();
        let flag = Arc::clone(&self.timed_out);
        let rt = self.runtime.clone();
        let name = self.name.clone();
        std::thread::spawn(move || {
            if rx.recv_timeout(after).is_err() {
                flag.store(true, Ordering::SeqCst);
                let _ = rt.quiet(&["kill", &name]);
            }
        });
        TimerGuard::new(Some(tx))
    }
}

impl Drop for ContainerHandle {
    fn drop(&mut self) {
        if self.status.is_some() {
            return;
        }
        // Dropped without wait (the supervisor bailed out): closing the
        // lifeline makes init kill everything; the explicit kill and remove
        // cover a runtime that is slow to notice.
        drop(self.lifeline.take());
        let _ = self.runtime.quiet(&["kill", &self.name]);
        let _ = self.child.kill();
        let _ = sys::wait_pid(self.cli_pid());
        self.runtime.force_remove(&self.name);
        let _ = self.relay.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_valid_container_names() {
        assert_eq!(
            container_name("20260101T000000-42"),
            "agentkeep-20260101T000000-42"
        );
        assert_eq!(container_name("a b/c"), "agentkeep-a-b-c");
    }

    #[test]
    fn identity_files_resolve_the_run_as_uid() {
        let mut plan: LaunchPlan = serde_json::from_value(serde_json::json!({
            "session_id": "s", "mounts": [], "project": "/p", "home": "/home/u",
            "env": {}, "cwd": "/p", "command": ["true"], "limits": {"cpu_percent": null,
            "memory": null, "pids": null, "wall_time_secs": null}, "hostname": "h",
            "self_exe": "/a", "root_base": "/r", "user_name": "u", "approval_socket": null,
            "shim": null, "proxy": null, "landlock": true, "seccomp": true,
            "inner_uid": 1000, "inner_gid": 1000
        }))
        .unwrap();
        let (passwd, group) = identity_files(&plan, (1234, 1234));
        assert!(passwd.contains("u:x:1234:1234:agentkeep user:/home/u:/bin/sh"));
        assert!(passwd.starts_with("root:x:0:0"));
        assert!(group.contains("u:x:1234:"));
        let (passwd, _) = identity_files(&plan, (0, 0));
        assert!(
            passwd.starts_with("u:x:0:0:"),
            "uid 0 resolves to the user name"
        );
        assert!(!passwd.contains("root:"));
        plan.limits.pids = Some(64);
        plan.limits.memory = Some(1 << 30);
        let info = Info {
            runtime: Runtime {
                kind: Kind::Docker,
                path: "/usr/bin/docker".into(),
            },
            rootless: false,
            cgroup_v2: true,
            limits: true,
            swap_limit: true,
            ncpu: 4,
            gvisor: false,
            version: String::new(),
        };
        let eff = effective_plan(&plan, &info);
        assert_eq!((eff.limits.pids, eff.limits.memory), (None, None));
        let info = Info {
            limits: false,
            ..info
        };
        assert_eq!(effective_plan(&plan, &info).limits.pids, Some(64));
    }
}
