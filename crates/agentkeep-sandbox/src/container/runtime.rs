//! Talking to the container runtime through its CLI.
//!
//! agentkeep never opens the daemon socket itself: every interaction is a
//! `podman` or `docker` command, so the user's own configuration (contexts,
//! rootless sockets, credentials) applies unchanged and agentkeep carries no
//! API client.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// How long `<runtime> info` may take before the runtime counts as broken.
pub const INFO_TIMEOUT: Duration = Duration::from_secs(5);

/// The only image the backend runs: an empty root filesystem it imports
/// itself. Everything the command sees is bind-mounted from the host plan.
/// The `localhost/` registry part keeps the name from ever resolving to a
/// public registry; `--pull never` makes sure nothing is fetched anyway.
pub const IMAGE: &str = "localhost/agentkeep/empty:1";

/// An empty tar archive: end-of-archive blocks padded to one 10 KiB record,
/// which is what `tar -cf - --files-from /dev/null` writes.
pub const EMPTY_TAR_LEN: usize = 10_240;

/// Layer digest of [`EMPTY_TAR_LEN`] zero bytes (sha256 of the uncompressed
/// layer, which is how both runtimes name layers). An image under
/// [`IMAGE`] with any other content is refused.
pub const EMPTY_LAYER: &str =
    "sha256:84ff92691f909a05b224e1c56abb4864f01b4f8e3c854e4bb4c7baf1d3f6d652";

/// Which runtime CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `podman`.
    Podman,
    /// `docker`.
    Docker,
}

impl Kind {
    /// The binary and capability name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Podman => "podman",
            Self::Docker => "docker",
        }
    }
}

/// A runtime CLI found on `PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runtime {
    /// Which one.
    pub kind: Kind,
    /// Absolute path of the binary, resolved once so a later `PATH` change
    /// cannot swap it.
    pub path: PathBuf,
}

impl Runtime {
    /// A command for this runtime with stdin closed. Output streams are left
    /// to the caller.
    ///
    /// The CLI inherits the user's environment (its contexts, rootless
    /// socket and storage settings live there) minus the dynamic loader's
    /// controls: agentkeep never hands `LD_PRELOAD` and friends to a process
    /// it starts (threat E2), and this one runs outside the sandbox.
    pub fn command(&self) -> Command {
        let mut c = Command::new(&self.path);
        c.stdin(Stdio::null());
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("LD_") {
                c.env_remove(name);
            }
        }
        if self.kind == Kind::Podman {
            // Rootless Podman finds the user's subordinate id ranges by the
            // name in `USER` when set, which can be stale (`su`, `sudo -E`)
            // and then yields a mapping without container root. Without it,
            // Podman looks the name up from the real uid.
            c.env_remove("USER");
        }
        c
    }

    /// Run `args` quietly and report whether it succeeded. Used for
    /// best-effort cleanup, where failure (the container is already gone)
    /// is the normal case.
    pub fn quiet(&self, args: &[&str]) -> bool {
        self.command()
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Remove a container whatever state it is in. Idempotent.
    pub fn force_remove(&self, name: &str) {
        let _ = self.quiet(&["rm", "--force", name]);
    }
}

/// What the probe learned about the runtime. Every field comes from the
/// runtime's own `info` output, never from assumptions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent facts about the runtime
pub struct Info {
    /// The CLI.
    pub runtime: Runtime,
    /// Containers run in a user namespace owned by the invoking user.
    pub rootless: bool,
    /// The runtime manages cgroup v2 (as opposed to v1).
    pub cgroup_v2: bool,
    /// `--memory` and `--pids-limit` are enforced by the runtime's cgroup.
    pub limits: bool,
    /// `--memory-swap` is enforced (so swap can be disabled).
    pub swap_limit: bool,
    /// CPUs the runtime can schedule on, for clamping `--cpus`.
    pub ncpu: u32,
    /// gVisor (`runsc`) is registered with the runtime.
    pub gvisor: bool,
    /// Runtime version, for logs.
    pub version: String,
}

/// Find `name` in `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(name);
        is_executable(&candidate).then_some(candidate)
    })
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Output of a command that was given a deadline.
pub struct Captured {
    /// Exit code, `None` if killed by a signal.
    pub code: Option<i32>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// Run `cmd` with `input` on stdin, kill it after `timeout`. Output is read
/// on helper threads so a chatty command cannot deadlock on a full pipe.
pub fn run_with_timeout(
    mut cmd: Command,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Captured, String> {
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let out_t = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(o) = out.as_mut() {
            let _ = o.read_to_string(&mut s);
        }
        s
    });
    let err_t = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(e) = err.as_mut() {
            let _ = e.read_to_string(&mut s);
        }
        s
    });
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        // A runtime that exits early closes the pipe; its exit status then
        // says why, so a write error here is not the interesting one.
        let _ = stdin.write_all(bytes);
    }
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(e.to_string()),
        }
    };
    let stdout = out_t.join().unwrap_or_default();
    let stderr = err_t.join().unwrap_or_default();
    match status {
        Some(st) => Ok(Captured {
            code: st.code(),
            stdout,
            stderr,
        }),
        None => Err(format!("timed out after {}s", timeout.as_secs())),
    }
}

/// First non-empty line of a runtime's error output, for one-line reasons.
pub fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
        .to_string()
}

/// The release string of the running kernel.
fn host_kernel() -> String {
    rustix::system::uname()
        .release()
        .to_string_lossy()
        .into_owned()
}

/// Probe one runtime: binary present and `info` answers within
/// [`INFO_TIMEOUT`].
fn probe_one(kind: Kind) -> Result<Info, String> {
    let path = which(kind.name()).ok_or_else(|| "not on PATH".to_string())?;
    let runtime = Runtime { kind, path };
    let mut cmd = runtime.command();
    match kind {
        Kind::Docker => cmd.args(["info", "--format", "{{json .}}"]),
        Kind::Podman => cmd.args(["info", "--format", "json"]),
    };
    let out = run_with_timeout(cmd, None, INFO_TIMEOUT)
        .map_err(|e| format!("`{} info` failed: {e}", kind.name()))?;
    if out.code != Some(0) {
        return Err(format!(
            "`{} info` failed: {}",
            kind.name(),
            first_line(&out.stderr)
        ));
    }
    let json: Value = serde_json::from_str(&out.stdout)
        .map_err(|e| format!("`{} info` output unreadable: {e}", kind.name()))?;
    match kind {
        Kind::Docker => parse_docker_info(runtime, &json, &host_kernel()),
        Kind::Podman => parse_podman_info(runtime, &json, &host_kernel()),
    }
}

/// Pick the runtime: `AGENTKEEP_CONTAINER_RUNTIME` (`podman` or `docker`)
/// when set, otherwise Podman if it works, then Docker.
pub fn detect() -> Result<Info, String> {
    let forced = std::env::var("AGENTKEEP_CONTAINER_RUNTIME")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let order: Vec<Kind> = match forced.as_deref().map(str::trim) {
        Some("podman") => vec![Kind::Podman],
        Some("docker") => vec![Kind::Docker],
        Some(other) => {
            return Err(format!(
                "AGENTKEEP_CONTAINER_RUNTIME=`{other}` is not `podman` or `docker`"
            ))
        }
        None => vec![Kind::Podman, Kind::Docker],
    };
    let mut reasons = Vec::new();
    for kind in order {
        match probe_one(kind) {
            Ok(info) => return Ok(info),
            Err(r) => reasons.push(format!("{}: {r}", kind.name())),
        }
    }
    Err(format!(
        "no usable container runtime ({})",
        reasons.join("; ")
    ))
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn bool_field(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn ncpu(v: Option<&Value>) -> u32 {
    v.and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0)
        .unwrap_or(1)
}

/// A daemon on another kernel (a remote `DOCKER_HOST`, a VM such as Docker
/// Desktop) cannot see the host paths agentkeep bind-mounts, and Unix
/// sockets do not cross into it, so the proxy, approval and lifeline
/// sockets would not work.
fn same_kernel(runtime: Kind, theirs: &str, ours: &str) -> Result<(), String> {
    if theirs.is_empty() || theirs == ours {
        return Ok(());
    }
    Err(format!(
        "the {} daemon runs on kernel {theirs}, not this host's {ours} (a VM or remote host): bind mounts and Unix sockets would not reach it",
        runtime.name()
    ))
}

/// Interpret `docker info --format '{{json .}}'`.
pub fn parse_docker_info(runtime: Runtime, v: &Value, kernel: &str) -> Result<Info, String> {
    if let Some(errs) = v.get("ServerErrors").and_then(Value::as_array) {
        if let Some(first) = errs.first() {
            return Err(format!(
                "docker daemon unreachable: {}",
                first.as_str().unwrap_or_default()
            ));
        }
    }
    let os = str_field(v, "OperatingSystem");
    if os.contains("Docker Desktop") {
        return Err(
            "Docker Desktop runs containers in a VM; Unix sockets do not cross into it (Linux hosts with a native daemon only for now)"
                .into(),
        );
    }
    same_kernel(runtime.kind, str_field(v, "KernelVersion"), kernel)?;
    let security: Vec<&str> = v
        .get("SecurityOptions")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let rootless = security
        .iter()
        .any(|o| o.split(',').any(|kv| kv == "name=rootless"));
    let runtimes = v.get("Runtimes").and_then(Value::as_object);
    let gvisor = runtimes.is_some_and(|r| r.contains_key("runsc"));
    if str_field(v, "DefaultRuntime") == "runsc" {
        return Err(
            "docker's default runtime is runsc (gVisor), which refuses the host Unix sockets agentkeep needs (see docs/limitations.md)"
                .into(),
        );
    }
    Ok(Info {
        runtime,
        rootless,
        cgroup_v2: str_field(v, "CgroupVersion") == "2",
        limits: bool_field(v, "MemoryLimit") && bool_field(v, "PidsLimit"),
        swap_limit: bool_field(v, "SwapLimit"),
        ncpu: ncpu(v.get("NCPU")),
        gvisor,
        version: str_field(v, "ServerVersion").to_string(),
    })
}

/// Interpret `podman info --format json`.
pub fn parse_podman_info(runtime: Runtime, v: &Value, kernel: &str) -> Result<Info, String> {
    let host = v.get("host").cloned().unwrap_or(Value::Null);
    same_kernel(runtime.kind, str_field(&host, "kernel"), kernel)?;
    let oci = host
        .get("ociRuntime")
        .map(|o| str_field(o, "name"))
        .unwrap_or_default();
    if oci == "runsc" {
        return Err(
            "podman's OCI runtime is runsc (gVisor), which refuses the host Unix sockets agentkeep needs (see docs/limitations.md)"
                .into(),
        );
    }
    let rootless = host
        .get("security")
        .is_some_and(|s| bool_field(s, "rootless"));
    let cgroup_v2 = str_field(&host, "cgroupVersion") == "v2";
    let controllers: Vec<&str> = host
        .get("cgroupControllers")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let has = |c: &str| controllers.contains(&c);
    // Rootless Podman can only limit what systemd delegated to the user;
    // rootful Podman on cgroup v1 always has the controllers.
    let limits = if cgroup_v2 || rootless {
        has("memory") && has("pids")
    } else {
        true
    };
    Ok(Info {
        runtime,
        rootless,
        cgroup_v2,
        limits,
        swap_limit: limits,
        ncpu: ncpu(host.get("cpus")),
        gvisor: which("runsc").is_some(),
        version: v
            .get("version")
            .map(|x| str_field(x, "Version"))
            .unwrap_or_default()
            .to_string(),
    })
}

/// Why an image under [`IMAGE`] is not acceptable, or `None` when it is the
/// empty image. `inspect` is the runtime's `image inspect` JSON array.
pub fn image_problem(inspect: &Value) -> Option<String> {
    let Some(img) = inspect.as_array().and_then(|a| a.first()) else {
        return Some("no image in inspect output".into());
    };
    let layers: Vec<&str> = img
        .pointer("/RootFS/Layers")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if layers != [EMPTY_LAYER] {
        return Some(format!("its layers are {layers:?}, not the empty layer"));
    }
    let config = img.get("Config").cloned().unwrap_or(Value::Null);
    // The image's environment reaches PID 1 (agentkeep itself), so only a
    // PATH is tolerated; volumes would add mounts the plan never asked for.
    let env_ok = config.get("Env").and_then(Value::as_array).is_none_or(|a| {
        a.iter()
            .all(|e| e.as_str().is_some_and(|s| s.starts_with("PATH=")))
    });
    if !env_ok {
        return Some("its configuration sets environment variables".into());
    }
    let volumes_ok = config
        .get("Volumes")
        .is_none_or(|v| v.is_null() || v.as_object().is_some_and(serde_json::Map::is_empty));
    if !volumes_ok {
        return Some("its configuration declares volumes".into());
    }
    None
}

/// Make sure [`IMAGE`] exists and is the empty image, importing it from an
/// in-memory empty tar archive when missing. Never pulls.
pub fn ensure_image(rt: &Runtime) -> Result<(), String> {
    let inspect = |rt: &Runtime| -> Result<Option<Value>, String> {
        let mut cmd = rt.command();
        cmd.args(["image", "inspect", IMAGE]);
        let out = run_with_timeout(cmd, None, Duration::from_secs(30))?;
        if out.code != Some(0) {
            return Ok(None);
        }
        serde_json::from_str(&out.stdout)
            .map(Some)
            .map_err(|e| format!("image inspect output unreadable: {e}"))
    };
    let found = if let Some(v) = inspect(rt)? {
        v
    } else {
        let mut cmd = rt.command();
        cmd.args([
            "import",
            "--message",
            "agentkeep: empty root filesystem",
            "-",
            IMAGE,
        ]);
        let tar = vec![0u8; EMPTY_TAR_LEN];
        let out = run_with_timeout(cmd, Some(&tar), Duration::from_mins(1))?;
        if out.code != Some(0) {
            return Err(format!(
                "`{} import` of the empty image failed: {}",
                rt.kind.name(),
                first_line(&out.stderr)
            ));
        }
        inspect(rt)?.ok_or_else(|| format!("{IMAGE} missing right after import"))?
    };
    match image_problem(&found) {
        None => Ok(()),
        Some(why) => Err(format!(
            "{IMAGE} exists but is not the empty image agentkeep creates: {why}; remove it with `{} rmi {IMAGE}`",
            rt.kind.name()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(kind: Kind) -> Runtime {
        Runtime {
            kind,
            path: PathBuf::from("/usr/bin/x"),
        }
    }

    #[test]
    fn docker_info_rootful_v1() {
        let v = serde_json::json!({
            "SecurityOptions": ["name=seccomp,profile=builtin"],
            "CgroupVersion": "1", "MemoryLimit": true, "PidsLimit": true, "SwapLimit": true,
            "NCPU": 4, "Runtimes": {"runc": {}}, "DefaultRuntime": "runc",
            "KernelVersion": "6.1.0", "ServerVersion": "29.0.0", "OperatingSystem": "Ubuntu"
        });
        let i = parse_docker_info(rt(Kind::Docker), &v, "6.1.0").unwrap();
        assert!(!i.rootless && !i.cgroup_v2 && i.limits && !i.gvisor);
        assert_eq!(i.ncpu, 4);
    }

    #[test]
    fn docker_info_rootless_gvisor_v2() {
        let v = serde_json::json!({
            "SecurityOptions": ["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"],
            "CgroupVersion": "2", "MemoryLimit": true, "PidsLimit": false,
            "NCPU": 2, "Runtimes": {"runc": {}, "runsc": {}}, "DefaultRuntime": "runc",
            "KernelVersion": "6.1.0"
        });
        let i = parse_docker_info(rt(Kind::Docker), &v, "6.1.0").unwrap();
        assert!(i.rootless && i.cgroup_v2 && i.gvisor);
        assert!(
            !i.limits,
            "pids limit unsupported means limits are not enforced"
        );
    }

    #[test]
    fn docker_info_refuses_vm_remote_and_gvisor_default() {
        let desktop =
            serde_json::json!({"OperatingSystem": "Docker Desktop", "KernelVersion": "6.1.0"});
        assert!(parse_docker_info(rt(Kind::Docker), &desktop, "6.1.0").is_err());
        let remote = serde_json::json!({"KernelVersion": "5.15.0-remote"});
        assert!(parse_docker_info(rt(Kind::Docker), &remote, "6.1.0").is_err());
        let gv = serde_json::json!({"DefaultRuntime": "runsc", "KernelVersion": "6.1.0"});
        assert!(parse_docker_info(rt(Kind::Docker), &gv, "6.1.0").is_err());
        let down = serde_json::json!({"ServerErrors": ["Cannot connect to the Docker daemon"]});
        assert!(parse_docker_info(rt(Kind::Docker), &down, "6.1.0").is_err());
    }

    #[test]
    fn podman_info_rootless() {
        let v = serde_json::json!({
            "host": {"kernel": "6.1.0", "cgroupVersion": "v2", "cgroupControllers": ["cpu", "memory", "pids"],
                     "cpus": 8, "security": {"rootless": true}, "ociRuntime": {"name": "crun"}},
            "version": {"Version": "4.9.3"}
        });
        let i = parse_podman_info(rt(Kind::Podman), &v, "6.1.0").unwrap();
        assert!(i.rootless && i.cgroup_v2 && i.limits);
        assert_eq!((i.ncpu, i.version.as_str()), (8, "4.9.3"));
        let v = serde_json::json!({"host": {"kernel": "6.1.0", "cgroupVersion": "v2", "cgroupControllers": [],
                                            "security": {"rootless": true}}});
        assert!(
            !parse_podman_info(rt(Kind::Podman), &v, "6.1.0")
                .unwrap()
                .limits
        );
    }

    #[test]
    fn image_check_accepts_only_the_empty_image() {
        let good = serde_json::json!([{"RootFS": {"Layers": [EMPTY_LAYER]}, "Config": {}}]);
        assert_eq!(image_problem(&good), None);
        let podman = serde_json::json!([{"RootFS": {"Layers": [EMPTY_LAYER]}, "Config": {"Env": ["PATH=/usr/bin"]}}]);
        assert_eq!(image_problem(&podman), None);
        let other = serde_json::json!([{"RootFS": {"Layers": ["sha256:00"]}, "Config": {}}]);
        assert!(image_problem(&other).is_some());
        let env = serde_json::json!([{"RootFS": {"Layers": [EMPTY_LAYER]}, "Config": {"Env": ["LD_PRELOAD=/x.so"]}}]);
        assert!(image_problem(&env).is_some());
        let vol = serde_json::json!([{"RootFS": {"Layers": [EMPTY_LAYER]}, "Config": {"Volumes": {"/data": {}}}}]);
        assert!(image_problem(&vol).is_some());
    }
}
