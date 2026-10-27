//! Compiling a [`LaunchPlan`] into a `podman run` / `docker run` argument
//! list. Pure: everything it needs about the host is passed in, so the
//! mapping is unit-tested without a runtime.
//!
//! The mount list mirrors `linux::mounts` exactly, including its ordering
//! semantics. The runtimes sort mounts by destination depth before applying
//! them, whereas the Linux backend applies hidden overlays *last*; so
//! entries that the Linux order would cover are resolved here and dropped
//! before the runtime sees them.
//!
//! Environment values never appear in the arguments: they would be readable
//! by every local user in `/proc/<pid>/cmdline` of the runtime CLI. The
//! command and its environment travel in the plan file instead (see
//! `container::mod` for why not `--env-file`).

use std::path::{Path, PathBuf};

use crate::linux::mounts::{HOME_TMPFS_SIZE, SMALL_TMPFS_SIZE, TMP_TMPFS_SIZE};
use crate::plan::{LaunchPlan, MountMode};
use crate::Error;

use super::runtime::Kind;

/// Where the agentkeep binary appears inside the container; it is PID 1.
pub const EXE: &str = "/run/agentkeep/agentkeep";
/// The (read-only) launch plan inside the container.
pub const PLAN: &str = "/run/agentkeep/plan.json";
/// The supervisor's lifeline and status socket inside the container.
pub const LIFELINE: &str = "/run/agentkeep/lifeline.sock";
/// Detach sequence for Docker, which cannot disable detaching. Chosen to be
/// something no one types by accident; Podman gets detaching disabled.
const DOCKER_DETACH_KEYS: &str = "ctrl-^,ctrl-@";

/// Whom the command runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// `--user uid:gid` with no user namespace of our own. For rootful
    /// runtimes this is the invoking user's host uid, so project files keep
    /// their owner; for rootless Docker it is container root, which is the
    /// invoking user on the host.
    User {
        /// UID inside the container.
        uid: u32,
        /// GID inside the container.
        gid: u32,
    },
    /// Rootless Podman: `--userns keep-id` maps the invoking user to this
    /// uid inside, like the Linux backend's user namespace.
    KeepId {
        /// UID inside the container.
        uid: u32,
        /// GID inside the container.
        gid: u32,
    },
}

impl Identity {
    /// The uid and gid the command has inside the container.
    pub fn ids(self) -> (u32, u32) {
        match self {
            Self::User { uid, gid } | Self::KeepId { uid, gid } => (uid, gid),
        }
    }
}

/// Host files the backend prepared for this session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFiles {
    /// The plan as init reads it (mode 0600).
    pub plan: PathBuf,
    /// The lifeline socket the supervisor listens on.
    pub lifeline: PathBuf,
    /// An empty file, bound over hidden files.
    pub empty: PathBuf,
    /// Directory of shim symlinks.
    pub bin: PathBuf,
    /// Synthesized `/etc/passwd`.
    pub passwd: PathBuf,
    /// Synthesized `/etc/group`.
    pub group: PathBuf,
}

/// Everything about the runtime and host the arguments depend on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent facts about the runtime
pub struct Settings {
    /// Runtime CLI flavour.
    pub kind: Kind,
    /// Run-as identity.
    pub identity: Identity,
    /// Allocate a TTY (only when agentkeep's stdin is one).
    pub tty: bool,
    /// Image to run.
    pub image: String,
    /// Container name.
    pub name: String,
    /// The runtime enforces `--memory` and `--pids-limit`.
    pub limits: bool,
    /// The runtime enforces `--memory-swap`.
    pub swap_limit: bool,
    /// The runtime uses cgroup v2 (then the cgroup namespace is made private).
    pub cgroup_v2: bool,
    /// CPUs available to the runtime.
    pub ncpu: u32,
    /// Landlock ABI init must find inside the container (0: none claimed).
    pub landlock_abi: u32,
    /// Session files.
    pub files: SessionFiles,
}

/// One mount as the runtime will apply it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A bind mount of a host path.
    Bind {
        /// Host path.
        source: PathBuf,
        /// Path inside the container.
        target: PathBuf,
        /// Read-only.
        readonly: bool,
    },
    /// A private tmpfs with the given mount options.
    Tmpfs {
        /// Path inside the container.
        target: PathBuf,
        /// Comma-separated options (`rw,exec,nosuid,nodev,size=...`).
        options: String,
    },
}

impl Entry {
    /// Path inside the container.
    pub fn target(&self) -> &Path {
        match self {
            Self::Bind { target, .. } | Self::Tmpfs { target, .. } => target,
        }
    }
}

/// Does a host path exist, and is it a directory? `None` when absent.
pub type HostLookup<'a> = &'a dyn Fn(&Path) -> Option<bool>;

fn depth(p: &Path) -> usize {
    p.components().count()
}

/// Reject paths the runtime CLI syntax cannot carry unambiguously. Failing
/// is safer than guessing how a comma or colon would be parsed.
fn check_path(p: &Path, tmpfs: bool) -> Result<&str, Error> {
    let s = p
        .to_str()
        .ok_or_else(|| Error::Plan(format!("{} is not valid UTF-8", p.display())))?;
    if !p.is_absolute() {
        return Err(Error::Plan(format!("{s} is not an absolute path")));
    }
    if let Some(c) = s
        .chars()
        .find(|c| matches!(c, ',' | '"' | '\n' | '\r' | '\0') || (tmpfs && *c == ':'))
    {
        return Err(Error::Plan(format!(
            "path `{s}` contains {c:?}, which the container runtime's mount syntax cannot carry safely; use the linux backend for it"
        )));
    }
    Ok(s)
}

/// Does `target` exist in the container view built so far, and is it a
/// directory? Mirrors what the Linux backend finds when it checks the path
/// inside its new root.
fn in_view(active: &[Entry], target: &Path, host: HostLookup<'_>) -> Option<bool> {
    if let Some(e) = active.iter().find(|e| e.target() == target) {
        return match e {
            Entry::Bind { source, .. } => host(source),
            Entry::Tmpfs { .. } => Some(true),
        };
    }
    // Mount points of deeper mounts exist as directories.
    if active
        .iter()
        .any(|e| e.target().starts_with(target) && e.target() != target)
    {
        return Some(true);
    }
    let covering = active
        .iter()
        .filter(|e| target.starts_with(e.target()))
        .max_by_key(|e| depth(e.target()))?;
    match covering {
        Entry::Bind {
            source,
            target: base,
            ..
        } => host(&source.join(target.strip_prefix(base).ok()?)),
        // An empty tmpfs (including a hidden one) holds nothing.
        Entry::Tmpfs { .. } => None,
    }
}

/// Add `e`, dropping whatever it covers: an earlier entry at the same path
/// or beneath it, exactly what a later mount covers in the Linux order.
fn push(active: &mut Vec<Entry>, e: Entry) {
    active.retain(|x| !x.target().starts_with(e.target()));
    active.push(e);
}

/// Owner options for a tmpfs that belongs to the command's user. Docker
/// passes `uid=`/`gid=` to the kernel; Podman refuses them and has `U`
/// ("chown to the container user") instead, which is the same owner here.
fn owner(kind: Kind, (uid, gid): (u32, u32)) -> String {
    match kind {
        Kind::Docker => format!("uid={uid},gid={gid}"),
        Kind::Podman => "U".into(),
    }
}

fn tmpfs_options(plan: &LaunchPlan, target: &Path, size: Option<u64>, s: &Settings) -> String {
    let is_home = target == plan.home;
    let world = target == Path::new("/tmp")
        || target == Path::new("/var/tmp")
        || target == Path::new("/dev/shm");
    let size = size.unwrap_or(if is_home {
        HOME_TMPFS_SIZE
    } else if world {
        TMP_TMPFS_SIZE
    } else {
        SMALL_TMPFS_SIZE
    });
    // Runtimes default tmpfs to noexec; the Linux backend's are executable.
    let base = "rw,exec,nosuid,nodev";
    let owner = owner(s.kind, s.identity.ids());
    if is_home {
        format!("{base},size={size},mode=0700,{owner}")
    } else if world {
        format!("{base},size={size},mode=1777")
    } else {
        format!("{base},size={size},mode=0755,{owner}")
    }
}

/// The mounts, resolved into the set the runtime applies. Order does not
/// matter to the runtime (it sorts by depth); the result contains no entry
/// that another one covers, so depth order gives the Linux result.
pub fn mounts(plan: &LaunchPlan, s: &Settings, host: HostLookup<'_>) -> Result<Vec<Entry>, Error> {
    let mut ordered: Vec<_> = plan.mounts.iter().collect();
    ordered.sort_by_key(|m| (m.mode == MountMode::Hidden, depth(&m.target)));
    let mut active: Vec<Entry> = Vec::new();
    for m in ordered {
        match m.mode {
            MountMode::ReadOnly | MountMode::ReadWrite => {
                if host(&m.source).is_none() {
                    continue; // not present on host, as in the Linux backend
                }
                check_path(&m.target, false)?;
                check_path(&m.source, false)?;
                push(
                    &mut active,
                    Entry::Bind {
                        source: m.source.clone(),
                        target: m.target.clone(),
                        readonly: m.mode == MountMode::ReadOnly,
                    },
                );
            }
            MountMode::Tmpfs => {
                check_path(&m.target, true)?;
                let options = tmpfs_options(plan, &m.target, m.size, s);
                push(
                    &mut active,
                    Entry::Tmpfs {
                        target: m.target.clone(),
                        options,
                    },
                );
            }
            MountMode::Hidden => {
                let Some(is_dir) = in_view(&active, &m.target, host) else {
                    continue; // nothing there to hide
                };
                check_path(&m.target, is_dir)?;
                let e = if is_dir {
                    Entry::Tmpfs {
                        target: m.target.clone(),
                        options: "ro,nosuid,nodev,noexec,size=4096,mode=0555".into(),
                    }
                } else {
                    Entry::Bind {
                        source: s.files.empty.clone(),
                        target: m.target.clone(),
                        readonly: true,
                    }
                };
                push(&mut active, e);
            }
        }
    }

    internal_mounts(&mut active, plan, s, host)?;
    Ok(active)
}

/// What the Linux backend adds after the planned mounts: the binary,
/// shims and approval socket, the proxy socket and CA bundle, identity.
fn internal_mounts(
    active: &mut Vec<Entry>,
    plan: &LaunchPlan,
    s: &Settings,
    host: HostLookup<'_>,
) -> Result<(), Error> {
    push(
        active,
        Entry::Tmpfs {
            target: PathBuf::from(format!("/run/user/{}", plan.inner_uid)),
            options: format!(
                "rw,nosuid,nodev,size={SMALL_TMPFS_SIZE},mode=0700,{}",
                owner(s.kind, s.identity.ids())
            ),
        },
    );
    if s.kind == Kind::Podman {
        // With `--read-only-tmpfs=false` Podman leaves /dev/shm read-only;
        // the Linux backend (and Docker) give a private writable one.
        push(
            active,
            Entry::Tmpfs {
                target: PathBuf::from("/dev/shm"),
                options: "rw,nosuid,nodev,noexec,size=67108864,mode=1777".into(),
            },
        );
    }
    let ro = |source: &Path, target: &str| Entry::Bind {
        source: source.to_path_buf(),
        target: PathBuf::from(target),
        readonly: true,
    };
    check_path(&plan.self_exe, false)?;
    push(active, ro(&plan.self_exe, EXE));
    push(active, ro(&s.files.plan, PLAN));
    push(
        active,
        Entry::Bind {
            source: s.files.lifeline.clone(),
            target: PathBuf::from(LIFELINE),
            readonly: false,
        },
    );
    if let Some(shim) = &plan.shim {
        check_path(&shim.dir, false)?;
        push(
            active,
            Entry::Bind {
                source: s.files.bin.clone(),
                target: shim.dir.clone(),
                readonly: true,
            },
        );
        if let Some(sock) = &plan.approval_socket {
            check_path(sock, false)?;
            check_path(&shim.socket, false)?;
            push(
                active,
                Entry::Bind {
                    source: sock.clone(),
                    target: shim.socket.clone(),
                    readonly: false,
                },
            );
        }
    }
    if let Some(proxy) = &plan.proxy {
        for p in [
            &proxy.host_socket,
            &proxy.sandbox_socket,
            &proxy.ca_bundle_host,
            &proxy.ca_bundle_sandbox,
        ] {
            check_path(p, false)?;
        }
        push(
            active,
            Entry::Bind {
                source: proxy.host_socket.clone(),
                target: proxy.sandbox_socket.clone(),
                readonly: false,
            },
        );
        push(
            active,
            Entry::Bind {
                source: proxy.ca_bundle_host.clone(),
                target: proxy.ca_bundle_sandbox.clone(),
                readonly: true,
            },
        );
    }
    if in_view(active, Path::new("/etc"), host) == Some(true) {
        for (file, src) in [
            ("/etc/passwd", &s.files.passwd),
            ("/etc/group", &s.files.group),
        ] {
            if in_view(active, Path::new(file), host).is_some() {
                push(active, ro(src, file));
            }
        }
    }
    Ok(())
}

fn mount_arg(e: &Entry, kind: Kind) -> Result<[String; 2], Error> {
    Ok(match e {
        Entry::Bind {
            source,
            target,
            readonly,
        } => {
            let src = check_path(source, false)?;
            let dst = check_path(target, false)?;
            let ro = if *readonly { ",readonly" } else { "" };
            [
                "--mount".into(),
                format!("type=bind,source={src},target={dst}{ro}"),
            ]
        }
        Entry::Tmpfs { target, options } => {
            let dst = check_path(target, true)?;
            // Podman copies the covered directory's content into a new
            // tmpfs by default, which would put hidden files right back.
            // Docker does not copy and rejects the option.
            let copyup = match kind {
                Kind::Podman => ",notmpcopyup",
                Kind::Docker => "",
            };
            ["--tmpfs".into(), format!("{dst}:{options}{copyup}")]
        }
    })
}

/// `--cpus` value, or `None` when the quota would not restrict anything.
fn cpus(percent: u32, ncpu: u32) -> Option<String> {
    if percent == 0 || u64::from(percent) >= u64::from(ncpu) * 100 {
        return None;
    }
    Some(format!("{}.{:02}", percent / 100, percent % 100))
}

/// The full argument list after the runtime binary: `run ... IMAGE
/// __container-init ...`.
pub fn build(plan: &LaunchPlan, s: &Settings, host: HostLookup<'_>) -> Result<Vec<String>, Error> {
    let cwd = check_path(&plan.cwd, false)?;
    let mut a: Vec<String> = Vec::new();
    let mut add = |items: &[&str]| a.extend(items.iter().map(|x| (*x).to_string()));
    add(&["run", "--rm", "--interactive"]);
    if s.tty {
        add(&["--tty"]);
    }
    let label = format!("dev.agentkeep.session={}", plan.session_id);
    add(&["--name", &s.name, "--label", &label]);
    // Never fetch anything, never write the session's output to the
    // runtime's log store, never run image-defined health checks.
    add(&["--pull=never", "--log-driver=none", "--no-healthcheck"]);
    add(&["--network=none", "--ipc=private"]);
    if s.kind == Kind::Podman {
        // Podman's defaults come from containers.conf and may be changed by
        // the host; state them. Docker has no setting for these.
        add(&["--pid=private", "--uts=private", "--read-only-tmpfs=false"]);
    }
    if s.cgroup_v2 {
        add(&["--cgroupns=private"]);
    }
    add(&[
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
    ]);
    let (uid, gid) = s.identity.ids();
    if let Identity::KeepId { .. } = s.identity {
        let userns = format!("--userns=keep-id:uid={uid},gid={gid}");
        add(&[&userns]);
    }
    let user = format!("--user={uid}:{gid}");
    let hostname = format!("--hostname={}", plan.hostname);
    let workdir = format!("--workdir={cwd}");
    add(&[&user, &hostname, &workdir]);
    match s.kind {
        Kind::Docker => add(&[&format!("--detach-keys={DOCKER_DETACH_KEYS}")]),
        Kind::Podman => add(&["--detach-keys="]),
    }
    if s.limits {
        if let Some(pids) = plan.limits.pids {
            add(&[&format!("--pids-limit={pids}")]);
        }
        if let Some(mem) = plan.limits.memory {
            add(&[&format!("--memory={mem}")]);
            if s.swap_limit {
                // Equal to --memory: no swap, so the limit is the limit.
                add(&[&format!("--memory-swap={mem}")]);
            }
        }
    }
    if let Some(c) = plan.limits.cpu_percent.and_then(|p| cpus(p, s.ncpu)) {
        add(&[&format!("--cpus={c}")]);
    }
    for e in mounts(plan, s, host)? {
        let [flag, value] = mount_arg(&e, s.kind)?;
        a.push(flag);
        a.push(value);
    }
    a.push(format!("--entrypoint={EXE}"));
    a.push(s.image.clone());
    a.push("__container-init".into());
    a.push("--landlock-abi".into());
    a.push(s.landlock_abi.to_string());
    Ok(a)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::plan::{Limits, Mount, ProxyPlan, ShimConfig};

    const SECRET: &str = "sk-test-fake-agentkeep-container-args";

    fn mount(source: &str, target: &str, mode: MountMode) -> Mount {
        Mount {
            source: source.into(),
            target: target.into(),
            mode,
            size: None,
        }
    }

    fn plan() -> LaunchPlan {
        LaunchPlan {
            session_id: "20260101T000000-42".into(),
            mounts: vec![
                mount("/usr", "/usr", MountMode::ReadOnly),
                mount("/etc", "/etc", MountMode::ReadOnly),
                mount("", "/home/u", MountMode::Tmpfs),
                mount("/home/u/work/p", "/home/u/work/p", MountMode::ReadWrite),
                mount("", "/home/u/.ssh", MountMode::Hidden),
                mount("", "/etc/shadow", MountMode::Hidden),
                mount("", "/etc/sudoers.d", MountMode::Hidden),
                mount("", "/etc/not-on-host", MountMode::Hidden),
                mount("", "/tmp", MountMode::Tmpfs),
            ],
            project: "/home/u/work/p".into(),
            home: "/home/u".into(),
            env: BTreeMap::from([
                ("HOME".into(), "/home/u".into()),
                ("ANTHROPIC_API_KEY".into(), SECRET.into()),
            ]),
            cwd: "/home/u/work/p".into(),
            command: vec!["sh".into(), "-c".into(), format!("echo {SECRET}")],
            limits: Limits {
                cpu_percent: Some(150),
                memory: Some(512 << 20),
                pids: Some(64),
                wall_time_secs: Some(10),
            },
            hostname: "agentkeep".into(),
            self_exe: "/opt/agentkeep/bin/agentkeep".into(),
            root_base: "/tmp/agentkeep.s/root".into(),
            user_name: "u".into(),
            approval_socket: Some("/tmp/agentkeep.s/exec.sock".into()),
            shim: Some(ShimConfig {
                dir: "/run/agentkeep/bin".into(),
                commands: vec!["git".into()],
                socket: "/run/agentkeep/exec.sock".into(),
            }),
            proxy: Some(ProxyPlan {
                host_socket: "/tmp/agentkeep.s/proxy.sock".into(),
                sandbox_socket: "/run/agentkeep/proxy.sock".into(),
                port: 3128,
                ca_bundle_host: "/tmp/agentkeep.s/ca-bundle.pem".into(),
                ca_bundle_sandbox: "/run/agentkeep/ca-bundle.pem".into(),
            }),
            landlock: true,
            seccomp: true,
            inner_uid: 1000,
            inner_gid: 1000,
        }
    }

    fn settings(kind: Kind) -> Settings {
        Settings {
            kind,
            identity: Identity::User {
                uid: 1234,
                gid: 1234,
            },
            tty: false,
            image: "localhost/agentkeep/empty:1".into(),
            name: "agentkeep-20260101T000000-42".into(),
            limits: true,
            swap_limit: true,
            cgroup_v2: true,
            ncpu: 4,
            landlock_abi: 5,
            files: SessionFiles {
                plan: "/tmp/agentkeep.s/root/plan.json".into(),
                lifeline: "/tmp/agentkeep.s/root/lifeline.sock".into(),
                empty: "/tmp/agentkeep.s/root/empty".into(),
                bin: "/tmp/agentkeep.s/root/bin".into(),
                passwd: "/tmp/agentkeep.s/root/passwd".into(),
                group: "/tmp/agentkeep.s/root/group".into(),
            },
        }
    }

    /// A fake host: these paths exist, directories end in `/`.
    fn host(p: &Path) -> Option<bool> {
        let dirs = [
            "/usr",
            "/etc",
            "/home/u/work/p",
            "/home/u/.ssh",
            "/etc/sudoers.d",
        ];
        let files = ["/etc/shadow", "/etc/passwd", "/etc/group"];
        let s = p.to_str()?;
        if dirs.contains(&s) {
            Some(true)
        } else if files.contains(&s) {
            Some(false)
        } else {
            None
        }
    }

    fn args(kind: Kind) -> Vec<String> {
        build(&plan(), &settings(kind), &host).unwrap()
    }

    #[test]
    fn isolation_flags_are_always_present() {
        for kind in [Kind::Docker, Kind::Podman] {
            let a = args(kind);
            for flag in [
                "--rm",
                "--network=none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--read-only",
                "--ipc=private",
                "--pull=never",
                "--log-driver=none",
                "--no-healthcheck",
                "--user=1234:1234",
                "--hostname=agentkeep",
                "--workdir=/home/u/work/p",
                "--entrypoint=/run/agentkeep/agentkeep",
            ] {
                assert!(
                    a.iter().any(|x| x == flag),
                    "{kind:?}: missing {flag}: {a:?}"
                );
            }
            assert_eq!(a[0], "run");
            let image = a
                .iter()
                .position(|x| x == "localhost/agentkeep/empty:1")
                .unwrap();
            assert_eq!(&a[image + 1..], ["__container-init", "--landlock-abi", "5"]);
            assert!(!a.iter().any(|x| x == "--tty"), "no tty without one");
            assert!(!a
                .iter()
                .any(|x| x.starts_with("--privileged") || x.starts_with("--cap-add")));
        }
        assert!(args(Kind::Podman).iter().any(|x| x == "--pid=private"));
    }

    #[test]
    fn no_environment_values_or_command_in_argv() {
        for kind in [Kind::Docker, Kind::Podman] {
            let a = args(kind);
            let joined = a.join(" ");
            assert!(
                !joined.contains(SECRET),
                "secret value on the command line: {joined}"
            );
            assert!(!joined.contains("ANTHROPIC_API_KEY"), "{joined}");
            for flag in ["-e", "--env", "--env-file", "--env-host"] {
                assert!(
                    !a.iter()
                        .any(|x| x == flag || x.starts_with(&format!("{flag}="))),
                    "{flag} in argv"
                );
            }
        }
    }

    #[test]
    fn mounts_map_like_the_linux_backend() {
        let a = args(Kind::Docker);
        let has = |v: &str| a.iter().any(|x| x == v);
        assert!(has("type=bind,source=/usr,target=/usr,readonly"));
        assert!(has("type=bind,source=/etc,target=/etc,readonly"));
        assert!(
            has("type=bind,source=/home/u/work/p,target=/home/u/work/p"),
            "project rw"
        );
        assert!(has(
            "/home/u:rw,exec,nosuid,nodev,size=536870912,mode=0700,uid=1234,gid=1234"
        ));
        assert!(has("/tmp:rw,exec,nosuid,nodev,size=2147483648,mode=1777"));
        // Hidden: a directory becomes an empty read-only tmpfs, a file an
        // empty read-only bind; paths absent from the view are skipped.
        assert!(has(
            "/etc/sudoers.d:ro,nosuid,nodev,noexec,size=4096,mode=0555"
        ));
        assert!(has(
            "type=bind,source=/tmp/agentkeep.s/root/empty,target=/etc/shadow,readonly"
        ));
        assert!(!a.join(" ").contains("not-on-host"));
        // ~/.ssh exists on the host but home is an empty tmpfs inside, so
        // there is nothing to hide (the Linux backend skips it too).
        assert!(!a.join(" ").contains("/home/u/.ssh"));
        // Internal mounts.
        assert!(has("type=bind,source=/opt/agentkeep/bin/agentkeep,target=/run/agentkeep/agentkeep,readonly"));
        assert!(has("type=bind,source=/tmp/agentkeep.s/root/plan.json,target=/run/agentkeep/plan.json,readonly"));
        assert!(has(
            "type=bind,source=/tmp/agentkeep.s/root/bin,target=/run/agentkeep/bin,readonly"
        ));
        assert!(has(
            "type=bind,source=/tmp/agentkeep.s/exec.sock,target=/run/agentkeep/exec.sock"
        ));
        assert!(has(
            "type=bind,source=/tmp/agentkeep.s/proxy.sock,target=/run/agentkeep/proxy.sock"
        ));
        assert!(has("type=bind,source=/tmp/agentkeep.s/ca-bundle.pem,target=/run/agentkeep/ca-bundle.pem,readonly"));
        assert!(has(
            "type=bind,source=/tmp/agentkeep.s/root/passwd,target=/etc/passwd,readonly"
        ));
        assert!(has(
            "type=bind,source=/tmp/agentkeep.s/root/group,target=/etc/group,readonly"
        ));
        assert!(has(
            "/run/user/1000:rw,nosuid,nodev,size=67108864,mode=0700,uid=1234,gid=1234"
        ));
    }

    #[test]
    fn approver_socket_and_session_directory_are_never_mounted() {
        let a = args(Kind::Docker).join(" ");
        assert!(!a.contains("approve.sock"), "{a}");
        // Only individual session files are bound, never their directory.
        for dir in ["/tmp/agentkeep.s,", "/tmp/agentkeep.s/root,"] {
            assert!(!a.contains(&format!("source={dir}")), "{a}");
        }
    }

    #[test]
    fn hidden_paths_cover_what_linux_would_cover() {
        let mut p = plan();
        // A secret bound on purpose, and hidden too: the hidden overlay wins.
        p.mounts
            .push(mount("/home/u/.ssh", "/home/u/.ssh", MountMode::ReadOnly));
        // A file inside a hidden directory stays covered even though the
        // runtime would apply the deeper bind after the tmpfs.
        p.mounts.push(mount(
            "/etc/sudoers.d/x",
            "/etc/sudoers.d/x",
            MountMode::ReadOnly,
        ));
        let host = |q: &Path| -> Option<bool> {
            match q.to_str()? {
                "/etc/sudoers.d/x" => Some(false),
                other => host(Path::new(other)),
            }
        };
        let m = mounts(&p, &settings(Kind::Docker), &host).unwrap();
        let ssh: Vec<_> = m
            .iter()
            .filter(|e| e.target() == Path::new("/home/u/.ssh"))
            .collect();
        assert_eq!(ssh.len(), 1);
        assert!(matches!(ssh[0], Entry::Tmpfs { options, .. } if options.starts_with("ro,")));
        assert!(!m
            .iter()
            .any(|e| e.target() == Path::new("/etc/sudoers.d/x")));
        // No two entries share a target.
        let mut targets: Vec<_> = m.iter().map(Entry::target).collect();
        targets.sort();
        let before = targets.len();
        targets.dedup();
        assert_eq!(before, targets.len());
    }

    #[test]
    fn limits_and_identity() {
        let a = args(Kind::Docker);
        for flag in [
            "--pids-limit=64",
            "--memory=536870912",
            "--memory-swap=536870912",
            "--cpus=1.50",
            "--cgroupns=private",
        ] {
            assert!(a.iter().any(|x| x == flag), "missing {flag}");
        }
        let mut s = settings(Kind::Docker);
        s.limits = false;
        s.ncpu = 1;
        let a = build(&plan(), &s, &host).unwrap();
        assert!(!a.iter().any(|x| x.starts_with("--memory")
            || x.starts_with("--pids-limit")
            || x.starts_with("--cpus")));
        let mut s = settings(Kind::Podman);
        s.identity = Identity::KeepId {
            uid: 1000,
            gid: 1000,
        };
        s.tty = true;
        let a = build(&plan(), &s, &host).unwrap();
        assert!(a.iter().any(|x| x == "--userns=keep-id:uid=1000,gid=1000"));
        assert!(a.iter().any(|x| x == "--user=1000:1000"));
        assert!(a.iter().any(|x| x == "--tty"));
        assert!(a.iter().any(|x| x == "--detach-keys="));
        assert!(
            a.iter().any(
                |x| x == "/home/u:rw,exec,nosuid,nodev,size=536870912,mode=0700,U,notmpcopyup"
            ),
            "podman tmpfs owner: {a:?}"
        );
        // Every Podman tmpfs refuses copy-up, or hidden content comes back.
        let tmpfs: Vec<&String> = a
            .windows(2)
            .filter(|w| w[0] == "--tmpfs")
            .map(|w| &w[1])
            .collect();
        assert!(tmpfs.len() > 3, "{tmpfs:?}");
        assert!(
            tmpfs.iter().all(|t| t.ends_with(",notmpcopyup")),
            "{tmpfs:?}"
        );
        let docker = args(Kind::Docker);
        assert!(!docker.iter().any(|x| x.contains("tmpcopyup")));
        assert_eq!(cpus(400, 4), None);
        assert_eq!(cpus(50, 4).as_deref(), Some("0.50"));
    }

    #[test]
    fn ambiguous_paths_fail_closed() {
        let mut p = plan();
        p.mounts
            .push(mount("/data,readonly=false", "/data", MountMode::ReadOnly));
        let host = |_: &Path| Some(true);
        assert!(build(&p, &settings(Kind::Docker), &host).is_err());
        let mut p = plan();
        p.mounts.push(mount("", "/odd:path", MountMode::Tmpfs));
        assert!(build(&p, &settings(Kind::Docker), &host).is_err());
    }
}
