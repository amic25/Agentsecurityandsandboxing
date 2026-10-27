//! The Seatbelt (SBPL) profile for one session.
//!
//! This module is pure: it turns a [`LaunchPlan`] plus a few macOS-specific
//! facts into profile text, and performs no I/O. Path resolution (symlinks,
//! `/var` versus `/private/var`) is supplied by the caller as a function, so
//! the whole thing compiles and is unit-tested on every platform, including
//! Linux CI, even though only macOS can execute the result.
//!
//! # SBPL semantics this profile relies on
//!
//! - `(version 1)` then `(deny default)`: every operation not allowed below
//!   is refused with `EPERM`. The profile is an allow-list.
//! - **Precedence: when several rules match one operation, the rule that
//!   appears last in the profile wins.** Apple's own profiles, Chromium,
//!   Bazel and other Seatbelt users rely on this ("allow a tree, then deny a
//!   part of it"). Every hidden and host-only path is therefore denied at the
//!   *end*, after all allows, so a deny always beats an allow of a parent.
//!   The same denies are also emitted right after `(deny default)`, so that
//!   the profile would still fail closed if that precedence ever changed.
//! - `(literal "/a/b")` matches exactly that path; `(subpath "/a")` matches
//!   `/a` itself and everything below it. No `regex` filters are generated,
//!   so no path can be misread as a pattern.
//! - Seatbelt matches the path the kernel resolved, so `/tmp/x` is checked as
//!   `/private/tmp/x`, `/var/...` as `/private/var/...` and `/etc/...` as
//!   `/private/etc/...`. Every path is emitted in each spelling that can
//!   refer to it: as given, resolved by the caller (symlinks followed), and
//!   with the macOS firmlink aliases applied. An extra spelling in an allow
//!   rule can only match the same file; in a deny rule it closes a gap.
//! - Strings are SBPL (Scheme) string literals: `\` and `"` are escaped with
//!   a backslash. Paths containing control characters or that are not UTF-8
//!   are refused rather than escaped, so no path can end a literal early or
//!   smuggle in a rule.
//! - Seatbelt policies are inherited by every child process and cannot be
//!   removed from inside.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

use crate::plan::{LaunchPlan, MountMode};

/// System trees every macOS program needs, read-only. Deliberately not
/// `/Users`, `/Applications`, `/Volumes`, `/private/var` or `/private/tmp`.
pub const SYSTEM_READ_ONLY: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    // The system library, not `~/Library`.
    "/Library",
    "/private/etc",
    "/private/var/db/timezone",
    // `/bin/sh` reads `/private/var/select/sh` to pick the real shell.
    "/private/var/select",
    // The `/usr/bin` developer-tool stubs (git, clang, python3, make) read
    // this symlink to find the active developer directory.
    "/private/var/db/xcode_select_link",
];

/// Paths under [`SYSTEM_READ_ONLY`] that hold secrets and stay denied even
/// though a parent is readable.
pub const SYSTEM_HIDDEN: &[&str] = &[
    // System keychains (admin-installed certificates, Wi-Fi passwords).
    "/Library/Keychains",
];

/// Device nodes that may be opened for reading.
const DEVICES_READ: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
];

/// Device nodes that may be opened for writing.
const DEVICES_WRITE: &[&str] = &["/dev/null", "/dev/zero", "/dev/tty"];

/// Mach services the sandbox may look up.
///
/// Every service listed here is a daemon running *outside* the sandbox that
/// acts on the sandbox's behalf, so each one is a potential confused deputy.
/// The list is kept to what ordinary command-line tools need and is still a
/// broad grant compared with the file and network rules; see
/// `docs/limitations.md`. Deliberately absent: `com.apple.SecurityServer`
/// and `com.apple.securityd.xpc` (keychain contents), `com.apple.trustd*`
/// (fetches certificate URLs from the network on request, a proxy bypass),
/// `com.apple.dnssd.service` and `com.apple.mDNSResponder` (DNS, threat N3),
/// `com.apple.coreservices.launchservicesd`, `com.apple.lsd.*` and
/// `com.apple.coreservices.appleevents` (launching or scripting apps outside
/// the sandbox), `com.apple.pasteboard.*` (clipboard), `com.apple.nsurlsessiond`
/// and `com.apple.cfnetwork.*` (network transfers outside the sandbox),
/// `com.apple.FSEvents` (file-change notifications for paths outside the
/// policy), `com.apple.SystemConfiguration.configd` (network configuration).
pub const MACH_SERVICES: &[&str] = &[
    // getpwuid, getgrgid and group membership; shells, git and Python
    // misbehave without them.
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    // notify(3), used by libc for time zone and locale changes.
    "com.apple.system.notification_center",
    // Unified logging and its activity tracing.
    "com.apple.logd",
    "com.apple.system.logger",
    "com.apple.diagnosticd",
    // CFPreferences. cfprefsd checks `user-preference-read`, which this
    // profile does not allow, so this only lets Foundation tools start.
    "com.apple.cfprefsd.daemon",
    "com.apple.cfprefsd.agent",
];

/// Exact sysctl names that may be read. Process listing and arguments
/// (`kern.proc.*`, `kern.procargs*`) are absent on purpose: on macOS they
/// expose the command line and environment of every process of the user,
/// including the supervisor's (threat E1).
const SYSCTL_NAMES: &[&str] = &[
    "hw.activecpu",
    "hw.busfrequency_compat",
    "hw.byteorder",
    "hw.cachelinesize",
    "hw.cachelinesize_compat",
    "hw.cpufamily",
    "hw.cpufrequency",
    "hw.cpufrequency_compat",
    "hw.cpusubtype",
    "hw.cputype",
    "hw.l1dcachesize",
    "hw.l1dcachesize_compat",
    "hw.l1icachesize",
    "hw.l1icachesize_compat",
    "hw.l2cachesize",
    "hw.l2cachesize_compat",
    "hw.l3cachesize",
    "hw.l3cachesize_compat",
    "hw.logicalcpu",
    "hw.logicalcpu_max",
    "hw.machine",
    "hw.memsize",
    "hw.model",
    "hw.ncpu",
    "hw.nperflevels",
    "hw.packages",
    "hw.pagesize",
    "hw.pagesize_compat",
    "hw.physicalcpu",
    "hw.physicalcpu_max",
    "hw.tbfrequency",
    "hw.tbfrequency_compat",
    "hw.vectorunit",
    "kern.argmax",
    "kern.bootargs",
    "kern.boottime",
    "kern.hostname",
    "kern.maxfiles",
    "kern.maxfilesperproc",
    "kern.maxproc",
    "kern.maxprocperuid",
    "kern.ngroups",
    "kern.osproductversion",
    "kern.osrelease",
    "kern.ostype",
    "kern.osvariant_status",
    "kern.osversion",
    "kern.secure_kernel",
    "kern.tcsm_available",
    "kern.tcsm_enable",
    "kern.usrstack64",
    "kern.version",
    "kern.willshutdown",
    "machdep.ptrauth_enabled",
    "security.mac.lockdown_mode_state",
    "sysctl.proc_cputype",
    "sysctl.proc_native",
    "sysctl.proc_translated",
    "vm.loadavg",
];

/// sysctl name prefixes that may be read (CPU feature flags).
const SYSCTL_PREFIXES: &[&str] = &["hw.optional.", "hw.perflevel", "machdep.cpu."];

/// macOS-specific inputs to [`build`]. All paths are host paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacInputs {
    /// The session's private `HOME` (read-write).
    pub home: PathBuf,
    /// The session's private `TMPDIR` (read-write).
    pub tmp: PathBuf,
    /// Directory holding the command shims (read-only).
    pub shim_dir: Option<PathBuf>,
    /// Loopback TCP port of the supervisor's relay to the egress proxy.
    pub relay_port: Option<u16>,
    /// Extra read-only trees, such as the active Xcode developer directory.
    pub extra_read_only: Vec<PathBuf>,
    /// Terminal devices the session was started on. They are already the
    /// command's stdin/stdout; allowing them by name lets programs reopen
    /// them, and nothing else (other terminals of the user stay closed).
    pub terminals: Vec<PathBuf>,
}

/// Why a profile could not be built. Every case is a refusal to launch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// A path cannot be expressed safely in SBPL.
    #[error("path {0:?} cannot be used in a Seatbelt profile (not absolute, not UTF-8, or contains control characters)")]
    BadPath(PathBuf),
    /// The macOS backend has no mount namespace and cannot remap paths.
    #[error("mount {host:?} -> {inside:?}: the macOS backend cannot show a path at a different location")]
    Remap {
        /// Host path.
        host: PathBuf,
        /// Requested sandbox path.
        inside: PathBuf,
    },
    /// Refusing to make the whole filesystem writable.
    #[error("refusing to make {0:?} writable")]
    TooBroad(PathBuf),
    /// An allowed tree would expose a host-only path such as the approver
    /// socket.
    #[error("{allowed:?} is allowed in the sandbox but contains the host-only path {host_only:?}")]
    ExposesHostOnly {
        /// The allowed tree.
        allowed: PathBuf,
        /// What it would expose.
        host_only: PathBuf,
    },
}

/// The macOS firmlink aliases: `/tmp`, `/var` and `/etc` are symlinks into
/// `/private`. Returns the other spelling of `p`, if it has one.
pub fn darwin_alias(p: &Path) -> Option<PathBuf> {
    for top in ["tmp", "var", "etc"] {
        let short = Path::new("/").join(top);
        let long = Path::new("/private").join(top);
        // `join("")` would add a trailing slash; `normalize` drops it.
        if let Ok(rest) = p.strip_prefix(&short) {
            return Some(normalize(&long.join(rest)));
        }
        if let Ok(rest) = p.strip_prefix(&long) {
            return Some(normalize(&short.join(rest)));
        }
    }
    None
}

/// Remove `.` components and trailing slashes without touching the
/// filesystem. `..` is refused by [`check`] instead of being interpreted.
fn normalize(p: &Path) -> PathBuf {
    p.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect()
}

fn check(p: &Path) -> Result<&str, ProfileError> {
    let bad = || ProfileError::BadPath(p.to_path_buf());
    let s = p.to_str().ok_or_else(bad)?;
    if !p.is_absolute()
        || s.chars().any(char::is_control)
        || p.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(bad());
    }
    Ok(s)
}

/// SBPL string literal.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// Every spelling of `p` that Seatbelt might see, validated and deduplicated.
fn spellings(p: &Path, resolve: &dyn Fn(&Path) -> PathBuf) -> Result<Vec<PathBuf>, ProfileError> {
    check(p)?;
    let given = normalize(p);
    let resolved = normalize(&resolve(&given));
    let mut out: Vec<PathBuf> = Vec::new();
    for cand in [given.clone(), resolved.clone()]
        .into_iter()
        .chain(darwin_alias(&given))
        .chain(darwin_alias(&resolved))
    {
        check(&cand)?;
        if !out.contains(&cand) {
            out.push(cand);
        }
    }
    Ok(out)
}

/// Proper ancestors of `p`, nearest first, including `/`.
fn ancestors(p: &Path) -> impl Iterator<Item = &Path> {
    p.ancestors().skip(1)
}

/// The resolved sets the profile is written from.
#[derive(Default)]
struct Sets {
    read: BTreeSet<PathBuf>,
    write: BTreeSet<PathBuf>,
    read_files: BTreeSet<PathBuf>,
    hidden: BTreeSet<PathBuf>,
    host_only: BTreeSet<PathBuf>,
    sockets: BTreeSet<PathBuf>,
    terminals: BTreeSet<PathBuf>,
}

fn add(
    set: &mut BTreeSet<PathBuf>,
    p: &Path,
    resolve: &dyn Fn(&Path) -> PathBuf,
) -> Result<(), ProfileError> {
    set.extend(spellings(p, resolve)?);
    Ok(())
}

fn collect(
    plan: &LaunchPlan,
    mac: &MacInputs,
    resolve: &dyn Fn(&Path) -> PathBuf,
) -> Result<Sets, ProfileError> {
    let mut s = Sets::default();
    for p in SYSTEM_READ_ONLY {
        add(&mut s.read, Path::new(p), resolve)?;
    }
    for p in &mac.extra_read_only {
        add(&mut s.read, p, resolve)?;
    }
    for p in SYSTEM_HIDDEN {
        add(&mut s.hidden, Path::new(p), resolve)?;
    }
    for m in &plan.mounts {
        match m.mode {
            MountMode::ReadOnly | MountMode::ReadWrite => {
                if normalize(&m.source) != normalize(&m.target) {
                    return Err(ProfileError::Remap {
                        host: m.source.clone(),
                        inside: m.target.clone(),
                    });
                }
                let set = if m.mode == MountMode::ReadOnly {
                    &mut s.read
                } else {
                    &mut s.write
                };
                add(set, &m.target, resolve)?;
            }
            MountMode::Hidden => add(&mut s.hidden, &m.target, resolve)?,
            // No mount namespace: a tmpfs cannot be conjured at a host path.
            // The home tmpfs is replaced by `mac.home` (the caller points
            // HOME there); other tmpfs targets (`/tmp`, `/var/tmp`) simply
            // stay closed, and programs are pointed at `mac.tmp` instead.
            MountMode::Tmpfs => {}
        }
    }
    add(&mut s.write, &plan.project, resolve)?;
    add(&mut s.write, &mac.home, resolve)?;
    add(&mut s.write, &mac.tmp, resolve)?;
    if let Some(dir) = &mac.shim_dir {
        add(&mut s.read, dir, resolve)?;
    }
    add(&mut s.read_files, &plan.self_exe, resolve)?;
    if let Some(proxy) = &plan.proxy {
        add(&mut s.read_files, &proxy.ca_bundle_host, resolve)?;
        // The sandbox talks to the relay, never to the proxy socket itself.
        add(&mut s.host_only, &proxy.host_socket, resolve)?;
    }
    if let Some(sock) = &plan.approval_socket {
        add(&mut s.sockets, sock, resolve)?;
    }
    for p in &plan.host_only {
        add(&mut s.host_only, p, resolve)?;
    }
    for t in &mac.terminals {
        add(&mut s.terminals, t, resolve)?;
    }

    for w in &s.write {
        if w.parent().is_none() {
            return Err(ProfileError::TooBroad(w.clone()));
        }
    }
    // Nothing allowed may contain a host-only path, and no host-only path
    // may be one of the sockets or files handed to the sandbox.
    for h in &s.host_only {
        let exposed = s
            .read
            .iter()
            .chain(&s.write)
            .find(|a| h.starts_with(a))
            .or_else(|| {
                s.read_files
                    .iter()
                    .chain(&s.sockets)
                    .chain(&s.terminals)
                    .find(|a| *a == h)
            });
        if let Some(a) = exposed {
            return Err(ProfileError::ExposesHostOnly {
                allowed: a.clone(),
                host_only: h.clone(),
            });
        }
    }
    Ok(s)
}

fn rule(out: &mut String, action: &str, ops: &str, filters: &[String]) {
    if filters.is_empty() {
        return;
    }
    let _ = write!(out, "({action} {ops}");
    for f in filters {
        let _ = write!(out, "\n  {f}");
    }
    out.push_str(")\n");
}

fn literals<'a>(paths: impl IntoIterator<Item = &'a PathBuf>) -> Vec<String> {
    paths
        .into_iter()
        .filter_map(|p| p.to_str())
        .map(|s| format!("(literal {})", quote(s)))
        .collect()
}

fn subpaths<'a>(paths: impl IntoIterator<Item = &'a PathBuf>) -> Vec<String> {
    paths
        .into_iter()
        .filter_map(|p| p.to_str())
        .map(|s| format!("(subpath {})", quote(s)))
        .collect()
}

/// The denies that must win over every allow: hidden paths and host-only
/// paths, plus protection of the directories above hidden paths so that a
/// hidden path cannot be moved out from under its rule.
fn denies(out: &mut String, s: &Sets) {
    rule(
        out,
        "deny",
        "file-read* file-write*",
        &subpaths(s.hidden.iter().chain(&s.host_only)),
    );
    rule(
        out,
        "deny",
        "process-exec",
        &subpaths(s.hidden.iter().chain(&s.host_only)),
    );
    rule(out, "deny", "network-outbound", &literals(&s.host_only));
    // Rules match paths, not files: renaming `config/` to `x/` would carry
    // `config/secret` out of `(subpath ".../config/secret")`. Refuse to
    // unlink or rename any directory above a hidden path.
    let mut above: BTreeSet<PathBuf> = BTreeSet::new();
    for h in &s.hidden {
        above.extend(ancestors(h).map(Path::to_path_buf));
    }
    rule(out, "deny", "file-write-unlink", &literals(&above));
}

/// The file allows: system and plan trees, the session's files, devices.
fn files(out: &mut String, s: &Sets) {
    out.push_str("\n; Files.\n");
    // stat() on the directories above every allowed path, so realpath(),
    // getcwd() fallbacks and upward searches (git, cargo, node) work. This
    // reveals that those directories exist, not what they contain.
    let mut meta: BTreeSet<PathBuf> = BTreeSet::new();
    for p in s
        .read
        .iter()
        .chain(&s.write)
        .chain(&s.read_files)
        .chain(&s.sockets)
    {
        meta.extend(ancestors(p).map(Path::to_path_buf));
    }
    for link in ["/tmp", "/var", "/etc"] {
        meta.insert(PathBuf::from(link));
    }
    meta.extend(s.sockets.iter().cloned());
    rule(out, "allow", "file-read-metadata", &literals(&meta));
    rule(out, "allow", "file-read*", &subpaths(&s.read));
    rule(out, "allow", "file-read*", &literals(&s.read_files));
    rule(out, "allow", "file-read* file-write*", &subpaths(&s.write));
    let dev_read: Vec<PathBuf> = DEVICES_READ.iter().map(PathBuf::from).collect();
    let dev_write: Vec<PathBuf> = DEVICES_WRITE.iter().map(PathBuf::from).collect();
    let dev_fd = [PathBuf::from("/dev/fd")];
    rule(out, "allow", "file-read*", &literals(&dev_read));
    rule(out, "allow", "file-read*", &subpaths(&dev_fd));
    rule(
        out,
        "allow",
        "file-write-data",
        &literals(dev_write.iter().chain(&s.terminals)),
    );
    rule(out, "allow", "file-write-data", &subpaths(&dev_fd));
    rule(out, "allow", "file-read-data", &literals(&s.terminals));
    rule(
        out,
        "allow",
        "file-ioctl",
        &literals(dev_write.iter().chain(&s.terminals)),
    );
}

/// Build the profile text for `plan`.
///
/// `resolve` maps a path to its fully resolved form (symlinks followed); the
/// macOS backend passes a canonicalising function, tests pass a fake. It may
/// return its input unchanged.
pub fn build(
    plan: &LaunchPlan,
    mac: &MacInputs,
    resolve: &dyn Fn(&Path) -> PathBuf,
) -> Result<String, ProfileError> {
    let s = collect(plan, mac, resolve)?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "(version 1)\n; agentkeep session {} (generated; do not edit)",
        plan.session_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>()
    );
    out.push_str(
        "; Precedence: the LAST matching rule wins. Hidden and host-only paths\n\
         ; are denied here and again at the end, after every allow.\n\
         (deny default)\n",
    );
    denies(&mut out, &s);

    out.push_str("\n; Processes. Policies are inherited by every child.\n");
    out.push_str("(allow process-fork)\n(allow process-exec)\n");
    // Signals and process inspection only within this sandbox: never the
    // supervisor, never the user's other processes.
    out.push_str("(allow signal (target same-sandbox))\n");
    out.push_str("(allow process-info* (target same-sandbox))\n");
    // POSIX semaphores (Python multiprocessing). Shared memory is not
    // allowed: its names are global to the host.
    out.push_str("(allow ipc-posix-sem)\n");

    out.push_str("\n; Read-only system information.\n");
    let mut sysctl: Vec<String> = SYSCTL_NAMES
        .iter()
        .map(|n| format!("(sysctl-name {})", quote(n)))
        .collect();
    sysctl.extend(
        SYSCTL_PREFIXES
            .iter()
            .map(|n| format!("(sysctl-name-prefix {})", quote(n))),
    );
    rule(&mut out, "allow", "sysctl-read", &sysctl);
    let mach: Vec<String> = MACH_SERVICES
        .iter()
        .map(|n| format!("(global-name {})", quote(n)))
        .collect();
    rule(&mut out, "allow", "mach-lookup", &mach);

    files(&mut out, &s);

    out.push_str("\n; Network: only the relay to the egress proxy and the decision socket.\n");
    if let Some(port) = mac.relay_port {
        let _ = writeln!(
            out,
            "(allow network-outbound (remote ip {}))",
            quote(&format!("localhost:{port}"))
        );
    }
    rule(&mut out, "allow", "network-outbound", &literals(&s.sockets));

    out.push_str("\n; Hidden and host-only paths, last so that they win.\n");
    denies(&mut out, &s);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::plan::{Limits, Mount, ProxyPlan, ShimConfig};

    fn plan() -> LaunchPlan {
        LaunchPlan {
            session_id: "20260101-1".into(),
            mounts: vec![
                Mount {
                    source: "/usr".into(),
                    target: "/usr".into(),
                    mode: MountMode::ReadOnly,
                    size: None,
                },
                Mount {
                    source: "/etc".into(),
                    target: "/etc".into(),
                    mode: MountMode::ReadOnly,
                    size: None,
                },
                Mount {
                    source: PathBuf::new(),
                    target: "/Users/u".into(),
                    mode: MountMode::Tmpfs,
                    size: None,
                },
                Mount {
                    source: "/Users/u/work/p".into(),
                    target: "/Users/u/work/p".into(),
                    mode: MountMode::ReadWrite,
                    size: None,
                },
                Mount {
                    source: PathBuf::new(),
                    target: "/Users/u/.ssh".into(),
                    mode: MountMode::Hidden,
                    size: None,
                },
                Mount {
                    source: PathBuf::new(),
                    target: "/Users/u/work/p/config/secret.json".into(),
                    mode: MountMode::Hidden,
                    size: None,
                },
                Mount {
                    source: PathBuf::new(),
                    target: "/tmp".into(),
                    mode: MountMode::Tmpfs,
                    size: None,
                },
            ],
            project: "/Users/u/work/p".into(),
            home: "/Users/u".into(),
            env: BTreeMap::new(),
            cwd: "/Users/u/work/p".into(),
            command: vec!["sh".into()],
            limits: Limits::default(),
            hostname: "agentkeep".into(),
            self_exe: "/opt/ak/bin/agentkeep".into(),
            root_base: "/var/folders/xy/T/agentkeep.1/root".into(),
            user_name: "u".into(),
            approval_socket: Some("/var/folders/xy/T/agentkeep.1/exec.sock".into()),
            shim: Some(ShimConfig {
                dir: "/run/agentkeep/bin".into(),
                commands: vec!["git".into()],
                socket: "/run/agentkeep/exec.sock".into(),
            }),
            proxy: Some(ProxyPlan {
                host_socket: "/var/folders/xy/T/agentkeep.1/proxy.sock".into(),
                sandbox_socket: "/run/agentkeep/proxy.sock".into(),
                port: 3128,
                ca_bundle_host: "/var/folders/xy/T/agentkeep.1/ca-bundle.pem".into(),
                ca_bundle_sandbox: "/run/agentkeep/ca-bundle.pem".into(),
            }),
            host_only: vec!["/var/folders/xy/T/agentkeep.1/approve.sock".into()],
            landlock: false,
            seccomp: false,
            inner_uid: 501,
            inner_gid: 20,
        }
    }

    fn mac() -> MacInputs {
        MacInputs {
            home: "/var/folders/xy/T/agentkeep.1/root/home".into(),
            tmp: "/var/folders/xy/T/agentkeep.1/root/tmp".into(),
            shim_dir: Some("/var/folders/xy/T/agentkeep.1/root/bin".into()),
            relay_port: Some(50123),
            extra_read_only: vec![],
            terminals: vec!["/dev/ttys003".into()],
        }
    }

    fn same(p: &Path) -> PathBuf {
        p.to_path_buf()
    }

    fn profile() -> String {
        build(&plan(), &mac(), &same).unwrap()
    }

    /// Index of the last line containing `needle`.
    fn last(text: &str, needle: &str) -> usize {
        text.lines()
            .enumerate()
            .filter(|(_, l)| l.contains(needle))
            .map(|(i, _)| i)
            .last()
            .unwrap_or_else(|| panic!("`{needle}` not in profile:\n{text}"))
    }

    #[test]
    fn starts_closed() {
        let p = profile();
        assert!(p.starts_with("(version 1)\n"));
        assert!(p.contains("\n(deny default)\n"));
        assert!(!p.contains("(allow default)"));
        // No blanket grants of whole operation classes.
        for broad in [
            "(allow file-read*)",
            "(allow file-write*)",
            "(allow network*",
            "(allow network-outbound)",
            "(allow mach-lookup)",
            "(allow sysctl-read)",
            "(allow signal)",
            "(allow file-link",
            "(allow ipc-posix-shm",
            "(allow user-preference",
            "(allow iokit",
            "(allow pseudo-tty",
            "regex",
        ] {
            assert!(!p.contains(broad), "profile contains `{broad}`:\n{p}");
        }
    }

    #[test]
    fn hidden_denies_come_after_every_allow() {
        let p = profile();
        let last_allow = last(&p, "(allow ");
        let ssh = last(&p, "(subpath \"/Users/u/.ssh\")");
        let secret = last(&p, "(subpath \"/Users/u/work/p/config/secret.json\")");
        let keychains = last(&p, "(subpath \"/Library/Keychains\")");
        for (name, line) in [("ssh", ssh), ("secret", secret), ("keychains", keychains)] {
            assert!(line > last_allow, "{name} deny is not last:\n{p}");
        }
        // ...and they are also present before the first allow.
        let first_allow = p.lines().position(|l| l.contains("(allow ")).unwrap();
        let first_ssh = p
            .lines()
            .position(|l| l.contains("(subpath \"/Users/u/.ssh\")"))
            .unwrap();
        assert!(first_ssh < first_allow);
        // Deny rule headers precede them.
        assert!(p.contains("(deny file-read* file-write*\n  (subpath \"/Library/Keychains\")"));
    }

    #[test]
    fn hidden_paths_cannot_be_renamed_away() {
        let p = profile();
        let tail = &p[p.rfind("; Hidden and host-only").unwrap()..];
        assert!(tail.contains("(deny file-write-unlink"));
        assert!(tail.contains("(literal \"/Users/u/work/p/config\")"));
        assert!(tail.contains("(literal \"/Users/u/work/p\")"));
    }

    #[test]
    fn project_home_and_tmp_are_writable_nothing_else() {
        let p = profile();
        let start = p.find("(allow file-read* file-write*").unwrap();
        let block = &p[start..start + p[start..].find(")\n(").unwrap()];
        let mut writable: Vec<&str> = block
            .lines()
            .filter_map(|l| l.trim().strip_prefix("(subpath \""))
            .map(|l| l.trim_end_matches("\")").trim_end_matches('"'))
            .collect();
        writable.sort_unstable();
        assert_eq!(
            writable,
            vec![
                "/Users/u/work/p",
                "/private/var/folders/xy/T/agentkeep.1/root/home",
                "/private/var/folders/xy/T/agentkeep.1/root/tmp",
                "/var/folders/xy/T/agentkeep.1/root/home",
                "/var/folders/xy/T/agentkeep.1/root/tmp",
            ],
            "{p}"
        );
        // The real home, /tmp and /var/tmp are not allowed at all.
        assert!(!p.contains("(subpath \"/Users/u\")"));
        assert!(!p.contains("(subpath \"/tmp\")"));
        assert!(!p.contains("(subpath \"/private/tmp\")"));
    }

    #[test]
    fn system_paths_read_only_and_aliases_both_spelled() {
        let p = profile();
        for sp in ["/usr", "/System", "/Library", "/private/etc", "/etc"] {
            assert!(
                p.contains(&format!("(subpath \"{sp}\")")),
                "missing {sp}:\n{p}"
            );
        }
        assert!(!p.contains("(subpath \"/Users\")"));
        assert!(!p.contains("(subpath \"/Applications\")"));
        assert!(!p.contains("(subpath \"/private/var\")"));
        // ~/Library is not /Library.
        assert!(!p.contains("(subpath \"/Users/u/Library\")"));
    }

    #[test]
    fn network_only_relay_and_exec_socket() {
        let p = profile();
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:50123\"))"));
        assert!(p.contains(
            "(allow network-outbound\n  (literal \"/private/var/folders/xy/T/agentkeep.1/exec.sock\")"
        ));
        let outbound: Vec<&str> = p.lines().filter(|l| l.contains("(allow network")).collect();
        assert_eq!(outbound.len(), 2, "{p}");
        // No allow rule ever names the approver or the proxy socket.
        for host_only in ["approve.sock", "proxy.sock"] {
            let allowed = p
                .split("\n(")
                .filter(|r| r.starts_with("allow"))
                .any(|r| r.contains(host_only));
            assert!(!allowed, "{host_only} allowed:\n{p}");
        }
        let tail = &p[p.rfind("; Hidden and host-only").unwrap()..];
        let deny_net = &tail[tail.find("(deny network-outbound").unwrap()..];
        let deny_net = &deny_net[..deny_net.find("))").unwrap()];
        for sp in ["/var/folders", "/private/var/folders"] {
            for sock in ["approve.sock", "proxy.sock"] {
                assert!(
                    deny_net.contains(&format!("(literal \"{sp}/xy/T/agentkeep.1/{sock}\"")),
                    "{sp} {sock} not denied:\n{p}"
                );
            }
        }
        // No resolver: neither the mDNSResponder socket nor its service.
        assert!(!p.contains("mDNSResponder"));
        assert!(!p.contains("dnssd"));
    }

    #[test]
    fn no_relay_means_no_tcp() {
        let mut m = mac();
        m.relay_port = None;
        let p = build(&plan(), &m, &same).unwrap();
        assert!(!p.contains("remote ip"));
    }

    #[test]
    fn keychain_and_launch_services_are_not_reachable() {
        let p = profile();
        for svc in [
            "SecurityServer",
            "securityd",
            "trustd",
            "launchservicesd",
            "lsd.",
            "appleevents",
            "pasteboard",
            "nsurlsessiond",
            "FSEvents",
            "configd",
        ] {
            assert!(!p.contains(svc), "{svc} reachable:\n{p}");
        }
        assert!(!p.contains("kern.proc"), "process listing readable");
    }

    #[test]
    fn signals_stay_inside_the_sandbox() {
        let p = profile();
        assert!(p.contains("(allow signal (target same-sandbox))"));
        assert!(!p.contains("(target others)"));
    }

    #[test]
    fn terminal_is_only_the_session_terminal() {
        let p = profile();
        assert!(p.contains("(literal \"/dev/ttys003\")"));
        let ttys = p.matches("/dev/ttys").count();
        assert_eq!(ttys, p.matches("/dev/ttys003\"").count(), "{p}");
        assert!(!p.contains("/dev/ptmx"));
        assert!(!p.contains("(subpath \"/dev\")"));
    }

    #[test]
    fn resolved_paths_are_added_too() {
        // Pretend the project lives behind a symlink.
        let resolve = |p: &Path| -> PathBuf {
            match p.strip_prefix("/Users/u/work") {
                Ok(rest) => Path::new("/Volumes/Data/work").join(rest),
                Err(_) => p.to_path_buf(),
            }
        };
        let p = build(&plan(), &mac(), &resolve).unwrap();
        assert!(p.contains("(subpath \"/Volumes/Data/work/p\")"));
        assert!(p.contains("(subpath \"/Users/u/work/p\")"));
        // The hidden file inside it is denied under both names.
        let tail = &p[p.rfind("; Hidden and host-only").unwrap()..];
        assert!(tail.contains("(subpath \"/Volumes/Data/work/p/config/secret.json\")"));
        assert!(tail.contains("(subpath \"/Users/u/work/p/config/secret.json\")"));
    }

    #[test]
    fn quoting_escapes_and_bad_paths_are_refused() {
        assert_eq!(quote(r#"/a "b"\c"#), r#""/a \"b\"\\c""#);
        let mut pl = plan();
        pl.project = "/Users/u/work/p\")(allow default)(\"".into();
        pl.mounts.retain(|m| m.mode != MountMode::ReadWrite);
        let p = build(&pl, &mac(), &same).unwrap();
        assert!(p.contains(r#"(subpath "/Users/u/work/p\")(allow default)(\"")"#));
        assert!(!p.contains("\n(allow default)"));
        for bad in ["relative/path", "/a/\nb", "/a/../b", "/a\u{7}"] {
            let mut pl = plan();
            pl.project = bad.into();
            assert!(
                matches!(build(&pl, &mac(), &same), Err(ProfileError::BadPath(_))),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn root_cannot_be_writable() {
        let mut pl = plan();
        pl.mounts.push(Mount {
            source: "/".into(),
            target: "/".into(),
            mode: MountMode::ReadWrite,
            size: None,
        });
        assert!(matches!(
            build(&pl, &mac(), &same),
            Err(ProfileError::TooBroad(_))
        ));
    }

    #[test]
    fn remapped_mounts_are_refused() {
        let mut pl = plan();
        pl.mounts.push(Mount {
            source: "/opt/a".into(),
            target: "/opt/b".into(),
            mode: MountMode::ReadOnly,
            size: None,
        });
        assert!(matches!(
            build(&pl, &mac(), &same),
            Err(ProfileError::Remap { .. })
        ));
    }

    #[test]
    fn allowed_tree_containing_the_approver_socket_is_refused() {
        let mut pl = plan();
        pl.mounts.push(Mount {
            source: "/var/folders".into(),
            target: "/var/folders".into(),
            mode: MountMode::ReadOnly,
            size: None,
        });
        assert!(matches!(
            build(&pl, &mac(), &same),
            Err(ProfileError::ExposesHostOnly { .. })
        ));
        // Or handing it over as the decision socket.
        let mut pl = plan();
        pl.approval_socket = pl.host_only.first().cloned();
        assert!(matches!(
            build(&pl, &mac(), &same),
            Err(ProfileError::ExposesHostOnly { .. })
        ));
    }

    #[test]
    fn aliases() {
        assert_eq!(
            darwin_alias(Path::new("/tmp/x")),
            Some(PathBuf::from("/private/tmp/x"))
        );
        assert_eq!(
            darwin_alias(Path::new("/private/var/folders")),
            Some(PathBuf::from("/var/folders"))
        );
        assert_eq!(
            darwin_alias(Path::new("/etc")),
            Some(PathBuf::from("/private/etc"))
        );
        assert_eq!(
            darwin_alias(Path::new("/private/etc")),
            Some(PathBuf::from("/etc"))
        );
        assert_eq!(
            darwin_alias(Path::new("/private/etc")).unwrap().as_os_str(),
            "/etc",
            "no trailing slash"
        );
        assert_eq!(darwin_alias(Path::new("/variable")), None);
        assert_eq!(darwin_alias(Path::new("/Users/u")), None);
    }

    #[test]
    fn parentheses_balance() {
        // A crude parser check: every rule closes, nothing is left open.
        let p = profile();
        let mut depth = 0i32;
        let mut in_str = false;
        let mut esc = false;
        for line in p.lines() {
            if line.trim_start().starts_with(';') {
                continue;
            }
            for ch in line.chars() {
                if in_str {
                    if esc {
                        esc = false;
                    } else if ch == '\\' {
                        esc = true;
                    } else if ch == '"' {
                        in_str = false;
                    }
                    continue;
                }
                match ch {
                    '"' => in_str = true,
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                assert!(depth >= 0, "unbalanced:\n{p}");
            }
        }
        assert_eq!(depth, 0, "unbalanced:\n{p}");
        assert!(!in_str);
    }
}
