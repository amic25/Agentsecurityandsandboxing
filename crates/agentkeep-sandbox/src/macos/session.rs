//! Host-side session layout for a backend without a mount namespace.
//!
//! On Linux the sandbox sees an empty tmpfs at the user's home, `/tmp` and
//! `/run/agentkeep`. On macOS nothing can be mounted, so the backend creates
//! real directories in the session's scratch directory and points the
//! command's environment at them instead. Everything here is plain file
//! system work and string rewriting, compiled on every Unix and tested on
//! Linux.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::plan::LaunchPlan;

/// Proxy variables pointed at the relay.
pub const PROXY_VARS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

/// CA bundle variables pointed at the host copy of the bundle.
pub const CA_VARS: &[&str] = &[
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    "DENO_CERT",
    "CARGO_HTTP_CAINFO",
    "NIX_SSL_CERT_FILE",
    "AWS_CA_BUNDLE",
    "PIP_CERT",
    "NPM_CONFIG_CAFILE",
];

/// Where the session's private directories live, all under the plan's
/// `root_base` (which the supervisor creates and removes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// Private `HOME`.
    pub home: PathBuf,
    /// Private `TMPDIR`.
    pub tmp: PathBuf,
    /// Command shims.
    pub shim_dir: PathBuf,
    /// The generated Seatbelt profile.
    pub profile: PathBuf,
}

impl Layout {
    /// The layout under `root_base`.
    pub fn new(root_base: &Path) -> Self {
        Self {
            home: root_base.join("home"),
            tmp: root_base.join("tmp"),
            shim_dir: root_base.join("bin"),
            profile: root_base.join("profile.sb"),
        }
    }

    /// Create the directories (owner-only) and the shim symlinks.
    pub fn create(&self, plan: &LaunchPlan) -> io::Result<()> {
        let mut b = fs::DirBuilder::new();
        b.mode(0o700);
        for d in [&self.home, &self.tmp, &self.shim_dir] {
            b.create(d)?;
        }
        if let Some(shim) = &plan.shim {
            for cmd in &shim.commands {
                // Same rule as the Linux backend: plain names only.
                if cmd.is_empty() || cmd.contains('/') || cmd == "." || cmd == ".." {
                    continue;
                }
                std::os::unix::fs::symlink(&plan.self_exe, self.shim_dir.join(cmd))?;
            }
        }
        Ok(())
    }

    /// Write the profile with mode 0600. Fails if it already exists, so a
    /// planted file is never reused.
    pub fn write_profile(&self, text: &str) -> io::Result<()> {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.profile)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()
    }
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// The environment the command actually gets on macOS: the plan's
/// environment with every sandbox-internal path replaced by its host
/// counterpart. `relay_port` is the supervisor's loopback relay to the
/// egress proxy; without it all proxy variables are removed, which leaves
/// the command without network (fail closed).
pub fn rewrite_env(
    plan: &LaunchPlan,
    layout: &Layout,
    relay_port: Option<u16>,
) -> BTreeMap<String, String> {
    let mut env = plan.env.clone();
    env.insert("HOME".into(), path_str(&layout.home));
    env.insert("TMPDIR".into(), path_str(&layout.tmp));
    for k in ["TMP", "TEMP", "XDG_RUNTIME_DIR"] {
        if env.contains_key(k) {
            env.insert(k.into(), path_str(&layout.tmp));
        }
    }

    for k in PROXY_VARS {
        env.remove(*k);
    }
    for k in CA_VARS {
        env.remove(*k);
    }
    if let (Some(proxy), Some(port)) = (&plan.proxy, relay_port) {
        let url = format!("http://127.0.0.1:{port}");
        for k in PROXY_VARS {
            env.insert((*k).into(), url.clone());
        }
        let ca = path_str(&proxy.ca_bundle_host);
        let inside = path_str(&proxy.ca_bundle_sandbox);
        for v in env.values_mut() {
            if *v == inside {
                v.clone_from(&ca);
            }
        }
        for k in CA_VARS {
            env.insert((*k).into(), ca.clone());
        }
    }

    match &plan.approval_socket {
        Some(sock) => {
            env.insert("AGENTKEEP_SOCKET".into(), path_str(sock));
        }
        None => {
            env.remove("AGENTKEEP_SOCKET");
        }
    }

    let host_shims = path_str(&layout.shim_dir);
    let inner_shims = plan.shim.as_ref().map(|s| path_str(&s.dir));
    let path = env.get("PATH").cloned().unwrap_or_default();
    let mut parts: Vec<String> = path
        .split(':')
        .filter(|p| !p.is_empty())
        .filter(|p| Some(*p) != inner_shims.as_deref() && *p != host_shims)
        .map(String::from)
        .collect();
    if plan.shim.is_some() {
        parts.insert(0, host_shims.clone());
        env.insert("AGENTKEEP_SHIM_DIR".into(), host_shims);
    } else {
        env.remove("AGENTKEEP_SHIM_DIR");
    }
    env.insert("PATH".into(), parts.join(":"));
    env
}

/// Resolve `p` as far as it exists: canonicalise the longest existing
/// prefix and append the rest. Used to spell every profile path the way the
/// kernel will see it.
pub fn resolve_existing(p: &Path) -> PathBuf {
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p;
    loop {
        if let Ok(real) = fs::canonicalize(cur) {
            let mut out = real;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                cur = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Limits, ProxyPlan, ShimConfig};

    fn plan(root: &Path) -> LaunchPlan {
        let env = BTreeMap::from([
            ("HOME".into(), "/Users/u".into()),
            ("TMPDIR".into(), "/tmp".into()),
            ("XDG_RUNTIME_DIR".into(), "/run/user/1000".into()),
            (
                "PATH".into(),
                "/run/agentkeep/bin:/usr/local/bin:/usr/bin:/bin".into(),
            ),
            ("HTTPS_PROXY".into(), "http://127.0.0.1:3128".into()),
            ("http_proxy".into(), "http://127.0.0.1:3128".into()),
            (
                "SSL_CERT_FILE".into(),
                "/run/agentkeep/ca-bundle.pem".into(),
            ),
            ("MY_CA".into(), "/run/agentkeep/ca-bundle.pem".into()),
            ("AGENTKEEP_SOCKET".into(), "/run/agentkeep/exec.sock".into()),
            ("AGENTKEEP_SHIM_DIR".into(), "/run/agentkeep/bin".into()),
            ("LANG".into(), "C".into()),
        ]);
        LaunchPlan {
            session_id: "s".into(),
            mounts: vec![],
            project: root.join("p"),
            home: "/Users/u".into(),
            env,
            cwd: root.join("p"),
            command: vec!["sh".into()],
            limits: Limits::default(),
            hostname: "agentkeep".into(),
            self_exe: "/opt/ak/agentkeep".into(),
            root_base: root.join("root"),
            user_name: "u".into(),
            approval_socket: Some(root.join("exec.sock")),
            shim: Some(ShimConfig {
                dir: "/run/agentkeep/bin".into(),
                commands: vec!["git".into(), "sudo".into(), "../evil".into(), String::new()],
                socket: "/run/agentkeep/exec.sock".into(),
            }),
            proxy: Some(ProxyPlan {
                host_socket: root.join("proxy.sock"),
                sandbox_socket: "/run/agentkeep/proxy.sock".into(),
                port: 3128,
                ca_bundle_host: root.join("ca-bundle.pem"),
                ca_bundle_sandbox: "/run/agentkeep/ca-bundle.pem".into(),
            }),
            host_only: vec![root.join("approve.sock")],
            landlock: false,
            seccomp: false,
            inner_uid: 501,
            inner_gid: 20,
        }
    }

    #[test]
    fn env_points_at_host_paths() {
        let root = Path::new("/scratch");
        let p = plan(root);
        let l = Layout::new(&p.root_base);
        let env = rewrite_env(&p, &l, Some(50123));
        assert_eq!(env["HOME"], "/scratch/root/home");
        assert_eq!(env["TMPDIR"], "/scratch/root/tmp");
        assert_eq!(env["XDG_RUNTIME_DIR"], "/scratch/root/tmp");
        assert_eq!(
            env["PATH"],
            "/scratch/root/bin:/usr/local/bin:/usr/bin:/bin"
        );
        assert_eq!(env["AGENTKEEP_SHIM_DIR"], "/scratch/root/bin");
        assert_eq!(env["AGENTKEEP_SOCKET"], "/scratch/exec.sock");
        for k in PROXY_VARS {
            assert_eq!(env[*k], "http://127.0.0.1:50123", "{k}");
        }
        for k in CA_VARS {
            assert_eq!(env[*k], "/scratch/ca-bundle.pem", "{k}");
        }
        assert_eq!(env["MY_CA"], "/scratch/ca-bundle.pem");
        assert_eq!(env["LANG"], "C");
        // Nothing still points into the Linux-only /run/agentkeep tree, and
        // the approver socket is never named.
        for (k, v) in &env {
            assert!(!v.contains("/run/agentkeep"), "{k}={v}");
            assert!(!v.contains("approve.sock"), "{k}={v}");
            assert!(!v.contains("proxy.sock"), "{k}={v}");
        }
    }

    #[test]
    fn no_relay_means_no_proxy_and_no_network_hint() {
        let p = plan(Path::new("/scratch"));
        let env = rewrite_env(&p, &Layout::new(&p.root_base), None);
        for k in PROXY_VARS.iter().chain(CA_VARS) {
            assert!(!env.contains_key(*k), "{k}");
        }
    }

    #[test]
    fn no_shims_no_shim_dir_and_no_socket() {
        let mut p = plan(Path::new("/scratch"));
        p.shim = None;
        p.approval_socket = None;
        p.env
            .insert("PATH".into(), "/usr/local/bin::/usr/bin:/bin".into());
        let env = rewrite_env(&p, &Layout::new(&p.root_base), None);
        assert!(!env.contains_key("AGENTKEEP_SHIM_DIR"));
        assert!(!env.contains_key("AGENTKEEP_SOCKET"));
        assert_eq!(env["PATH"], "/usr/local/bin:/usr/bin:/bin");
    }

    #[test]
    fn layout_creates_private_dirs_and_plain_shims() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut p = plan(dir.path());
        fs::create_dir(&p.root_base).unwrap();
        p.self_exe = dir.path().join("agentkeep");
        let l = Layout::new(&p.root_base);
        l.create(&p).unwrap();
        for d in [&l.home, &l.tmp, &l.shim_dir] {
            let mode = fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", d.display());
        }
        let mut shims: Vec<String> = fs::read_dir(&l.shim_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        shims.sort();
        assert_eq!(shims, vec!["git", "sudo"]);
        assert_eq!(fs::read_link(l.shim_dir.join("git")).unwrap(), p.self_exe);
        assert!(!dir.path().join("evil").exists());

        l.write_profile("(version 1)").unwrap();
        let mode = fs::metadata(&l.profile).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            l.write_profile("(version 1)").is_err(),
            "profile must be fresh"
        );
    }

    #[test]
    fn resolve_follows_symlinks_of_existing_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
        let got = resolve_existing(&dir.path().join("link/missing/file"));
        assert_eq!(got, fs::canonicalize(&real).unwrap().join("missing/file"));
        assert_eq!(
            resolve_existing(Path::new("/definitely/not/here")),
            PathBuf::from("/definitely/not/here")
        );
    }
}
