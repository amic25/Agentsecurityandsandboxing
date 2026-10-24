//! Built-in defaults. This is the lowest layer of every policy and the
//! single place where the deny-by-default posture is written down.
//!
//! The text is real TOML with comments so `agentkeep policy show --defaults`
//! prints exactly what is compiled in.

/// The built-in default policy.
pub const DEFAULT_POLICY: &str = r#"# agentkeep built-in defaults.
# Everything not listed here is unavailable to the agent.
schema = 1

[sandbox]
backend = "auto"
allow_degraded = false

[filesystem]
# The project is the only read-write tree. It is resolved at run time: the
# git root of the current directory, or the current directory itself.
project = "."
# System paths visible read-only. Only those that exist on the host are mounted.
read_only = [
  "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
  "/etc", "/opt", "/nix", "/snap", "/var/lib/snapd",
  "/run/current-system",            # NixOS
  "/run/host/usr",                  # Flatpak-style hosts
]
read_write = []
# Hidden even if a parent is made visible. The home directory itself is not
# mounted at all; this list is a second layer for paths users bind on purpose.
hidden = [
  "~/.ssh",
  "~/.aws",
  "~/.azure",
  "~/.config/gcloud",
  "~/.kube",
  "~/.docker",
  "~/.gnupg",
  "~/.password-store",
  "~/.netrc",
  "~/.npmrc",
  "~/.pypirc",
  "~/.cargo/credentials",
  "~/.cargo/credentials.toml",
  "~/.gem/credentials",
  "~/.config/gh",
  "~/.config/hub",
  "~/.config/op",
  "~/.1password",
  "~/.terraform.d/credentials.tfrc.json",
  "~/.vault-token",
  "~/.local/share/keyrings",
  "~/.mozilla",
  "~/.thunderbird",
  "~/.config/google-chrome",
  "~/.config/chromium",
  "~/.config/BraveSoftware",
  "~/.config/microsoft-edge",
  "~/.config/vivaldi",
  "~/snap/firefox",
  "~/Library/Keychains",
  "~/Library/Application Support/Google/Chrome",
  "~/Library/Application Support/Firefox",
  "~/Library/Application Support/BraveSoftware",
  "~/Library/Application Support/Microsoft Edge",
  "~/Library/Cookies",
  "/etc/shadow",
  "/etc/gshadow",
  "/etc/sudoers",
  "/etc/sudoers.d",
  "/etc/ssh/ssh_host_ed25519_key",
  "/etc/ssh/ssh_host_rsa_key",
  "/etc/ssh/ssh_host_ecdsa_key",
  "/etc/docker",
  "/etc/kubernetes",
  "/var/run/docker.sock",
  "/run/docker.sock",
]

[env]
# Passed through unchanged. Everything else is dropped; dropped names that
# look like secrets are recorded in the audit log (names only, never values).
allow = [
  "HOME", "PATH", "USER", "LOGNAME", "SHELL", "EDITOR", "VISUAL", "PAGER",
  "LANG", "LANGUAGE", "LC_*", "TZ", "TERM", "COLORTERM", "TERM_PROGRAM",
  "COLUMNS", "LINES", "NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "FORCE_COLOR",
  "CI",
]
# Secrets the agent needs (its own provider key). Add yours here or in a preset.
pass = []

[env.set]
TMPDIR = "/tmp"

[network]
allow = []
ask = []
deny = []
tls_inspect = true
passthrough = []
allow_private = false

[dlp]
enabled = true
block_values = []

[commands]
ask = [
  "git push*",
  "git remote add*",
  "git remote set-url*",
  "rm -rf *",
  "rm -fr *",
  "git clean -*f*",
  "git reset --hard*",
  "docker *",
  "podman *",
  "kubectl *",
  "terraform apply*",
  "terraform destroy*",
  "aws *",
  "gcloud *",
  "az *",
  "npm publish*",
  "cargo publish*",
  "twine upload*",
  "gh release*",
  "gh repo delete*",
]
deny = [
  "sudo *",
  "su *",
  "su",
  "doas *",
  "pkexec *",
  # Pipelines are only visible when a shell is asked to run them, so these
  # start with `*` to catch `sh -c "curl ... | sh"` as well.
  "*curl * | *sh*",
  "*wget * | *sh*",
  "ssh *",
  "scp *",
  "sftp *",
  "mount *",
  "umount *",
]

[mcp]
allow_tools = []
deny_tools = []
pin = "strict"
block_injection = false

[limits]
cpu_percent = 400
memory = "8G"
pids = 1024
wall_time = "8h"

[approval]
transport = ["tty", "socket"]
timeout = "60s"

[audit]
dir = "~/.local/share/agentkeep/sessions"
redact = true
"#;

/// Template written by `agentkeep policy init --defaults` into a project.
/// It states only what a project typically changes; everything else comes
/// from the built-in defaults above.
pub const PROJECT_TEMPLATE: &str = r#"# agentkeep policy for this project.
# Reference: https://github.com/amic25/Agentsecurityandsandboxing/blob/main/docs/policy.md
# Everything not listed here falls back to the built-in defaults
# (`agentkeep policy show --defaults`). Rules only tighten: a project file can
# add allowed domains and paths, but it cannot remove a built-in `hidden` or
# `deny` entry without the explicit [override] table below.
schema = 1

[sandbox]
# backend = "auto"          # auto | linux | macos | container | wsl
# preset = "claude-code"    # normally auto-detected from the command

[filesystem]
# Extra paths the agent may read or write. "~" and "$PROJECT" are expanded.
read_only = []
read_write = []
# Add project-specific secrets here, e.g. "$PROJECT/.env.production"
hidden = []

[env]
# Variables passed through unchanged. Secrets go in `pass`, not here.
allow = []
# Secrets the agent needs. DLP binds each one to its provider's domains.
pass = []

[network]
# Hosts the agent may reach, in addition to the preset's. `*.example.com`
# matches subdomains only.
allow = []
# Hosts that prompt on first contact during the session.
ask = []
deny = []

[commands]
# Globs matched against the full command line. Deny beats ask.
ask = []
deny = []

[limits]
# memory = "4G"
# pids = 512
# wall_time = "2h"

# [override]
# acknowledge = true
# unhide = ["~/.npmrc"]    # printed in red at every start and written to the audit log
"#;

#[cfg(test)]
mod tests {
    use crate::parse_str;

    #[test]
    fn defaults_parse() {
        let f = parse_str(super::DEFAULT_POLICY, "<defaults>").unwrap();
        assert!(f
            .filesystem
            .as_ref()
            .unwrap()
            .hidden
            .iter()
            .any(|p| p == "~/.ssh"));
        assert!(
            f.network.as_ref().unwrap().allow.is_empty(),
            "defaults must allow no domains"
        );
    }

    #[test]
    fn template_parses() {
        parse_str(super::PROJECT_TEMPLATE, "<template>").unwrap();
    }
}
