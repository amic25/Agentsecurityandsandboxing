//! Heuristics for names that usually hold secrets.
//!
//! These never see values. They decide which *names* are logged as "scrubbed
//! secret" rather than "scrubbed variable", and which paths the defaults hide.

/// Substrings that make an environment variable name look like a secret.
/// Compared case-insensitively against the whole name.
const SECRET_NAME_MARKERS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CLIENT_SECRET",
    "CREDENTIAL",
    "AUTH",
    "SESSION_KEY",
    "SIGNING_KEY",
    "ENCRYPTION_KEY",
    "_KEY",
];

/// Names that contain a marker but are not secrets in practice.
const SECRET_NAME_EXCEPTIONS: &[&str] = &["SSH_AUTH_SOCK", "GPG_TTY", "XAUTHORITY", "KEYBOARD"];

/// Does this environment variable name look like it holds a secret?
pub fn looks_like_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if SECRET_NAME_EXCEPTIONS.iter().any(|e| upper == *e) {
        return false;
    }
    SECRET_NAME_MARKERS.iter().any(|m| upper.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_secret_names() {
        for n in [
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "DATABASE_PASSWORD",
            "npm_config__auth",
            "my_private_key",
        ] {
            assert!(looks_like_secret_name(n), "{n}");
        }
    }

    #[test]
    fn leaves_ordinary_names_alone() {
        for n in [
            "HOME",
            "PATH",
            "TERM",
            "SSH_AUTH_SOCK",
            "LANG",
            "KEYBOARD",
            "EDITOR",
        ] {
            assert!(!looks_like_secret_name(n), "{n}");
        }
    }
}
