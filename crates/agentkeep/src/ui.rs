//! Terminal output helpers. Colour only when stderr is a terminal and
//! `NO_COLOR` is unset.

use std::io::IsTerminal;

fn colour() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn paint(code: &str, text: &str) -> String {
    if colour() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// A red error line.
pub fn error(msg: &str) {
    eprintln!("{} {msg}", paint("1;31", "agentkeep: error:"));
}

/// A yellow warning line.
pub fn warn(msg: &str) {
    eprintln!("{} {msg}", paint("1;33", "agentkeep: warning:"));
}

/// A red line for a weakened protection; always loud.
pub fn danger(msg: &str) {
    eprintln!("{} {msg}", paint("1;31", "agentkeep: PROTECTION WEAKENED:"));
}

/// A dim informational line.
pub fn info(msg: &str) {
    eprintln!("{}", paint("2", &format!("agentkeep: {msg}")));
}

/// Bold text for prompts.
pub fn bold(text: &str) -> String {
    paint("1", text)
}
