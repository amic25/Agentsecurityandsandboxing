//! The macOS backend: a Seatbelt profile generated per session and applied
//! with `/usr/bin/sandbox-exec`.
//!
//! macOS has no mount, pid or network namespaces, so this backend works
//! differently from the Linux one:
//!
//! - **Files** stay where they are. The profile ([`profile`]) allows reading
//!   the system trees and the plan's read-only paths, reading and writing
//!   the project and a private `HOME` and `TMPDIR` created in the session's
//!   scratch directory, and denies every hidden path even under an allowed
//!   parent. Everything else is refused with `EPERM`, but stays visible to
//!   `stat` on the directories above allowed paths.
//! - **Environment**: paths the Linux backend shows at fixed places inside
//!   the sandbox (`/run/agentkeep/...`, the tmpfs home) are rewritten to
//!   their host locations ([`session`]).
//! - **Network**: the supervisor runs a loopback relay to the egress proxy
//!   ([`relay`]); the profile allows outbound connections to that one port
//!   and to the decision socket, and nothing else, so DNS and direct
//!   connections fail.
//! - **Processes**: the command leads its own process group, gets
//!   `RLIMIT_CORE = 0` and an approximate `RLIMIT_NPROC`, and the whole
//!   group is killed at the wall-clock limit and when the command exits.
//!
//! [`profile`], [`session`] and [`relay`] are portable and unit-tested on
//! Linux; only probing and launching need macOS.

pub mod profile;
#[cfg(unix)]
pub mod relay;
#[cfg(unix)]
pub mod session;

#[cfg(target_os = "macos")]
mod backend;
#[cfg(target_os = "macos")]
mod sys;

#[cfg(target_os = "macos")]
pub use backend::{install_supervisor_signals, MacosBackend, MacosHandle, SANDBOX_EXEC};

#[cfg(target_os = "macos")]
pub(crate) use backend::{give_terminal_back, take_terminal};
