//! `agentkeep doctor`: which backends work here and what each can enforce.

use std::process::ExitCode;

use anyhow::Result;

/// Exit code when no sandbox backend is available.
pub const EXIT_NO_BACKEND: u8 = 3;

/// `agentkeep doctor`: probe every compiled-in backend.
pub fn run() -> Result<ExitCode> {
    let mut any = false;
    for b in agentkeep_sandbox::backends() {
        match b.probe() {
            agentkeep_sandbox::Probe::Available {
                capabilities,
                degradations,
            } => {
                any = true;
                println!("{}: available", b.name());
                println!("{}", serde_json::to_string_pretty(&capabilities)?);
                for d in degradations {
                    println!(
                        "  degraded: {} ({}); fallback: {}",
                        d.control, d.reason, d.fallback
                    );
                }
            }
            agentkeep_sandbox::Probe::Unavailable { reason } => {
                println!("{}: unavailable: {reason}", b.name());
            }
        }
    }
    if !any {
        println!("no backend available (macOS and container backends land in Phase 2)");
        return Ok(ExitCode::from(EXIT_NO_BACKEND));
    }
    Ok(ExitCode::SUCCESS)
}
