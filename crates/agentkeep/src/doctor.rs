//! `agentkeep doctor`: which backends work here and what each can enforce.

use std::process::ExitCode;

use anyhow::Result;

/// Exit code when no sandbox backend is available.
pub const EXIT_NO_BACKEND: u8 = 3;

/// `agentkeep doctor`: probe every compiled-in backend.
pub fn run(json: bool) -> Result<ExitCode> {
    let mut any = false;
    let mut report = Vec::new();
    for b in agentkeep_sandbox::backends() {
        let probe = b.probe();
        any |= probe.available();
        report.push(serde_json::json!({
            "name": b.name(),
            "available": probe.available(),
            "reason": match &probe {
                agentkeep_sandbox::Probe::Unavailable { reason } => Some(reason.clone()),
                agentkeep_sandbox::Probe::Available { .. } => None,
            },
            "capabilities": probe.capabilities(),
            "controls": probe.capabilities().map(agentkeep_sandbox::Capabilities::controls).unwrap_or_default(),
            "degradations": probe.degradations(),
        }));
        if json {
            continue;
        }
        match &probe {
            agentkeep_sandbox::Probe::Available {
                capabilities,
                degradations,
            } => {
                println!("{}: available", b.name());
                println!("  controls: {}", capabilities.controls().join(", "));
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
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "backends": report }))?
        );
    } else if !any {
        println!("no sandbox backend is available on this host");
    }
    Ok(if any {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_NO_BACKEND)
    })
}
