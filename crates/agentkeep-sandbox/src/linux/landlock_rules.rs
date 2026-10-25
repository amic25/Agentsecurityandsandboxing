//! Landlock as a second layer under the mount namespace.
//!
//! The mount tree already decides what exists. Landlock additionally pins
//! *write* access to the few trees that are meant to be writable, so a
//! mistake in the mount plan cannot silently widen the sandbox.

use std::path::{Path, PathBuf};

use landlock::{
    path_beneath_rules, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};

use crate::plan::{LaunchPlan, MountMode};

/// Highest ABI we know how to use. Best-effort compatibility downgrades on
/// older kernels.
const TARGET_ABI: ABI = ABI::V5;

/// The Landlock ABI supported by the running kernel, 0 when absent.
pub fn kernel_abi() -> u32 {
    super::sys::landlock_abi()
}

/// Paths that stay writable under Landlock. Everything else visible is
/// read-only, including anything an unexpected bind might have exposed.
pub fn writable_paths(plan: &LaunchPlan) -> Vec<PathBuf> {
    let mut out = vec![
        plan.project.clone(),
        plan.home.clone(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/dev"),
        PathBuf::from("/proc"),
        PathBuf::from(format!("/run/user/{}", plan.inner_uid)),
    ];
    for m in &plan.mounts {
        if matches!(m.mode, MountMode::ReadWrite | MountMode::Tmpfs) && !out.contains(&m.target) {
            out.push(m.target.clone());
        }
    }
    out
}

/// Apply the ruleset to the current process. Returns a note when the
/// kernel enforced it only partially or not at all.
pub fn apply(plan: &LaunchPlan) -> Result<Option<String>, String> {
    let abi = TARGET_ABI;
    let writable = writable_paths(plan);
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| e.to_string())?
        .create()
        .map_err(|e| e.to_string())?
        .add_rules(path_beneath_rules(
            [Path::new("/")],
            AccessFs::from_read(abi),
        ))
        .map_err(|e| e.to_string())?
        .add_rules(path_beneath_rules(
            writable.iter().map(PathBuf::as_path),
            AccessFs::from_all(abi),
        ))
        .map_err(|e| e.to_string())?
        .restrict_self()
        .map_err(|e| e.to_string())?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => None,
        RulesetStatus::PartiallyEnforced => {
            Some("landlock: partially enforced (older kernel ABI)".to_string())
        }
        RulesetStatus::NotEnforced => Some("landlock: not enforced by this kernel".to_string()),
    })
}
