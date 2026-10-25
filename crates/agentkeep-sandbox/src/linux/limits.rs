//! Resource limits: cgroup v2 when this process may create a child cgroup,
//! rlimits otherwise.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rustix::process::{setrlimit, Resource, Rlimit};

use crate::plan::Limits;

/// Where the current process's cgroup v2 directory is, if the unified
/// hierarchy is mounted and the process can write there.
pub fn own_cgroup_dir() -> Option<PathBuf> {
    let cg = fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = cg.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let root = Path::new("/sys/fs/cgroup");
    if !root.join("cgroup.controllers").exists() {
        return None;
    }
    let dir = root.join(rel.trim_start_matches('/'));
    let probe = dir.join("cgroup.procs");
    let writable = fs::OpenOptions::new().append(true).open(&probe).is_ok();
    writable.then_some(dir)
}

/// A child cgroup created for one sandbox. Removed on drop.
#[derive(Debug)]
pub struct Cgroup {
    dir: PathBuf,
}

impl Cgroup {
    /// Try to create `agentkeep-<id>` under our own cgroup and write the
    /// limits. Fails (quietly, for the caller to fall back) when the kernel
    /// or the cgroup delegation does not allow it.
    pub fn create(id: &str, limits: &Limits) -> io::Result<Self> {
        let parent = own_cgroup_dir().ok_or_else(|| io::Error::other("no writable cgroup v2"))?;
        // Controllers must be enabled for children by the parent.
        let wanted = "+memory +pids +cpu";
        fs::write(parent.join("cgroup.subtree_control"), wanted)?;
        let dir = parent.join(format!("agentkeep-{id}"));
        fs::create_dir(&dir)?;
        let cg = Self { dir };
        if let Some(mem) = limits.memory {
            fs::write(cg.dir.join("memory.max"), mem.to_string())?;
            // Disable swap so the limit is the limit.
            let _ = fs::write(cg.dir.join("memory.swap.max"), "0");
        }
        if let Some(pids) = limits.pids {
            fs::write(cg.dir.join("pids.max"), pids.to_string())?;
        }
        if let Some(pct) = limits.cpu_percent {
            let period: u64 = 100_000;
            let quota = period * u64::from(pct) / 100;
            fs::write(cg.dir.join("cpu.max"), format!("{quota} {period}"))?;
        }
        Ok(cg)
    }

    /// Move a process into this cgroup.
    pub fn attach(&self, pid: i32) -> io::Result<()> {
        fs::write(self.dir.join("cgroup.procs"), pid.to_string())
    }

    /// Path, for logs.
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // Processes are gone by now (the pid namespace died with init), so
        // rmdir succeeds; if not, leaving an empty cgroup behind is harmless.
        let _ = fs::remove_dir(&self.dir);
    }
}

/// Apply rlimits inside the sandbox. `memory_via_rlimit` is false when a
/// cgroup already enforces memory, since `RLIMIT_AS` counts address space,
/// not resident memory, and would double-restrict.
pub fn apply_rlimits(limits: &Limits, memory_via_rlimit: bool) -> Vec<String> {
    let mut notes = Vec::new();
    let set = |res: Resource, value: u64, what: &str, notes: &mut Vec<String>| {
        let r = setrlimit(
            res,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        );
        match r {
            Ok(()) => notes.push(format!("rlimit {what}={value}")),
            Err(e) => notes.push(format!("rlimit {what} failed: {e}")),
        }
    };
    // Core dumps could carry secrets into the project directory.
    set(Resource::Core, 0, "core", &mut notes);
    if memory_via_rlimit {
        if let Some(mem) = limits.memory {
            set(Resource::As, mem, "as", &mut notes);
        }
    }
    if let Some(pids) = limits.pids {
        // RLIMIT_NPROC is tracked per user namespace since Linux 5.14, so
        // this counts only processes inside the sandbox.
        set(Resource::Nproc, u64::from(pids), "nproc", &mut notes);
    }
    notes
}
