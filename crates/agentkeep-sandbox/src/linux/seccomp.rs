//! The syscall deny-list (threat model C5, F5, F6, C6).
//!
//! Everything is allowed except syscalls that only matter for escaping or
//! attacking the kernel. Denied calls fail with `EPERM` so programs see an
//! ordinary error; `clone3` fails with `ENOSYS` so libc falls back to
//! `clone`, where the namespace flags can be inspected.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

/// Syscalls refused outright.
const DENY: &[i64] = &[
    // Debugging and memory access to other processes (F5).
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_pidfd_getfd,
    // Mount manipulation (F6).
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    libc::SYS_chroot,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    // Namespaces (C6); clone/unshare are handled by flag below.
    libc::SYS_setns,
    // Kernel attack surface (C5).
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_fanotify_init,
    libc::SYS_lookup_dcookie,
    libc::SYS_nfsservctl,
    libc::SYS_acct,
    libc::SYS_quotactl,
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_vhangup,
];

/// Namespace flags that must never appear in `clone` or `unshare`.
const NAMESPACE_FLAGS: &[u64] = &[
    libc::CLONE_NEWUSER as u64,
    libc::CLONE_NEWNS as u64,
    libc::CLONE_NEWPID as u64,
    libc::CLONE_NEWNET as u64,
    libc::CLONE_NEWIPC as u64,
    libc::CLONE_NEWUTS as u64,
    libc::CLONE_NEWCGROUP as u64,
    0x80, // CLONE_NEWTIME
];

fn flag_rules() -> Result<Vec<SeccompRule>, String> {
    NAMESPACE_FLAGS
        .iter()
        .map(|&flag| {
            let cond = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )
            .map_err(|e| e.to_string())?;
            SeccompRule::new(vec![cond]).map_err(|e| e.to_string())
        })
        .collect()
}

/// Build the two BPF programs: the EPERM deny-list and the ENOSYS one for
/// `clone3`.
pub fn programs() -> Result<Vec<BpfProgram>, String> {
    let mut deny: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in DENY {
        deny.insert(nr, vec![]);
    }
    deny.insert(libc::SYS_unshare, flag_rules()?);
    deny.insert(libc::SYS_clone, flag_rules()?);
    let eperm = SeccompFilter::new(
        deny,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        ARCH,
    )
    .map_err(|e| e.to_string())?;

    let mut enosys: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    enosys.insert(libc::SYS_clone3, vec![]);
    let clone3 = SeccompFilter::new(
        enosys,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        ARCH,
    )
    .map_err(|e| e.to_string())?;

    let a: BpfProgram = eperm
        .try_into()
        .map_err(|e: seccompiler::BackendError| e.to_string())?;
    let b: BpfProgram = clone3
        .try_into()
        .map_err(|e: seccompiler::BackendError| e.to_string())?;
    Ok(vec![a, b])
}

/// Install the filters on the current thread (inherited by children and
/// across exec). Requires `no_new_privs`.
pub fn apply() -> Result<(), String> {
    for prog in programs()? {
        seccompiler::apply_filter(&prog).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn filters_compile() {
        let progs = super::programs().unwrap();
        assert_eq!(progs.len(), 2);
        assert!(progs[0].len() > super::DENY.len());
    }
}
