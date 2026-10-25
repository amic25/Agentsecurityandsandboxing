//! Building the private root filesystem.
//!
//! Runs inside the new mount namespace as PID 1 of the new pid namespace,
//! before any user code. The strategy is bubblewrap's: a tmpfs becomes the
//! new root, host paths are bind-mounted into it one by one, then
//! `pivot_root` swaps it in and the old root is detached so nothing outside
//! the plan is reachable by any path.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::plan::{LaunchPlan, Mount, MountMode};

use super::sys;

/// Default tmpfs sizes (bytes) when the plan does not say.
const HOME_TMPFS_SIZE: u64 = 512 << 20;
const TMP_TMPFS_SIZE: u64 = 2 << 30;
const SMALL_TMPFS_SIZE: u64 = 64 << 20;

fn step<T>(what: &str, r: io::Result<T>) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

fn rel(base: &Path, target: &Path) -> PathBuf {
    base.join(target.strip_prefix("/").unwrap_or(target))
}

fn mkdir_p(p: &Path) -> Result<(), String> {
    step(&format!("mkdir {}", p.display()), fs::create_dir_all(p))
}

fn touch(p: &Path) -> Result<(), String> {
    if let Some(parent) = p.parent() {
        mkdir_p(parent)?;
    }
    if !p.exists() {
        step(
            &format!("create {}", p.display()),
            fs::File::create(p).map(drop),
        )?;
    }
    Ok(())
}

fn tmpfs(target: &Path, flags: libc::c_ulong, opts: &str) -> Result<(), String> {
    mkdir_p(target)?;
    step(
        &format!("mount tmpfs on {}", target.display()),
        sys::mount(
            Some(Path::new("tmpfs")),
            target,
            Some("tmpfs"),
            flags,
            Some(opts),
        ),
    )
}

/// Bind `source` at `target` (which must already exist with the right type)
/// and remount it with `extra` flags plus whatever the source had locked.
fn bind(source: &Path, target: &Path, extra: libc::c_ulong) -> Result<(), String> {
    step(
        &format!("bind {} -> {}", source.display(), target.display()),
        sys::mount(
            Some(source),
            target,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        ),
    )?;
    let locked = step(
        &format!("statfs {}", target.display()),
        sys::locked_mount_flags(target),
    )?;
    step(
        &format!("remount {}", target.display()),
        sys::mount(
            None,
            target,
            None,
            libc::MS_REMOUNT | libc::MS_BIND | locked | extra | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        ),
    )
}

/// Prepare the target for a bind of `source`: a directory for a directory,
/// an empty file for anything else. Returns false if the source is missing.
fn prepare_target(source: &Path, target: &Path) -> Result<bool, String> {
    let Ok(meta) = fs::metadata(source) else {
        return Ok(false);
    };
    if meta.is_dir() {
        mkdir_p(target)?;
    } else {
        touch(target)?;
    }
    Ok(true)
}

/// Mounts that the plan lists, applied in depth order with hidden overlays
/// last so they cover whatever the binds exposed.
fn planned_mounts(
    plan: &LaunchPlan,
    base: &Path,
    empty_file: &Path,
) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    let mut mounts: Vec<&Mount> = plan.mounts.iter().collect();
    mounts.sort_by_key(|m| (m.mode == MountMode::Hidden, m.target.components().count()));
    for m in mounts {
        let target = rel(base, &m.target);
        match m.mode {
            MountMode::ReadOnly | MountMode::ReadWrite => {
                if !prepare_target(&m.source, &target)? {
                    notes.push(format!(
                        "skipped {}: not present on host",
                        m.source.display()
                    ));
                    continue;
                }
                let ro = if m.mode == MountMode::ReadOnly {
                    libc::MS_RDONLY
                } else {
                    0
                };
                bind(&m.source, &target, ro)?;
            }
            MountMode::Tmpfs => {
                let is_home = m.target == plan.home;
                let world = m.target == Path::new("/tmp")
                    || m.target == Path::new("/var/tmp")
                    || m.target == Path::new("/dev/shm");
                let size = m.size.unwrap_or(if is_home {
                    HOME_TMPFS_SIZE
                } else if world {
                    TMP_TMPFS_SIZE
                } else {
                    SMALL_TMPFS_SIZE
                });
                let opts = if is_home {
                    format!(
                        "mode=0700,uid={},gid={},size={size}",
                        plan.inner_uid, plan.inner_gid
                    )
                } else if world {
                    format!("mode=1777,size={size}")
                } else {
                    format!(
                        "mode=0755,uid={},gid={},size={size}",
                        plan.inner_uid, plan.inner_gid
                    )
                };
                tmpfs(&target, libc::MS_NOSUID | libc::MS_NODEV, &opts)?;
            }
            MountMode::Hidden => {
                let Ok(meta) = fs::symlink_metadata(&target) else {
                    continue;
                };
                if meta.is_dir() {
                    tmpfs(
                        &target,
                        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                        "mode=0555,size=4096",
                    )?;
                    step(
                        &format!("remount hidden {}", target.display()),
                        sys::mount(
                            None,
                            &target,
                            None,
                            libc::MS_REMOUNT
                                | libc::MS_BIND
                                | libc::MS_RDONLY
                                | libc::MS_NOSUID
                                | libc::MS_NODEV
                                | libc::MS_NOEXEC,
                            None,
                        ),
                    )?;
                } else {
                    bind(empty_file, &target, libc::MS_RDONLY | libc::MS_NOEXEC)?;
                }
                notes.push(format!("hidden {}", m.target.display()));
            }
        }
    }
    Ok(notes)
}

/// `/dev` with the handful of nodes every program needs and nothing that
/// reaches hardware.
fn setup_dev(base: &Path) -> Result<(), String> {
    let dev = base.join("dev");
    tmpfs(
        &dev,
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755,size=1048576",
    )?;
    for node in ["null", "zero", "full", "random", "urandom", "tty"] {
        let src = Path::new("/dev").join(node);
        let dst = dev.join(node);
        if src.exists() {
            touch(&dst)?;
            // Device nodes need MS_NODEV absent, so this is a plain bind.
            step(
                &format!("bind /dev/{node}"),
                sys::mount(Some(&src), &dst, None, libc::MS_BIND, None),
            )?;
        }
    }
    let pts = dev.join("pts");
    mkdir_p(&pts)?;
    let devpts = sys::mount(
        Some(Path::new("devpts")),
        &pts,
        Some("devpts"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    );
    if devpts.is_ok() {
        step(
            "symlink /dev/ptmx",
            std::os::unix::fs::symlink("pts/ptmx", dev.join("ptmx")),
        )?;
    } else {
        // Older kernels: share the host's pty instance read-write.
        step(
            "bind /dev/pts",
            sys::mount(
                Some(Path::new("/dev/pts")),
                &pts,
                None,
                libc::MS_BIND | libc::MS_REC,
                None,
            ),
        )?;
        touch(&dev.join("ptmx"))?;
        step(
            "bind /dev/ptmx",
            sys::mount(
                Some(Path::new("/dev/ptmx")),
                &dev.join("ptmx"),
                None,
                libc::MS_BIND,
                None,
            ),
        )?;
    }
    tmpfs(
        &dev.join("shm"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=1777,size=67108864",
    )?;
    for (link, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        step(
            &format!("symlink /dev/{link}"),
            std::os::unix::fs::symlink(target, dev.join(link)),
        )?;
    }
    Ok(())
}

/// The agentkeep binary and command shims at `/run/agentkeep`, plus the
/// approval socket if the supervisor opened one.
fn setup_shims(plan: &LaunchPlan, base: &Path) -> Result<(), String> {
    let Some(shim) = &plan.shim else {
        return Ok(());
    };
    let ak_dir = rel(base, shim.dir.parent().unwrap_or(&shim.dir));
    mkdir_p(&ak_dir)?;
    let exe = ak_dir.join("agentkeep");
    touch(&exe)?;
    bind(&plan.self_exe, &exe, libc::MS_RDONLY)?;
    let bin = rel(base, &shim.dir);
    mkdir_p(&bin)?;
    for cmd in &shim.commands {
        if cmd.contains('/') || cmd.is_empty() {
            continue;
        }
        step(
            &format!("shim {cmd}"),
            std::os::unix::fs::symlink("../agentkeep", bin.join(cmd)),
        )?;
    }
    if let Some(host_sock) = &plan.approval_socket {
        let target = rel(base, &shim.socket);
        touch(&target)?;
        step(
            "bind approval socket",
            sys::mount(Some(host_sock), &target, None, libc::MS_BIND, None),
        )?;
    }
    Ok(())
}

/// A minimal `/etc/passwd` and `/etc/group` so `getpwuid` resolves the inner
/// uid. Many tools (git, ssh clients, shells) misbehave without one.
fn setup_identity(plan: &LaunchPlan, base: &Path) -> Result<(), String> {
    let etc = rel(base, Path::new("/etc"));
    if !etc.is_dir() {
        return Ok(());
    }
    let staging = base.join("run/agentkeep/etc");
    mkdir_p(&staging)?;
    let passwd = format!(
        "root:x:0:0:root:/root:/bin/sh\n{name}:x:{uid}:{gid}:agentkeep user:{home}:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
        name = plan.user_name,
        uid = plan.inner_uid,
        gid = plan.inner_gid,
        home = plan.home.display()
    );
    let group = format!(
        "root:x:0:\n{name}:x:{gid}:\nnogroup:x:65534:\n",
        name = plan.user_name,
        gid = plan.inner_gid
    );
    for (file, content) in [("passwd", passwd), ("group", group)] {
        let src = staging.join(file);
        step(&format!("write {file}"), fs::write(&src, content))?;
        let dst = etc.join(file);
        if dst.exists() {
            bind(&src, &dst, libc::MS_RDONLY)?;
        }
    }
    Ok(())
}

/// Build the root and pivot into it. On return the process sees only the
/// planned tree. Returns informational notes for the audit log.
pub fn build_root(plan: &LaunchPlan) -> Result<Vec<String>, String> {
    let base = &plan.root_base;
    step("statfs base", fs::metadata(base).map(drop))?;

    // Stop mount events propagating back to the host, then make the base a
    // fresh tmpfs that will become `/`.
    step(
        "make / rslave",
        sys::mount(
            None,
            Path::new("/"),
            None,
            libc::MS_SLAVE | libc::MS_REC,
            None,
        ),
    )?;
    tmpfs(
        base,
        libc::MS_NOSUID | libc::MS_NODEV,
        "mode=0755,size=16777216",
    )?;

    let empty_file = base.join("run/agentkeep/empty");
    touch(&empty_file)?;

    let mut notes = planned_mounts(plan, base, &empty_file)?;

    // /run holds the shim binary and the approval socket; it is created
    // before planned mounts would need it because planned mounts never
    // target /run.
    let run = base.join("run");
    if !run.join("agentkeep").exists() {
        mkdir_p(&run.join("agentkeep"))?;
    }
    mkdir_p(&run.join(format!("user/{}", plan.inner_uid)))?;
    setup_shims(plan, base)?;
    setup_identity(plan, base)?;
    setup_dev(base)?;

    // We are PID 1 of the new pid namespace, so this procfs shows only the
    // sandbox. hidepid=2 hides other users' processes as a second layer.
    let proc = base.join("proc");
    mkdir_p(&proc)?;
    step(
        "mount /proc",
        sys::mount(
            Some(Path::new("proc")),
            &proc,
            Some("proc"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some("hidepid=2"),
        ),
    )?;
    let sys_dir = base.join("sys");
    mkdir_p(&sys_dir)?;
    if sys::mount(
        Some(Path::new("sysfs")),
        &sys_dir,
        Some("sysfs"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
    .is_err()
    {
        notes.push("sysfs not mounted (kernel refused); /sys is empty".into());
    }

    // Swap roots. pivot_root(".", ".") stacks the old root under the new one
    // at the same path; detaching "." then drops the old root entirely.
    step("chdir base", std::env::set_current_dir(base))?;
    step(
        "pivot_root",
        sys::pivot_root(Path::new("."), Path::new(".")),
    )?;
    step(
        "detach old root",
        sys::umount2(Path::new("."), libc::MNT_DETACH),
    )?;
    step("chdir /", std::env::set_current_dir("/"))?;

    // Nothing may create new top-level entries.
    step(
        "remount / read-only",
        sys::mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        ),
    )?;
    Ok(notes)
}
