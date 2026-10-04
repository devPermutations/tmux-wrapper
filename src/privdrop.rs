//! Giving up root for good. The helper drops to its unix user and the front
//! to the `run_as` system user; both go through `drop_privileges`, which only
//! reports success once it has checked that root cannot be regained.

use nix::unistd::{Gid, Uid, getgroups, getresgid, getresuid, setgid, setgroups, setuid};
use std::io;

/// `setgroups(groups)` → `setgid(gid)` → `setuid(uid)`, then verify: real,
/// effective and saved ids are the targets (and not root), the supplementary
/// groups are exactly `groups`, no capabilities remain, and `setuid(0)` fails.
/// Any failure is an `Err`; the caller must exit without handling input.
///
/// `setgroups` needs `CAP_SETGID`, so it is skipped when the groups are
/// already right: that makes a call with the current ids and groups a no-op
/// for an unprivileged process (still verified).
pub fn drop_privileges(uid: Uid, gid: Gid, groups: &[Gid]) -> io::Result<()> {
    if uid.is_root() {
        return Err(failed("refusing to drop to uid 0"));
    }
    if !same_groups(&getgroups()?, groups) {
        setgroups(groups)?;
    }
    setgid(gid)?;
    setuid(uid)?;
    verify(uid, gid, groups)
}

fn verify(uid: Uid, gid: Gid, groups: &[Gid]) -> io::Result<()> {
    let u = getresuid()?;
    if [u.real, u.effective, u.saved] != [uid; 3] || u.real.is_root() || u.effective.is_root() {
        return Err(failed(&format!(
            "uids are {}/{}/{} after the drop, expected {uid}",
            u.real, u.effective, u.saved
        )));
    }
    let g = getresgid()?;
    if [g.real, g.effective, g.saved] != [gid; 3] {
        return Err(failed(&format!(
            "gids are {}/{}/{} after the drop, expected {gid}",
            g.real, g.effective, g.saved
        )));
    }
    if !same_groups(&getgroups()?, groups) {
        return Err(failed("supplementary groups were not replaced"));
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    for field in ["CapPrm:", "CapEff:"] {
        if !has_no_capabilities(&status, field) {
            return Err(failed(&format!("{field} is not empty after the drop")));
        }
    }
    if setuid(Uid::from_raw(0)).is_ok() {
        return Err(failed("setuid(0) succeeded after the drop"));
    }
    Ok(())
}

/// Same set of gids, ignoring order and duplicates.
fn same_groups(current: &[Gid], wanted: &[Gid]) -> bool {
    let set = |gs: &[Gid]| {
        let mut v: Vec<u32> = gs.iter().map(|g| g.as_raw()).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    set(current) == set(wanted)
}

/// Whether `field` (e.g. `CapEff:`) in `/proc/self/status` text is all zero.
fn has_no_capabilities(status: &str, field: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .is_some_and(|mask| {
            let mask = mask.trim();
            !mask.is_empty() && mask.bytes().all(|b| b == b'0')
        })
}

fn failed(msg: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("privilege drop: {msg}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::{ForkResult, fork, geteuid, getgid, getuid};

    #[test]
    fn current_ids_and_groups_are_a_no_op_without_root() {
        if geteuid().is_root() {
            eprintln!("skipping: running as root");
            return;
        }
        drop_privileges(getuid(), getgid(), &getgroups().unwrap()).unwrap();
        assert_eq!(getuid(), geteuid());
    }

    #[test]
    fn unprivileged_process_cannot_change_groups_or_user() {
        if geteuid().is_root() {
            eprintln!("skipping: running as root");
            return;
        }
        let groups = getgroups().unwrap();
        if !groups.is_empty() {
            // Can't clear supplementary groups: an error, never a silent Ok.
            assert!(drop_privileges(getuid(), getgid(), &[]).is_err());
        }
        let nobody = Uid::from_raw(65534);
        assert!(drop_privileges(nobody, getgid(), &groups).is_err());
        assert!(drop_privileges(Uid::from_raw(0), getgid(), &groups).is_err());
    }

    #[test]
    fn capability_masks_are_parsed() {
        let status = "Name:\tx\nCapPrm:\t0000000000000000\nCapEff:\t000001ffffffffff\n";
        assert!(has_no_capabilities(status, "CapPrm:"));
        assert!(!has_no_capabilities(status, "CapEff:"));
        assert!(!has_no_capabilities(status, "CapAmb:"));
    }

    /// Exit code of a forked child after `drop_privileges(65534, 65534, &[])`:
    /// 0 when every check passes, otherwise which check failed.
    fn child_checks() -> i32 {
        let nobody = Uid::from_raw(65534);
        if drop_privileges(nobody, Gid::from_raw(65534), &[]).is_err() {
            return 10;
        }
        if getuid() != nobody || geteuid() != nobody {
            return 11;
        }
        if setuid(Uid::from_raw(0)).is_ok() {
            return 12;
        }
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        if !status
            .lines()
            .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["CapEff:", "0000000000000000"])
        {
            return 13;
        }
        0
    }

    #[test]
    #[ignore = "needs root: run `cargo test privdrop:: -- --ignored` as root"]
    fn root_drop_is_permanent() {
        assert!(geteuid().is_root(), "this test must run as root");
        // SAFETY: the child only makes syscalls and small allocations, then
        // leaves with _exit (no atexit handlers, no unwinding into the harness).
        match unsafe { fork() }.unwrap() {
            ForkResult::Child => {
                let code = std::panic::catch_unwind(child_checks).unwrap_or(99);
                unsafe { nix::libc::_exit(code) }
            }
            ForkResult::Parent { child } => {
                assert_eq!(waitpid(child, None).unwrap(), WaitStatus::Exited(child, 0));
            }
        }
    }
}
