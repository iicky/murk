//! Process hardening: best-effort defense-in-depth measures.

/// Disable core dumps for this process.
///
/// Sets `RLIMIT_CORE` to 0 on Unix. A core file written after a crash while
/// murk holds decrypted secret material is the worst possible leak — disabling
/// it up front removes the failure mode regardless of system defaults, which
/// vary across Linux distros, macOS, and BSDs.
///
/// Best-effort: a failed syscall is swallowed rather than blocking the
/// command. Idempotent — a second call on a process that's already at zero is
/// a no-op. On non-Unix targets this is a no-op.
pub fn disable_core_dumps() {
    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads through the pointer for the duration of
        // the call; `limit` lives for that scope. Return code is intentionally
        // ignored — see the doc comment.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &raw const limit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn disables_core_dumps() {
        disable_core_dumps();

        let mut current = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes into `&mut current` for the duration of
        // the call.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut current) };
        assert_eq!(rc, 0, "getrlimit failed");
        assert_eq!(current.rlim_cur, 0);
        assert_eq!(current.rlim_max, 0);
    }
}
