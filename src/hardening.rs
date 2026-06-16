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

/// Whether `MURK_STRICT` is enabled. Strict mode trades convenience for a
/// hard "never let a secret touch the disk" guarantee — see [`is_ram_backed`].
///
/// On for `1`, `true`, or `yes` (case-insensitive). Off when unset, empty, or
/// any other value (including `0`). This is the user/session-level strict
/// toggle; vault-declared policy will later flip the same behaviors.
pub fn strict_mode() -> bool {
    strict_from(&std::env::var("MURK_STRICT").unwrap_or_default())
}

/// Parse a `MURK_STRICT` value. Split out from [`strict_mode`] so the truthiness
/// rules are testable without mutating process-global env state.
fn strict_from(val: &str) -> bool {
    matches!(
        val.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Whether `path` lives on a RAM-backed filesystem (tmpfs/ramfs), meaning data
/// written there never hits persistent storage.
///
/// Used to fail closed in strict mode before `murk edit` writes a decrypted
/// secret to a scratch file: a best-effort overwrite-and-unlink can't undo a
/// write to a journaled or copy-on-write disk, and editors leave their own swap
/// files behind, so the only real guarantee is to never write to disk at all.
///
/// On Linux a tmpfs/ramfs mount is identified by its `statfs` magic number. On
/// macOS there is no tmpfs by default, so this returns `false` for the usual
/// `/tmp` — which is the honest answer. On non-Unix targets this returns
/// `false` (assume disk-backed; we can't prove otherwise).
pub fn is_ram_backed(path: &std::path::Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        // TMPFS_MAGIC and RAMFS_MAGIC from <linux/magic.h>.
        const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
        const RAMFS_MAGIC: libc::c_long = 0x858_458f6_u64 as libc::c_long;

        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: zeroed statfs is a valid initial state; statfs writes into it
        // for the duration of the call, and `c_path` outlives the call.
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(c_path.as_ptr(), &raw mut buf) };
        rc == 0 && matches!(buf.f_type as libc::c_long, TMPFS_MAGIC | RAMFS_MAGIC)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: as above; macOS statfs reports the filesystem type by name.
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(c_path.as_ptr(), &raw mut buf) };
        if rc != 0 {
            return false;
        }
        // f_fstypename is a fixed-size [c_char] holding a NUL-terminated name.
        let name: Vec<u8> = buf
            .f_fstypename
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c.cast_unsigned())
            .collect();
        name == b"tmpfs"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = path;
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn disables_core_dumps() {
        disable_core_dumps();

        let mut current = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes into `&mut current` for the duration of
        // the call.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut current) };
        assert_eq!(rc, 0, "getrlimit failed");
        assert_eq!(current.rlim_cur, 0);
        assert_eq!(current.rlim_max, 0);
    }

    #[test]
    fn strict_truthiness() {
        for on in ["1", "true", "yes", "YES", " True ", "Yes"] {
            assert!(strict_from(on), "{on:?} should enable strict mode");
        }
        for off in ["", "0", "false", "no", "off", "enabled", "2"] {
            assert!(!strict_from(off), "{off:?} should not enable strict mode");
        }
    }

    #[test]
    fn nonexistent_path_is_not_ram_backed() {
        // statfs fails on a missing path; we must not report it as RAM-backed.
        assert!(!is_ram_backed(std::path::Path::new(
            "/no/such/murk/path/exists"
        )));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dev_shm_is_ram_backed() {
        let shm = std::path::Path::new("/dev/shm");
        if shm.is_dir() {
            assert!(is_ram_backed(shm), "/dev/shm should be tmpfs");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_tmp_is_not_ram_backed() {
        // macOS has no tmpfs by default; the disk-backed temp dir must read false.
        assert!(!is_ram_backed(&std::env::temp_dir()));
    }
}
