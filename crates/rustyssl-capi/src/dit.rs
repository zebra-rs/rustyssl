//! Arm's data-independent timing (`PSTATE.DIT`) around computations on secrets.
//!
//! Without DIT, an Arm core may take operand-dependent time over instructions that constant-time
//! code relies on. Apple's cores do: on an M5, X25519's derivation with a structured private key
//! (0x11 repeated) measured about 10 ns faster in 25 µs than with random keys, a signal DIT
//! removes (`docs/TEST_PLAN.md`, constant-time verification). [`with`] runs a computation with
//! DIT set and puts the caller's DIT back, on cores that have it (`FEAT_DIT`); elsewhere, and
//! under Miri, it only runs the computation. OpenSSL 3.5 doesn't set DIT.

/// Runs `f` with DIT set where the core has it, restoring the caller's setting afterwards (on
/// unwinding too).
pub(crate) fn with<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    let _guard = arm::Guard::set();
    f()
}

#[cfg(all(target_arch = "aarch64", not(miri)))]
mod arm {
    use core::arch::asm;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// `PSTATE.DIT`'s bit in the `DIT` register's value.
    const DIT_BIT: u64 = 1 << 24;

    /// Whether the core has `FEAT_DIT`: 0 unknown, 1 no, 2 yes.
    static AVAILABLE: AtomicU8 = AtomicU8::new(0);

    fn available() -> bool {
        match AVAILABLE.load(Ordering::Relaxed) {
            1 => false,
            2 => true,
            _ => {
                let yes = probe();
                AVAILABLE.store(if yes { 2 } else { 1 }, Ordering::Relaxed);
                yes
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn probe() -> bool {
        let mut value: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>();
        // SAFETY: the name is a C string; the value and its length are locals.
        let ret = unsafe {
            libc::sysctlbyname(
                c"hw.optional.arm.FEAT_DIT".as_ptr(),
                (&raw mut value).cast(),
                &raw mut len,
                core::ptr::null_mut(),
                0,
            )
        };
        ret == 0 && value != 0
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn probe() -> bool {
        // SAFETY: getauxval has no preconditions.
        let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
        hwcap & libc::HWCAP_DIT != 0
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    fn probe() -> bool {
        false
    }

    /// DIT set for its lifetime, the caller's setting restored when it drops.
    pub(super) struct Guard {
        /// The `DIT` register's value before, when this guard set it.
        before: Option<u64>,
    }

    impl Guard {
        pub(super) fn set() -> Self {
            if !available() {
                return Self { before: None };
            }
            let before: u64;
            // SAFETY: reads `DIT` (S3_3_C4_C2_5), which the core has (`FEAT_DIT`); no memory.
            unsafe { asm!("mrs {0}, s3_3_c4_c2_5", out(reg) before, options(nomem, nostack)) };
            if before & DIT_BIT != 0 {
                return Self { before: None };
            }
            // SAFETY: `MSR DIT, #1` (encoded, as assemblers name DIT only for armv8.4-a), on a
            // core with `FEAT_DIT`; it changes only this thread's timing mode.
            unsafe { asm!(".inst 0xd503415f", options(nomem, nostack)) };
            Self {
                before: Some(before),
            }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(before) = self.before {
                // SAFETY: writes back the `DIT` value read in `set`, on the same core feature.
                unsafe { asm!("msr s3_3_c4_c2_5, {0}", in(reg) before, options(nomem, nostack)) };
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn dit() -> u64 {
            let v: u64;
            // SAFETY: as in `Guard::set`, only called where `available()`.
            unsafe { asm!("mrs {0}, s3_3_c4_c2_5", out(reg) v, options(nomem, nostack)) };
            v & DIT_BIT
        }

        #[test]
        fn dit_is_set_inside_and_restored_after() {
            if !available() || dit() != 0 {
                return;
            }
            let outside = dit();
            assert_eq!(super::super::with(dit), DIT_BIT);
            assert_eq!(dit(), outside);
            // A caller that had it set keeps it.
            // SAFETY: as in `Guard::set`.
            unsafe { asm!(".inst 0xd503415f", options(nomem, nostack)) };
            assert_eq!(super::super::with(dit), DIT_BIT);
            assert_eq!(dit(), DIT_BIT);
            // SAFETY: `MSR DIT, #0`, putting back this thread's setting from before the test.
            unsafe { asm!(".inst 0xd503405f", options(nomem, nostack)) };
            assert_eq!(dit(), outside);
        }
    }
}
