//! Data-independent timing around computations on secrets.
//!
//! Some cores take operand-dependent time over instructions that constant-time code relies on
//! unless a timing mode is set: Arm's `PSTATE.DIT` (an Apple M5 ran X25519 about 10 ns faster
//! in 25 µs for a structured private key without it; `docs/TEST_PLAN.md`, constant-time
//! verification). Setting it takes an instruction this crate can't contain
//! (`#![forbid(unsafe_code)]`), so the embedder installs [`Hooks`] and every operation on
//! secrets runs inside [`with`]: an asymmetric private operation, a cipher, AEAD or MAC call, a
//! KDF, a constant-time modular exponentiation or inversion. Without hooks (this crate's own
//! tests, a core without the mode) [`with`] only runs the computation.
//!
//! [`with`] goes around whole operations, never around single blocks: setting and restoring
//! the mode costs about 18 ns on an M5, several AES blocks' worth. Nested calls cost a read of
//! the mode (the inner one finds it set and leaves it).

use std::sync::OnceLock;

/// How the embedder sets the timing mode and puts it back.
pub struct Hooks {
    /// Sets the mode; true if it wasn't set before (so [`Hooks::leave`] must clear it).
    pub enter: fn() -> bool,
    /// Clears the mode that [`Hooks::enter`] set.
    pub leave: fn(),
}

static HOOKS: OnceLock<&'static Hooks> = OnceLock::new();

/// Installs the embedder's hooks; later calls change nothing.
pub fn install(hooks: &'static Hooks) {
    let _ = HOOKS.set(hooks);
}

/// Whether hooks are installed.
#[must_use]
pub fn installed() -> bool {
    HOOKS.get().is_some()
}

/// Runs `f` with the timing mode set, putting back the caller's setting afterwards, on
/// unwinding too.
pub fn with<T>(f: impl FnOnce() -> T) -> T {
    let _guard = HOOKS.get().map(|h| Guard {
        hooks: h,
        set: (h.enter)(),
    });
    f()
}

/// The mode set for its lifetime by [`with`].
struct Guard {
    hooks: &'static Hooks,
    /// Whether this guard set it (else the caller had it already).
    set: bool,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.set {
            (self.hooks.leave)();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static MODE: Cell<bool> = const { Cell::new(false) };
        static CALLS: Cell<u32> = const { Cell::new(0) };
    }

    fn enter() -> bool {
        CALLS.with(|c| c.set(c.get().saturating_add(1)));
        MODE.with(|m| !m.replace(true))
    }

    fn leave() {
        MODE.with(|m| m.set(false));
    }

    static TEST_HOOKS: Hooks = Hooks { enter, leave };

    #[test]
    fn with_sets_the_mode_and_puts_it_back() {
        install(&TEST_HOOKS);
        assert!(installed());
        assert!(!MODE.with(Cell::get));
        assert!(with(|| MODE.with(Cell::get)));
        assert!(!MODE.with(Cell::get));
        // Nested: the inner call finds it set and leaves it to the outer.
        assert!(with(
            || with(|| MODE.with(Cell::get)) && MODE.with(Cell::get)
        ));
        assert!(!MODE.with(Cell::get));
        // A caller that had it set keeps it.
        MODE.with(|m| m.set(true));
        assert!(with(|| MODE.with(Cell::get)));
        assert!(MODE.with(Cell::get));
        MODE.with(|m| m.set(false));
        // Unwinding puts it back.
        let r = std::panic::catch_unwind(|| with(|| panic!("inside")));
        assert!(r.is_err());
        assert!(!MODE.with(Cell::get));
        assert!(CALLS.with(Cell::get) >= 5);
    }
}
