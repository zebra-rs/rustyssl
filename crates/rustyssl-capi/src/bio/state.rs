//! The private state of a built-in BIO type that OpenSSL keeps in C behind the BIO's `ptr`.
//! Here it's Rust: an `Arc<Mutex<T>>` in a typed slot of the BIO object, which is downcast to
//! the type that asks for it. The `ptr` is set to the state's address, as OpenSSL sets it to
//! its context, but only as a marker: nothing here reads through it, so an application that
//! changes it with `BIO_set_data` can't make the state be misread.
//!
//! A method that calls out (to the next BIO, whose callbacks may free this one) clones the
//! `Arc` first, so the state outlives the call, and holds the lock only between calls, never
//! across one (AGENTS.md, security rule 7). A callback that re-enters the BIO sees the state as
//! the interrupted call left it.
//!
//! A method assembled from a built-in type's functions with another create function finds no
//! state of that type, and its functions do nothing.

use core::any::Any;
use core::ptr;
use core::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::Bio;

/// A BIO's slot for its type's state.
#[derive(Default)]
pub(crate) struct Slot(Mutex<Option<Arc<dyn Any + Send + Sync>>>);

/// Gives `bio` its state.
pub(crate) fn install<T: Send + 'static>(bio: &Bio, state: T) {
    let state = Arc::new(Mutex::new(state));
    bio.ptr
        .store(Arc::as_ptr(&state).cast_mut().cast(), Ordering::Relaxed);
    *lock(&bio.state.0) = Some(state);
}

/// The state of `bio`, if it has one of type `T`.
pub(crate) fn get<T: Send + 'static>(bio: &Bio) -> Option<Arc<Mutex<T>>> {
    let state = lock(&bio.state.0).clone()?;
    state.downcast::<Mutex<T>>().ok()
}

/// Takes the state out of `bio`, if it has one of type `T`, clearing its `ptr`.
pub(crate) fn remove<T: Send + 'static>(bio: &Bio) -> Option<Arc<Mutex<T>>> {
    let mut slot = lock(&bio.state.0);
    if !slot.as_ref().is_some_and(|s| s.is::<Mutex<T>>()) {
        return None;
    }
    let state = slot.take()?;
    drop(slot);
    bio.ptr.store(ptr::null_mut(), Ordering::Relaxed);
    state.downcast::<Mutex<T>>().ok()
}

/// Locks state, ignoring poisoning: a panic inside left it consistent enough to keep going,
/// and was already reported as an internal error.
pub(crate) fn lock<T: ?Sized>(state: &Mutex<T>) -> MutexGuard<'_, T> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A zeroed buffer of `len` bytes, or `None` if it can't be allocated (OpenSSL's allocation
/// failures, without aborting).
pub(crate) fn zeroed(len: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).ok()?;
    bytes.resize(len, 0);
    Some(bytes)
}
