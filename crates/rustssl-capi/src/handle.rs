//! Opaque C handles (`SSL_CTX *`, `X509 *`, ...): pointers to reference-counted Rust objects.
//!
//! [`Handle::new_handle`] moves the object into an `Arc` behind a type tag and gives C the
//! pointer. `*_up_ref` adds a reference ([`Handle::up_ref`]), `*_free` drops one
//! ([`Handle::free`]), and the object lives until the last is gone.
//!
//! The object never moves, so pointers to its fields, which OpenSSL's `get0` functions return,
//! stay valid for as long as it lives. C may share a handle between threads, so `Object` is
//! `Send + Sync`, and state that changes after creation needs interior mutability (`Mutex`,
//! `RwLock`, atomics).
//!
//! The tag is defense in depth. A handle of one type passed where another belongs (an `SSL *`
//! for an `SSL_CTX *`, say) is caught and rejected instead of being reinterpreted. A pointer
//! that isn't one of our handles at all is still undefined behavior, as with OpenSSL.

use std::sync::Arc;

/// The allocation behind a handle: the tag first, at a fixed offset for every `T`.
#[repr(C)]
struct Tagged<T> {
    tag: u64,
    object: T,
}

/// A tag derived from the C type's name (FNV-1a), unique per type in practice.
pub(crate) const fn tag(name: &str) -> u64 {
    let mut rest = name.as_bytes();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    while let [byte, tail @ ..] = rest {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
        rest = tail;
    }
    hash
}

/// Ties an opaque C type, such as `rustssl_abi::X509`, to the Rust object its pointers point
/// to. Implement it with [`handle_type!`].
///
/// # Safety
/// `TAG` must differ from every other implementation's.
pub(crate) unsafe trait Handle: Sized {
    type Object: Send + Sync + 'static;
    const TAG: u64;

    /// Moves `object` behind a new handle with one reference.
    fn new_handle(object: Self::Object) -> *mut Self {
        let tagged = Arc::new(Tagged {
            tag: Self::TAG,
            object,
        });
        Arc::into_raw(tagged).cast_mut().cast()
    }

    /// The object behind `handle`, or `None` if it's null or a handle of another type.
    ///
    /// # Safety
    /// `handle` is null or a live handle from [`Handle::new_handle`], of any handle type, that
    /// outlives `'a`.
    unsafe fn get<'a>(handle: *const Self) -> Option<&'a Self::Object> {
        if handle.is_null() {
            return None;
        }
        let tagged = handle.cast::<Tagged<Self::Object>>();
        // SAFETY: every handle starts with its tag (`Tagged` is `repr(C)`), so reading it is
        // valid before we know the type.
        let tag = unsafe { tagged.cast::<u64>().read() };
        if tag != Self::TAG {
            return None;
        }
        // SAFETY: the tag says this is a `Tagged<Self::Object>` inside a live `Arc`.
        Some(unsafe { &(*tagged).object })
    }

    /// Adds a reference, as `*_up_ref` does. Returns `false` for null or a handle of another
    /// type.
    ///
    /// # Safety
    /// As for [`Handle::get`].
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "first used by a `*_up_ref` export")
    )]
    unsafe fn up_ref(handle: *const Self) -> bool {
        // SAFETY: the caller's guarantee is the one `get` needs.
        if unsafe { Self::get(handle) }.is_none() {
            return false;
        }
        // SAFETY: `get` checked that this is a live `Arc<Tagged<Self::Object>>`.
        unsafe { Arc::increment_strong_count(handle.cast::<Tagged<Self::Object>>()) };
        true
    }

    /// Drops a reference, as `*_free` does; the object is dropped with the last one. Null and
    /// handles of another type are left alone.
    ///
    /// # Safety
    /// As for [`Handle::get`]; the caller gives up its reference.
    unsafe fn free(handle: *mut Self) {
        // SAFETY: the caller's guarantee is the one `get` needs.
        if unsafe { Self::get(handle) }.is_none() {
            return;
        }
        // SAFETY: `get` checked that this is a live `Arc<Tagged<Self::Object>>`, and the
        // caller owns one of its references.
        unsafe { Arc::decrement_strong_count(handle.cast::<Tagged<Self::Object>>()) };
    }
}

/// Implements [`Handle`] for an opaque C type: `handle_type!(rustssl_abi::X509 => X509Object);`
macro_rules! handle_type {
    ($c:ty => $object:ty) => {
        // SAFETY: the tag comes from the C type's name, and each C type has one implementation.
        unsafe impl $crate::handle::Handle for $c {
            type Object = $object;
            const TAG: u64 = $crate::handle::tag(stringify!($c));
        }
    };
}
pub(crate) use handle_type;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// Stand-ins for two opaque C types.
    #[repr(C)]
    struct Widget {
        _opaque: [u8; 0],
    }
    #[repr(C)]
    struct Gadget {
        _opaque: [u8; 0],
    }

    struct WidgetObject {
        uses: AtomicU32,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for WidgetObject {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    crate::handle::handle_type!(Widget => WidgetObject);
    crate::handle::handle_type!(Gadget => u64);

    fn widget() -> (*mut Widget, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        let object = WidgetObject {
            uses: AtomicU32::new(0),
            dropped: dropped.clone(),
        };
        (Widget::new_handle(object), dropped)
    }

    #[test]
    fn the_object_lives_until_the_last_reference_is_freed() {
        let (handle, dropped) = widget();
        // SAFETY: `handle` is live throughout, and each `free` gives up one reference.
        unsafe {
            assert!(Widget::up_ref(handle));
        }
        // SAFETY: as above.
        unsafe { Widget::free(handle) };
        assert!(!dropped.load(Ordering::SeqCst));
        // SAFETY: as above; this is the last reference.
        unsafe { Widget::free(handle) };
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn interior_pointers_stay_put() {
        let (handle, _dropped) = widget();
        // SAFETY: `handle` is live until the final `free`.
        let first = unsafe { Widget::get(handle) }.map(|o| &raw const o.uses);
        // SAFETY: as above.
        unsafe { Widget::up_ref(handle) };
        // SAFETY: as above.
        let object = unsafe { Widget::get(handle) }.unwrap();
        object.uses.fetch_add(1, Ordering::SeqCst);
        assert_eq!(first, Some(&raw const object.uses));
        // SAFETY: two references are dropped, the last one freeing the object.
        unsafe {
            Widget::free(handle);
        }
        // SAFETY: as above.
        unsafe { Widget::free(handle) };
    }

    #[test]
    fn null_and_wrong_types_are_rejected() {
        let (handle, dropped) = widget();
        let gadget = handle.cast::<Gadget>();
        // SAFETY: null is allowed; `gadget` is a live handle of another type.
        unsafe {
            assert!(Widget::get(core::ptr::null()).is_none());
        }
        // SAFETY: as above.
        assert!(unsafe { Gadget::get(gadget) }.is_none());
        // SAFETY: as above.
        assert!(!unsafe { Gadget::up_ref(gadget) });
        // SAFETY: as above; freeing through the wrong type must leave the object alone.
        unsafe { Gadget::free(gadget) };
        assert!(!dropped.load(Ordering::SeqCst));
        // SAFETY: `handle` is live and this drops its only reference.
        unsafe { Widget::free(handle) };
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn tags_differ_by_type_name() {
        assert_ne!(Widget::TAG, Gadget::TAG);
        assert_eq!(tag("X509"), tag("X509"));
        assert_ne!(tag("SSL"), tag("SSL_CTX"));
    }

    /// A handle sent to another thread, as C code would.
    struct Shared(*mut Widget);
    // SAFETY: handle objects are `Send + Sync`; the pointer is only a reference to one.
    unsafe impl Send for Shared {}
    impl Shared {
        fn into_inner(self) -> *mut Widget {
            self.0
        }
    }

    #[test]
    fn handles_can_be_shared_between_threads() {
        let (handle, dropped) = widget();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                // SAFETY: each thread takes its own reference before the main thread could
                // drop the original one.
                assert!(unsafe { Widget::up_ref(handle) });
                let shared = Shared(handle);
                std::thread::spawn(move || {
                    let handle = shared.into_inner();
                    // SAFETY: this thread owns one reference to the live handle.
                    let object = unsafe { Widget::get(handle) }.unwrap();
                    object.uses.fetch_add(1, Ordering::SeqCst);
                    // SAFETY: the thread gives up its reference.
                    unsafe { Widget::free(handle) };
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        // SAFETY: the main thread still owns the original reference.
        let uses = unsafe { Widget::get(handle) }
            .unwrap()
            .uses
            .load(Ordering::SeqCst);
        assert_eq!(uses, 8);
        // SAFETY: the last reference.
        unsafe { Widget::free(handle) };
        assert!(dropped.load(Ordering::SeqCst));
    }
}
