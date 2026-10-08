# Deviations from OpenSSL

rustssl matches OpenSSL's behavior, including its quirks (AGENTS.md, "Compatibility target"),
with one exception: where matching it would be unsafe. Every such case is listed here, with
the reason and the test that pins the behavior down. Each entry names the OpenSSL release it was
checked against.

Most entries cover inputs where OpenSSL corrupts memory or crashes. A program that works with
OpenSSL never depends on them.

| Function | OpenSSL 3.5 | rustssl | Test |
|---|---|---|---|
| `CRYPTO_aligned_alloc` on macOS | adds `num + alignment` without checking, so a huge `num` wraps and gets a block smaller than requested | fails with null and `*freeptr` null | `mem::tests::aligned_allocations` |
| `CRYPTO_secure_used`, `CRYPTO_secure_actual_size` | without a secure heap, lock a null lock and crash | return 0 | `tests/no_secure_heap.rs` |
| `OPENSSL_cleanse(NULL, n)` | writes to null and crashes | does nothing | `mem::tests::cleanse_null_does_nothing` |
| `CRYPTO_memcmp` with a null pointer and `len > 0` | reads from null and crashes | returns 1, unequal: fails closed | `mem::tests::memcmp_returns_zero_or_one` |
| An allocator from `CRYPTO_set_mem_functions` that calls `CRYPTO_malloc` | recurses until the stack overflows | the nested call takes the default allocator | `tests/reentrant_allocator.rs` |

## Notes

- **`CRYPTO_aligned_alloc`.** On Linux both libraries use `posix_memalign`, which checks the
  size itself, so only macOS (and other builds without it) differs. The rest of the
  macOS rounding is kept, quirks included: alignment 0 returns null with `*freeptr` set, as
  OpenSSL's does. That's allowed because the alignment must be a power of two.
- **Reentrant allocators.** An application can't normally hit this. It takes a malloc
  function that wraps `CRYPTO_malloc`, which OpenSSL can't run either, or `CRYPTO_malloc`
  itself reached through a different address (a non-PIE executable's PLT entry, say).
