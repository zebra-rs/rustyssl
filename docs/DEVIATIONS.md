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
| `OPENSSL_atexit(NULL)` | registers it, then crashes calling it at `OPENSSL_cleanup` | returns 0 and registers nothing | `init::tests::a_null_exit_handler_is_refused` |
| `OPENSSL_INIT_set_config_filename`/`_appname` on null settings | dereference null and crash | return 0 | `init::tests::null_settings_are_refused` |
| `CRYPTO_THREAD_*` and `CRYPTO_atomic_*` with a null lock, key, once, or value pointer | pass it to pthreads or dereference it, and crash | return 0 (null for `CRYPTO_THREAD_get_local`) | `threads::tests::null_pointers_fail` |
| `ERR_add_error_txt` with a separator, where a piece between separators doesn't fit in an error's data even when the error is fresh (about 3,990 bytes) | starts new errors forever | splits the piece at the limit | `err::tests::long_text_without_separators_is_split` |
| `OSSL_ERR_STATE_restore` and `OSSL_ERR_STATE_save_to_mark` on the thread's own state (`ERR_get_state()`) | restore chases its own end forever; save-to-mark frees slots it then moves | do nothing | `err::tests::the_threads_own_state_is_left_alone` |
| `ERR_get_state()->top` or `->bottom` set out of range by the application | indexes outside the ring | wrapped into the ring | `err::tests::wild_ring_positions_are_wrapped` |
| `ERR_set_error_data(NULL, flags)`, `ERR_add_error_txt(sep, NULL)` | `strlen(NULL)` crashes | clear the data; do nothing | `err::tests::null_data_and_text_do_nothing` |
| `ERR_load_strings`, `ERR_load_strings_const`, `ERR_unload_strings` with a null table; `ERR_error_string_n` with a null buffer; `ERR_print_errors_cb` with a null callback; `ERR_print_errors_fp` with a null `FILE` | dereference null and crash (the last two once an error is queued) | do nothing (the loaders return 1, as for an empty table), leaving the queue as it was | `err::strings::tests::null_arguments_do_nothing` |
| `OPENSSL_LH_doall`, `OPENSSL_LH_doall_arg`, and `OPENSSL_LH_doall_arg_thunk` on a table without thunks (made with `OPENSSL_LH_new` rather than a typed `lh_TYPE_new`) | calls the missing thunk, a null pointer, and crashes | calls the function directly | `lhash::tests::doall_without_thunks_calls_directly` |
| A `doall` callback that deletes the item after the one it's given | visits the deleted node through freed memory | stops that chain | `lhash::tests::deleting_the_next_item_during_doall_is_safe` |
| `OPENSSL_LH_*` with a null table (insert, delete, retrieve, error, the down load, the statistics), or `doall` with a null function | dereferences null and crashes | returns null or 0, or does nothing | `lhash::tests::doall_without_thunks_calls_directly` |
| `OPENSSL_sk_pop_free` with a null function, `OPENSSL_sk_deep_copy` with a null copy function, `OPENSSL_sk_set_cmp_func` on a null stack | calls or dereferences null and crashes | frees only the stack; returns null; returns null | `stack::tests::null_callbacks_are_refused` |
| `CRYPTO_*_ex_data` with a null `CRYPTO_EX_DATA`; `CRYPTO_alloc_ex_data` for an index that doesn't exist | dereference null and crash | return 0 or null, or do nothing | `ex_data::tests::null_data_and_missing_indexes_fail` |
| The string and hex helpers (`OPENSSL_strnlen`, `OPENSSL_strlcpy`, `OPENSSL_strlcat`, `OPENSSL_hexstr2buf(_ex)`, `OPENSSL_buf2hexstr(_ex)`) with a null string or buffer | dereference null and crash | count it as empty, or fail | `string::tests::nulls_are_refused` |
| `OPENSSL_DIR_end` | frees the context and leaves `*ctx` pointing at it, so a second call frees it again | sets `*ctx` to null; a second call returns 0 with `EINVAL` | `dir::tests::ending_clears_the_context` |
| The BIO accessors (`BIO_set_data`, `BIO_get_init`, `BIO_set_flags`, `BIO_method_name`, `BIO_set_ex_data`, ...) with a null BIO; `BIO_new` with a null method; `BIO_new_file` with a null name or mode | dereference null and crash | read as 0 or null, or do nothing | `bio::tests::null_bios_are_ignored` |
| `BIO_meth_free` and `BIO_meth_set_*` on a built-in method (`BIO_s_mem()`, ...) | write to read-only data and crash | `BIO_meth_free` ignores it; the setters return 0 | `bio::tests::builtin_methods_cant_be_changed_or_freed` |
| `BIO_indent` with a negative limit | loops about 2^31 times, writing a space each time | writes nothing and returns 1 | `bio::tests::a_negative_indent_limit_writes_nothing` |
| `BIO_set_mem_buf(b, NULL, ...)` | frees the old buffer, then dereferences null | returns 0, keeping the old buffer | `bio::tests::a_negative_indent_limit_writes_nothing` |
| A `FILE` BIO with no `FILE` yet: `BIO_eof`, `BIO_tell`, `BIO_seek`, `BIO_gets` | pass null to stdio and crash | return 0 (`BIO_eof`, `BIO_gets`) or -1 | `bio::tests::a_file_bio_without_a_file_fails` |
| `OpenSSL_version(OPENSSL_VERSION)`, `OPENSSL_FULL_VERSION_STRING`, `OPENSSL_version_build_metadata` | no build metadata: `OpenSSL 3.5.9 29 Sep 2026` | build metadata `+rustssl.<version>`: `OpenSSL 3.5.9+rustssl.0.1.0 29 Sep 2026` | `version::tests::version_text_names_rustssl_in_the_build_metadata` |

## Notes

- **The version text.** This is the one entry not about memory safety: it's about knowing what
  runs. A vulnerability scanner or an administrator reading `OpenSSL 3.5.9` would apply
  OpenSSL's advisories to rustssl and miss rustssl's own. The version numbers
  (`OpenSSL_version_num`, `OPENSSL_version_major`/`_minor`/`_patch`,
  `OPENSSL_VERSION_STRING`) are untouched, so version checks pass. The name goes where
  OpenSSL's man page reserves room "for other parties, such as `+fips`, or `+vendor.1`".
  Parsers that read `OpenSSL x.y.z` from the text still do. The other build information
  (directories, compiler, build date, CPU capabilities) describes rustssl's build, as a
  differently configured OpenSSL's would describe its own; it isn't a deviation.

- **`CRYPTO_aligned_alloc`.** On Linux both libraries use `posix_memalign`, which checks the
  size itself, so only macOS (and other builds without it) differs. The rest of the
  macOS rounding is kept, quirks included: alignment 0 returns null with `*freeptr` set, as
  OpenSSL's does. That's allowed because the alignment must be a power of two.
- **Reentrant allocators.** An application can't normally hit this. It takes a malloc
  function that wraps `CRYPTO_malloc`, which OpenSSL can't run either, or `CRYPTO_malloc`
  itself reached through a different address (a non-PIE executable's PLT entry, say).
- **`ERR_add_error_txt`.** Its text often comes from outside, such as a peer's or a
  configuration file's, so OpenSSL's endless loop can be a denial of service. Where OpenSSL
  returns, rustssl splits the text exactly as it does, separator quirks included (the
  differential probe compares them). The probe's random text never contains a piece that
  long, because the reference would hang.
