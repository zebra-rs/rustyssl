//! What an export does before it's implemented.

/// Called by the generated stub of every export that isn't implemented yet: reports the
/// function on stderr and aborts the process.
///
/// Returning an error instead isn't safe without knowing each function's conventions. A stub
/// `CRYPTO_memcmp` returning 0 would say two buffers are equal, `SSL_get_verify_result`
/// returning 0 means `X509_V_OK`, and `AES_set_encrypt_key` returns 0 on success.
#[cold]
pub(crate) fn unimplemented(name: &str) -> ! {
    use std::io::Write as _;
    // Nothing useful can be done if stderr is closed; the process aborts either way.
    let _ = writeln!(
        std::io::stderr(),
        "rustssl: {name} is not implemented yet; aborting"
    );
    std::process::abort()
}
