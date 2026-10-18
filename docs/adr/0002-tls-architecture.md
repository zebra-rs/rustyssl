# ADR 0002: The TLS stack: a sans-IO core that yields at every observable event

- **Status:** Accepted, 2026-10-18 (implementation plan step 7.1)

## Context

libssl is about 65,000 lines of C (`ssl/`, without QUIC). Applications observe much more of it than
its wire behavior:

- **Callbacks run in the middle of a handshake** and may call any API on the same `SSL`: the
  servername callback calls `SSL_set_SSL_CTX`, the verify callback reads `SSL_get_ex_data`, the
  client hello callback reads the raw extensions, the info callback reads `SSL_get_state()`. A
  callback may also suspend the handshake (`SSL_ERROR_WANT_X509_LOOKUP`, `WANT_CLIENT_HELLO_CB`,
  `WANT_RETRY_VERIFY`) and be called again when the application retries.
- **State is visible at each callback:** `SSL_get_state`, `SSL_state_string_long`, the info
  callback's `where` and `ret`, the message callback's bytes in order.
- **Crypto goes through providers.** libssl fetches every algorithm from the `SSL_CTX`'s library
  context and property query, and learns groups and signature algorithms (`TLS-GROUP`,
  `TLS-SIGALG`) from the providers' capabilities, so a third-party provider can add a group.
- **Certificates and keys are libcrypto objects** (`X509`, `EVP_PKEY`, `X509_STORE`), and
  verification is `X509_verify_cert` with the application's callbacks.

Security rule 7 forbids holding a lock while a C callback runs, and the core crates are safe Rust
with no knowledge of C.

## Decision

1. **`rustyssl-tls` is a sans-IO, crypto-agnostic core.** It owns the record layer, the message
   and extension codecs, the cipher-suite table, the cipher-string parser, the key schedules,
   and the client and server state machines (TLS 1.0–1.3; DTLS later). It does no I/O and never
   calls C.

2. **Crypto is a trait the caller supplies** (`rustyssl_tls::crypto::Provider`): hashing,
   HMAC, AEAD and CBC record protection, key shares (DH, ECDH, X25519/X448, ML-KEM and the
   hybrids, by group), signing with a key handle, verifying with a peer certificate, and
   randomness. HKDF and the TLS 1.2 PRF are built in the core on top of the provider's HMAC.
   `rustyssl-capi` implements the trait with `EVP_*_fetch` on the `SSL_CTX`'s library context
   and property query, and keys and certificates stay `EVP_PKEY` and `X509` objects behind
   opaque handles. The core's own tests implement it with `rustyssl-crypto` directly.

3. **The core yields at every observable event.** `Connection::step` runs the state machine
   until the next event and returns it: output to send, input needed, a callback to make (info,
   message, keylog, servername, client hello, certificate selection, verification, ALPN, PSK,
   session lookup and storage, ticket keys, custom extensions), handshake completion,
   application data, or closure. The state that `SSL_get_state` and friends report is the state
   at that event. A callback that decides something is answered with a matching `resume_*`
   call; one that suspends (`WANT_*`) leaves the request pending, and the next `step` repeats it.

4. **`rustyssl-capi` drives the core** (`ssl/` modules, all `rustyssl_private_*`): it takes the
   `SSL`'s lock, calls `step`, releases the lock, and only then calls the application, so every
   callback may re-enter any API. It moves bytes between the core and the BIOs, and maps the
   core's results to OpenSSL's return values, `SSL_get_error` codes, alerts, and `SSL_R_*`
   errors.

5. **OpenSSL's observable choices are reproduced in the core:** the order and contents of the
   ClientHello's extensions, the alert sent for each failure, the `SSL_R_*` reason recorded with
   it (the core's errors name OpenSSL's reasons; capi maps them in one place), the state
   numbering, and the cipher and group preference orders. Where only the wire matters, the core
   is free in how it gets there.

## Consequences

- Every C callback runs without a lock held, and every retryable suspension falls out of the
  model instead of being bolted on.
- The core can be tested and fuzzed alone, client against server, against RFC 8448's traces,
  and with arbitrary peer flights, with no C in the loop.
- Algorithms come from providers exactly as in OpenSSL, including third-party groups.
- A step returns after each event, so a handshake takes more calls into the core than OpenSSL
  takes function calls. The cost is a branch per event, small next to the crypto.

## DTLS (implementation plan step 8.1)

DTLS 1.0 and 1.2 share the TLS 1.2 state machine, as in OpenSSL (`statem.c` with the
`SSL_CONNECTION_IS_DTLS` branches; there is no DTLS 1.3 in 3.5: `DTLS_MAX_VERSION_INTERNAL`
is `DTLS1_2_VERSION`). The core keeps OpenSSL's wire versions (`DTLS1_VERSION` 0xfeff,
`DTLS1_2_VERSION` 0xfefd): every ordering goes through `version::cmp`, which counts DTLS
versions down, and the protocol features a version has (signature algorithms, the SHA-256
PRF, explicit IVs) come from its TLS equivalent (`version::tls_level`).

- **Datagrams in, datagrams out.** The caller feeds whole datagrams
  (`Connection::feed_datagram`); a record never crosses one, and a truncated record drops the
  rest of its datagram. Output is a list of datagrams (`Connection::take_datagrams`): during a
  handshake records collect into the open datagram up to the MTU, as OpenSSL's buffering BIO
  holds them until a flush, and a flush point closes it.
- **The record layer** (`record::dtls`) reads 13-octet headers with the epoch and the 48-bit
  sequence number, checks the 64-record replay window of the current epoch, buffers up to 16
  records of the next epoch while in a handshake and replays them after the epoch changes,
  and drops what OpenSSL drops (a wrong version, a record too long, a bad MAC or tag)
  silently. The MAC and AEAD nonce take `epoch || sequence`. The writer keeps the previous
  epoch's protection so the last flight can be retransmitted across a ChangeCipherSpec.
- **The handshake layer** (`conn::dtls`, from `statem_dtls.c`): 12-octet message headers,
  each message fragmented to the MTU; received fragments are reassembled with a bitmap, and
  messages ahead of the expected one are buffered (at most ten ahead, each no longer than
  `max_cert_list`), so a datagram's loss or reordering never reaches the state machine. The
  transcript takes each message with its header as if unfragmented. The flight sent is kept
  for retransmission and dropped when the peer's flight completes (`dtls1_stop_timer`).
- **Timers stay with the caller.** The core says when OpenSSL starts and stops the
  retransmission timer and counts timeouts; capi owns the clock, `DTLS_set_timer_cb`, the
  `BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT` notification, and calls `Connection::dtls_timeout` when
  it fires (`DTLSv1_handle_timeout`, and before each read as `dtls1_read_bytes` does).
- **Cookies** are requests like the other callbacks (`Request::DtlsCookieGenerate`,
  `DtlsCookieVerify`). `DTLSv1_listen` is a stateless exchange in capi that answers
  ClientHellos without a valid cookie with a HelloVerifyRequest and hands the first good one
  to the core.
