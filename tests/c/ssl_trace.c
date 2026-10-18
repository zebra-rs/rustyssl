/*
 * Conformance test for SSL_trace(3), the message callback that prints a readable trace of
 * records and handshake messages: crafted messages of every kind given to it directly (on fresh
 * TLS client, TLS server and DTLS connections, and on connections after a TLS 1.2 and a TLS 1.3
 * handshake, whose state changes what it prints), malformed and truncated ones, and two real
 * handshakes traced through SSL_set_msg_callback.
 *
 * The crafted traces are printed whole. In the real handshakes, the fields that vary from run to
 * run (randoms, key shares, signatures, tickets, and the lengths that follow from them) are
 * masked.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static const char SERVER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBxDCCAWqgAwIBAgICA+kwCgYIKoZIzj0EAwIwKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0yNjEwMTgwOTMyNDZaGA8yMTI2\n"
    "MDkyNDA5MzI0NlowGTEXMBUGA1UEAwwOc2VydmVyLmV4YW1wbGUwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAARQwBruuNdz4xCD1gvolSn84T4lhmxXimDiZyo55Kdd\n"
    "rfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHko4GOMIGLMAkGA1UdEwQC\n"
    "MAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBkGA1UdEQQS\n"
    "MBCCDnNlcnZlci5leGFtcGxlMB0GA1UdDgQWBBTJhnvwTSY1MKJTWPQEV8hTOvQj\n"
    "CzAfBgNVHSMEGDAWgBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjOPQQDAgNI\n"
    "ADBFAiA9HtDZKkG58jRwUNQ4CbP61ozryZRRkz7W3RF94vEpSQIhAKwrnOIS/FEg\n"
    "N7iBJyOB+Buj5UbPic6SYxuj11J3f/PG\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvhwC7sEHpNUtRIwR\n"
    "1HpSoTfsfnL+ayakODf8YQkvzpKhRANCAARQwBruuNdz4xCD1gvolSn84T4lhmxX\n"
    "imDiZyo55KddrfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHk\n"
    "-----END PRIVATE KEY-----\n";

static X509 *cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static EVP_PKEY *key(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free(b);
    return k;
}

/* A message under construction. */
struct msg {
    unsigned char d[8192];
    size_t n;
};

static void put(struct msg *m, const void *p, size_t n)
{
    if (m->n + n > sizeof(m->d)) {
        printf("Bail out! message too long\n");
        exit(1);
    }
    memcpy(m->d + m->n, p, n);
    m->n += n;
}

static void u8(struct msg *m, unsigned v)
{
    unsigned char b = (unsigned char)v;

    put(m, &b, 1);
}

static void u16(struct msg *m, unsigned v)
{
    u8(m, v >> 8);
    u8(m, v);
}

static void u24(struct msg *m, unsigned long v)
{
    u8(m, (unsigned)(v >> 16));
    u8(m, (unsigned)(v >> 8));
    u8(m, (unsigned)v);
}

/* Appends octets written as hex (spaces ignored). */
static void hex(struct msg *m, const char *h)
{
    while (*h != '\0') {
        unsigned v;

        if (*h == ' ') {
            h++;
            continue;
        }
        if (sscanf(h, "%2x", &v) != 1) {
            printf("Bail out! bad hex\n");
            exit(1);
        }
        u8(m, v);
        h += 2;
    }
}

/* `n` octets counting up from `start`. */
static void seq(struct msg *m, unsigned start, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        u8(m, (unsigned)(start + i));
}

/* A handshake message of `type` around `body` (TLS framing). */
static void hs(struct msg *out, unsigned type, const struct msg *body)
{
    out->n = 0;
    u8(out, type);
    u24(out, body->n);
    put(out, body->d, body->n);
}

/* The same in DTLS framing: message_seq 5, unfragmented. */
static void dtls_hs(struct msg *out, unsigned type, const struct msg *body)
{
    out->n = 0;
    u8(out, type);
    u24(out, body->n);
    u16(out, 5);
    u24(out, 0);
    u24(out, body->n);
    put(out, body->d, body->n);
}

/* An extension. */
static void ext(struct msg *m, unsigned type, const char *h)
{
    struct msg b = { { 0 }, 0 };

    hex(&b, h);
    u16(m, type);
    u16(m, (unsigned)b.n);
    put(m, b.d, b.n);
}

/* A vector with a 2-octet length. */
static void vec16(struct msg *m, const struct msg *body)
{
    u16(m, (unsigned)body->n);
    put(m, body->d, body->n);
}

static BIO *out;

/* Prints what the trace wrote, each line marked, and empties the BIO. */
static void flush(void)
{
    char *p;
    long n = BIO_get_mem_data(out, &p), i, start = 0;

    for (i = 0; i < n; i++) {
        if (p[i] == '\n') {
            printf("  | %.*s\n", (int)(i - start), p + start);
            start = i + 1;
        }
    }
    if (start < n)
        printf("  | %.*s<no newline>\n", (int)(n - start), p + start);
    (void)BIO_reset(out);
}

/* Gives a message to SSL_trace and prints its trace. */
static void trace(const char *what, SSL *s, int write_p, int content_type, const struct msg *m)
{
    printf("# %s\n", what);
    SSL_trace(write_p, TLS1_2_VERSION, content_type, m->d, m->n, s, out);
    flush();
}

/* A handshake message to SSL_trace. */
static void trace_hs(const char *what, SSL *s, int write_p, unsigned type, const struct msg *body)
{
    struct msg m;

    hs(&m, type, body);
    trace(what, s, write_p, SSL3_RT_HANDSHAKE, &m);
}

static void trace_hex(const char *what, SSL *s, int write_p, int content_type, const char *h)
{
    struct msg m = { { 0 }, 0 };

    hex(&m, h);
    trace(what, s, write_p, content_type, &m);
}

static unsigned char cert_der[2048];
static size_t cert_len;
static unsigned char dn_der[256];
static size_t dn_len;

/* A ClientHello with every extension the trace knows (and some it doesn't). */
static void client_hello(struct msg *b, int dtls)
{
    struct msg e = { { 0 }, 0 };

    b->n = 0;
    u16(b, dtls ? DTLS1_2_VERSION : TLS1_2_VERSION);
    seq(b, 0x40, 32);
    u8(b, 32);
    seq(b, 0x80, 32);
    if (dtls)
        hex(b, "04 c0 0c 1e 55");
    hex(b, "000c 1301 1302 c02b c02f 00ff 0a0a");
    hex(b, "02 00 01");
    ext(&e, TLSEXT_TYPE_server_name, "000e00000b6578616d706c652e636f6d");
    ext(&e, TLSEXT_TYPE_supported_groups, "0008 001d 0017 11ec 7a7a");
    ext(&e, TLSEXT_TYPE_ec_point_formats, "03 00 01 02");
    ext(&e, TLSEXT_TYPE_signature_algorithms, "000c 0403 0804 0807 0201 0905 eeee");
    ext(&e, TLSEXT_TYPE_application_layer_protocol_negotiation, "000c 02 6832 08 687474702f312e31");
    ext(&e, TLSEXT_TYPE_supported_versions, "06 0304 0303 fefd");
    ext(&e, TLSEXT_TYPE_psk_kex_modes, "02 01 00");
    ext(&e, TLSEXT_TYPE_key_share,
        "0026 001d 0020 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        " 0017 0002 0405");
    ext(&e, TLSEXT_TYPE_renegotiate, "00");
    ext(&e, TLSEXT_TYPE_session_ticket, "");
    ext(&e, TLSEXT_TYPE_session_ticket, "aabbccdd");
    ext(&e, TLSEXT_TYPE_max_fragment_length, "02");
    ext(&e, TLSEXT_TYPE_compress_certificate, "06 0001 0002 0003");
    ext(&e, TLSEXT_TYPE_client_cert_type, "02 00 02");
    ext(&e, TLSEXT_TYPE_server_cert_type, "03 00 02 01");
    ext(&e, TLSEXT_TYPE_early_data, "");
    ext(&e, TLSEXT_TYPE_extended_master_secret, "");
    ext(&e, TLSEXT_TYPE_padding, "0000000000000000000000000000000000000000");
    ext(&e, 0xfafa, "01");
    vec16(b, &e);
}

/* A ServerHello (TLS 1.2 framing unless `version` is TLS 1.3's) with these extensions. */
static void server_hello(struct msg *b, unsigned version, const struct msg *e)
{
    b->n = 0;
    u16(b, version);
    seq(b, 0x20, 32);
    if (version != TLS1_3_VERSION) {
        u8(b, 4);
        hex(b, "01020304");
    }
    hex(b, "c02f");
    if (version != TLS1_3_VERSION)
        u8(b, 0);
    vec16(b, e);
}

/* A TLS 1.2 Certificate: the server's, one that doesn't parse, one with octets after it. */
static void certificates(struct msg *b, int tls13)
{
    struct msg l = { { 0 }, 0 };

    if (tls13)
        hex(&l, "");
    u24(&l, cert_len);
    put(&l, cert_der, cert_len);
    if (tls13)
        hex(&l, "0005 0012 0001 aa");
    u24(&l, 4);
    hex(&l, "30020500");
    if (tls13)
        hex(&l, "0000");
    u24(&l, 5);
    hex(&l, "0500 0102 03");
    if (tls13)
        hex(&l, "0000");
    b->n = 0;
    if (tls13)
        hex(b, "02 abcd");
    u24(b, l.n);
    put(b, l.d, l.n);
}

/* The messages whose printing doesn't depend on a negotiated cipher. */
static void common_messages(SSL *s, int write_p)
{
    struct msg b = { { 0 }, 0 }, e = { { 0 }, 0 };

    certificates(&b, 0);
    trace_hs("Certificate", s, write_p, SSL3_MT_CERTIFICATE, &b);
    b.n = 0;
    hex(&b, "03 01 40 99");
    hex(&b, "0006 0403 0804 0201");
    u16(&b, (unsigned)(2 + dn_len + 2 + 3));
    u16(&b, (unsigned)dn_len);
    put(&b, dn_der, dn_len);
    hex(&b, "0003 300100");
    trace_hs("CertificateRequest", s, write_p, SSL3_MT_CERTIFICATE_REQUEST, &b);
    b.n = 0;
    hex(&b, "0403 0006 300402010102");
    trace_hs("CertificateVerify", s, write_p, SSL3_MT_CERTIFICATE_VERIFY, &b);
    b.n = 0;
    seq(&b, 0xa0, 12);
    trace_hs("Finished", s, write_p, SSL3_MT_FINISHED, &b);
    b.n = 0;
    trace_hs("ServerHelloDone", s, write_p, SSL3_MT_SERVER_DONE, &b);
    hex(&b, "00");
    trace_hs("ServerHelloDone with a body", s, write_p, SSL3_MT_SERVER_DONE, &b);
    b.n = 0;
    trace_hs("EndOfEarlyData", s, write_p, SSL3_MT_END_OF_EARLY_DATA, &b);
    trace_hs("NewSessionTicket, empty", s, write_p, SSL3_MT_NEWSESSION_TICKET, &b);
    hex(&b, "00001c20 0004 deadbeef");
    trace_hs("NewSessionTicket", s, write_p, SSL3_MT_NEWSESSION_TICKET, &b);
    hex(&b, "00");
    trace_hs("NewSessionTicket with trailing octets", s, write_p, SSL3_MT_NEWSESSION_TICKET, &b);
    e.n = 0;
    ext(&e, TLSEXT_TYPE_application_layer_protocol_negotiation, "0003 02 6832");
    ext(&e, TLSEXT_TYPE_server_name, "");
    ext(&e, TLSEXT_TYPE_early_data, "");
    ext(&e, TLSEXT_TYPE_max_fragment_length, "01");
    ext(&e, TLSEXT_TYPE_server_cert_type, "02");
    ext(&e, TLSEXT_TYPE_client_cert_type, "00");
    ext(&e, TLSEXT_TYPE_supported_groups, "0004 001d 0017");
    b.n = 0;
    vec16(&b, &e);
    trace_hs("EncryptedExtensions", s, write_p, SSL3_MT_ENCRYPTED_EXTENSIONS, &b);
    b.n = 0;
    trace_hs("EncryptedExtensions, none at all", s, write_p, SSL3_MT_ENCRYPTED_EXTENSIONS, &b);
    hex(&b, "0000");
    trace_hs("EncryptedExtensions, empty", s, write_p, SSL3_MT_ENCRYPTED_EXTENSIONS, &b);
    b.n = 0;
    hex(&b, "01");
    trace_hs("KeyUpdate", s, write_p, SSL3_MT_KEY_UPDATE, &b);
    hex(&b, "07");
    trace_hs("KeyUpdate, too long", s, write_p, SSL3_MT_KEY_UPDATE, &b);
    b.n = 0;
    hex(&b, "05");
    trace_hs("KeyUpdate, unknown", s, write_p, SSL3_MT_KEY_UPDATE, &b);
    b.n = 0;
    hex(&b, "0001 000400 000006 010203040506");
    trace_hs("CompressedCertificate", s, write_p, SSL3_MT_COMPRESSED_CERTIFICATE, &b);
    b.n = 0;
    hex(&b, "0003 000400 000000");
    trace_hs("CompressedCertificate, empty", s, write_p, SSL3_MT_COMPRESSED_CERTIFICATE, &b);
    b.n = 0;
    hex(&b, "fefd 03 010203");
    trace_hs("HelloVerifyRequest", s, write_p, DTLS1_MT_HELLO_VERIFY_REQUEST, &b);
    b.n = 0;
    seq(&b, 0, 40);
    trace_hs("an unknown message", s, write_p, 0x77, &b);
    b.n = 0;
    hex(&b, "0000 0003 300100");
    trace_hs("CertificateRequest, no types", s, write_p, SSL3_MT_CERTIFICATE_REQUEST, &b);
    b.n = 0;
    hex(&b, "01 01 0003 0403 00");
    trace_hs("CertificateRequest, odd sigalgs", s, write_p, SSL3_MT_CERTIFICATE_REQUEST, &b);
    b.n = 0;
    hex(&b, "01 01 0002 0403 0005 0003 3001");
    trace_hs("CertificateRequest, a short name", s, write_p, SSL3_MT_CERTIFICATE_REQUEST, &b);
    b.n = 0;
    hex(&b, "000002 3000");
    trace_hs("Certificate, short list", s, write_p, SSL3_MT_CERTIFICATE, &b);
    b.n = 0;
    hex(&b, "000004 000005 3000");
    trace_hs("Certificate, short entry", s, write_p, SSL3_MT_CERTIFICATE, &b);
}

/* Records, ChangeCipherSpec, alerts, and malformed handshake framing. */
static void records(SSL *s, int dtls)
{
    struct msg m = { { 0 }, 0 };

    if (dtls) {
        trace_hex("record header", s, 1, SSL3_RT_HEADER, "16 fefd 0001 000000000203 0040");
        trace_hex("record header, unknown version", s, 0, SSL3_RT_HEADER,
            "17 1234 ffff 0102030405ff 4000");
        trace_hex("record header, short", s, 0, SSL3_RT_HEADER, "16 fefd 0001 0000");
    } else {
        trace_hex("record header", s, 1, SSL3_RT_HEADER, "16 0301 0200");
        trace_hex("record header, received", s, 0, SSL3_RT_HEADER, "17 0303 4011");
        trace_hex("record header, unknown type", s, 0, SSL3_RT_HEADER, "63 0304 0000");
        trace_hex("record header, longer", s, 1, SSL3_RT_HEADER, "15 0302 00 00 0002");
        trace_hex("record header, short", s, 1, SSL3_RT_HEADER, "16 03");
        trace_hex("record header, empty", s, 0, SSL3_RT_HEADER, "");
    }
    trace_hex("inner content type", s, 1, SSL3_RT_INNER_CONTENT_TYPE, "16");
    trace_hex("inner content type, unknown", s, 0, SSL3_RT_INNER_CONTENT_TYPE, "fe");
    trace_hex("ChangeCipherSpec", s, 1, SSL3_RT_CHANGE_CIPHER_SPEC, "01");
    trace_hex("ChangeCipherSpec, unknown value", s, 0, SSL3_RT_CHANGE_CIPHER_SPEC, "0203");
    trace_hex("ChangeCipherSpec, empty", s, 0, SSL3_RT_CHANGE_CIPHER_SPEC, "");
    trace_hex("alert", s, 1, SSL3_RT_ALERT, "0228");
    trace_hex("alert, warning close_notify", s, 0, SSL3_RT_ALERT, "0100");
    trace_hex("alert, unknown", s, 0, SSL3_RT_ALERT, "03c8");
    trace_hex("alert, too long", s, 0, SSL3_RT_ALERT, "022800");
    trace_hex("alert, too short", s, 0, SSL3_RT_ALERT, "02");
    trace_hex("application data", s, 0, SSL3_RT_APPLICATION_DATA, "414243");
    trace_hex("an unknown content type", s, 0, 99, "414243");
    trace_hex("handshake, empty", s, 0, SSL3_RT_HANDSHAKE, "");
    trace_hex("handshake, short header", s, 0, SSL3_RT_HANDSHAKE, "0100");
    trace_hex("handshake, short body", s, 0, SSL3_RT_HANDSHAKE, "14000010 0102");
    m.n = 0;
    trace("handshake, header only", s, 0, SSL3_RT_HANDSHAKE, &m);
}

/* A ClientHello and its malformed variants. */
static void hellos(SSL *s, int write_p, int dtls)
{
    struct msg b = { { 0 }, 0 }, e = { { 0 }, 0 }, m;

    client_hello(&b, dtls);
    if (dtls) {
        dtls_hs(&m, SSL3_MT_CLIENT_HELLO, &b);
        trace("ClientHello", s, write_p, SSL3_RT_HANDSHAKE, &m);
        b.n = 0;
        hex(&b, "fefd 03 010203");
        dtls_hs(&m, DTLS1_MT_HELLO_VERIFY_REQUEST, &b);
        trace("HelloVerifyRequest", s, !write_p, SSL3_RT_HANDSHAKE, &m);
        hex(&m, "ff");
        trace("HelloVerifyRequest, trailing octet", s, !write_p, SSL3_RT_HANDSHAKE, &m);
        m.n = 7;
        trace("HelloVerifyRequest, short DTLS header", s, !write_p, SSL3_RT_HANDSHAKE, &m);
        return;
    }
    trace_hs("ClientHello", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= 3;
    trace_hs("ClientHello, truncated extension", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n = 0;
    u16(&b, TLS1_VERSION);
    seq(&b, 0, 32);
    hex(&b, "00 0003 1301 13 01 00");
    trace_hs("ClientHello, odd cipher suites", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n = 0;
    u16(&b, TLS1_VERSION);
    seq(&b, 0, 32);
    hex(&b, "00 0002 1301 01 00");
    trace_hs("ClientHello, no extensions", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    hex(&b, "0000");
    trace_hs("ClientHello, empty extensions", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= 2;
    hex(&b, "0008 000a 0010 0004 001d");
    trace_hs("ClientHello, extension past the end", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= 10;
    hex(&b, "0002 000a");
    trace_hs("ClientHello, extension header cut", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= 4;
    hex(&b, "0010 000a");
    trace_hs("ClientHello, extensions past the end", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= 4;
    e.n = 0;
    ext(&e, TLSEXT_TYPE_application_layer_protocol_negotiation, "0003 05 6832");
    vec16(&b, &e);
    trace_hs("ClientHello, ALPN past the end", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= e.n + 2;
    e.n = 0;
    ext(&e, TLSEXT_TYPE_signature_algorithms, "0003 040300");
    vec16(&b, &e);
    trace_hs("ClientHello, odd signature algorithms", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= e.n + 2;
    e.n = 0;
    ext(&e, TLSEXT_TYPE_key_share, "0006 001d 0004 0102");
    vec16(&b, &e);
    trace_hs("ClientHello, key share past the end", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= e.n + 2;
    e.n = 0;
    ext(&e, TLSEXT_TYPE_renegotiate, "03 010203");
    vec16(&b, &e);
    trace_hs("ClientHello, renegotiation info", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= e.n + 2;
    e.n = 0;
    ext(&e, TLSEXT_TYPE_ec_point_formats, "02 00");
    vec16(&b, &e);
    trace_hs("ClientHello, short point formats", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
    b.n -= e.n + 2;
    e.n = 0;
    ext(&e, TLSEXT_TYPE_supported_versions, "03 0304 03");
    vec16(&b, &e);
    trace_hs("ClientHello, odd versions", s, write_p, SSL3_MT_CLIENT_HELLO, &b);
}

/* ServerHellos, as the server sends them (or a client receives them). */
static void server_hellos(SSL *s, int write_p)
{
    struct msg b = { { 0 }, 0 }, e = { { 0 }, 0 };

    ext(&e, TLSEXT_TYPE_renegotiate, "18 000102030405060708090a0b 0c0d0e0f1011121314151617");
    ext(&e, TLSEXT_TYPE_ec_point_formats, "01 00");
    ext(&e, TLSEXT_TYPE_extended_master_secret, "");
    ext(&e, TLSEXT_TYPE_session_ticket, "");
    server_hello(&b, TLS1_2_VERSION, &e);
    trace_hs("ServerHello, TLS 1.2", s, write_p, SSL3_MT_SERVER_HELLO, &b);
    e.n = 0;
    ext(&e, TLSEXT_TYPE_supported_versions, "0304");
    ext(&e, TLSEXT_TYPE_key_share, "001d 0004 01020304");
    server_hello(&b, TLS1_2_VERSION, &e);
    trace_hs("ServerHello, TLS 1.3", s, write_p, SSL3_MT_SERVER_HELLO, &b);
    server_hello(&b, TLS1_3_VERSION, &e);
    trace_hs("ServerHello, TLS 1.3's version", s, write_p, SSL3_MT_SERVER_HELLO, &b);
    e.n = 0;
    ext(&e, TLSEXT_TYPE_supported_versions, "0304");
    ext(&e, TLSEXT_TYPE_key_share, "0017");
    ext(&e, TLSEXT_TYPE_cookie, "0004 01020304");
    server_hello(&b, TLS1_2_VERSION, &e);
    trace_hs("HelloRetryRequest", s, write_p, SSL3_MT_SERVER_HELLO, &b);
    e.n = 0;
    ext(&e, TLSEXT_TYPE_supported_versions, "030403");
    server_hello(&b, TLS1_2_VERSION, &e);
    trace_hs("ServerHello, long version", s, write_p, SSL3_MT_SERVER_HELLO, &b);
    e.n = 0;
    ext(&e, TLSEXT_TYPE_renegotiate, "03 010203");
    server_hello(&b, TLS1_2_VERSION, &e);
    trace_hs("ServerHello, odd renegotiation info", s, write_p, SSL3_MT_SERVER_HELLO, &b);
    e.n = 0;
    ext(&e, TLSEXT_TYPE_key_share, "001d 0008 01020304");
    server_hello(&b, TLS1_2_VERSION, &e);
    trace_hs("ServerHello, key share past the end", s, write_p, SSL3_MT_SERVER_HELLO, &b);
    e.n = 0;
    ext(&e, TLSEXT_TYPE_server_cert_type, "0102");
    server_hello(&b, TLS1_2_VERSION, &e);
    trace_hs("ServerHello, two certificate types", s, write_p, SSL3_MT_SERVER_HELLO, &b);
    b.n = 0;
    u16(&b, TLS1_2_VERSION);
    seq(&b, 0, 20);
    trace_hs("ServerHello, short random", s, write_p, SSL3_MT_SERVER_HELLO, &b);
}

/* The messages whose printing depends on the negotiated key exchange (after a handshake). */
static void key_exchanges(SSL *s, int write_p)
{
    struct msg b = { { 0 }, 0 };

    hex(&b, "03 0017 04 01020304 0403 0004 30020500");
    trace_hs("ServerKeyExchange, named curve", s, write_p, SSL3_MT_SERVER_KEY_EXCHANGE, &b);
    hex(&b, "00");
    trace_hs("ServerKeyExchange, trailing octet", s, write_p, SSL3_MT_SERVER_KEY_EXCHANGE, &b);
    b.n = 0;
    hex(&b, "03 0017 04 01020304");
    trace_hs("ServerKeyExchange, no signature", s, write_p, SSL3_MT_SERVER_KEY_EXCHANGE, &b);
    b.n = 0;
    hex(&b, "01 0017");
    trace_hs("ServerKeyExchange, explicit prime", s, write_p, SSL3_MT_SERVER_KEY_EXCHANGE, &b);
    b.n = 0;
    hex(&b, "02");
    trace_hs("ServerKeyExchange, explicit char2", s, write_p, SSL3_MT_SERVER_KEY_EXCHANGE, &b);
    b.n = 0;
    hex(&b, "07 0017");
    trace_hs("ServerKeyExchange, unknown curve type", s, write_p, SSL3_MT_SERVER_KEY_EXCHANGE, &b);
    b.n = 0;
    hex(&b, "03 00");
    trace_hs("ServerKeyExchange, short curve", s, write_p, SSL3_MT_SERVER_KEY_EXCHANGE, &b);
    b.n = 0;
    trace_hs("ServerKeyExchange, empty", s, write_p, SSL3_MT_SERVER_KEY_EXCHANGE, &b);
    hex(&b, "04 01020304");
    trace_hs("ClientKeyExchange", s, write_p, SSL3_MT_CLIENT_KEY_EXCHANGE, &b);
    hex(&b, "00");
    trace_hs("ClientKeyExchange, trailing octet", s, write_p, SSL3_MT_CLIENT_KEY_EXCHANGE, &b);
    b.n = 0;
    hex(&b, "08 0102");
    trace_hs("ClientKeyExchange, short", s, write_p, SSL3_MT_CLIENT_KEY_EXCHANGE, &b);
}

/* The TLS 1.3 forms of Certificate, CertificateRequest and NewSessionTicket. */
static void tls13_messages(SSL *s, int write_p)
{
    struct msg b = { { 0 }, 0 }, e = { { 0 }, 0 };

    certificates(&b, 1);
    trace_hs("Certificate, TLS 1.3", s, write_p, SSL3_MT_CERTIFICATE, &b);
    b.n = 0;
    hex(&b, "00 000000");
    trace_hs("Certificate, TLS 1.3, empty", s, write_p, SSL3_MT_CERTIFICATE, &b);
    b.n = 0;
    hex(&b, "05 01");
    trace_hs("Certificate, TLS 1.3, short context", s, write_p, SSL3_MT_CERTIFICATE, &b);
    ext(&e, TLSEXT_TYPE_signature_algorithms, "0004 0403 0804");
    ext(&e, TLSEXT_TYPE_certificate_authorities, "0003 0001 30");
    b.n = 0;
    hex(&b, "02 0102");
    vec16(&b, &e);
    trace_hs("CertificateRequest, TLS 1.3", s, write_p, SSL3_MT_CERTIFICATE_REQUEST, &b);
    e.n = 0;
    ext(&e, TLSEXT_TYPE_early_data, "00004000");
    b.n = 0;
    hex(&b, "00093a80 01020304 08 0000000000000001 0005 0102030405");
    vec16(&b, &e);
    trace_hs("NewSessionTicket, TLS 1.3", s, write_p, SSL3_MT_NEWSESSION_TICKET, &b);
    e.n = 0;
    ext(&e, TLSEXT_TYPE_early_data, "000040");
    b.n = 0;
    hex(&b, "00093a80 01020304 00 0001 aa");
    vec16(&b, &e);
    trace_hs("NewSessionTicket, TLS 1.3, short early data", s, write_p, SSL3_MT_NEWSESSION_TICKET,
        &b);
    b.n = 0;
    hex(&b, "00093a80 0102");
    trace_hs("NewSessionTicket, TLS 1.3, short", s, write_p, SSL3_MT_NEWSESSION_TICKET, &b);
    b.n = 0;
    hex(&b, "0804 0004 01020304");
    trace_hs("CertificateVerify, TLS 1.3", s, write_p, SSL3_MT_CERTIFICATE_VERIFY, &b);
}

/* A server context with the server's certificate and key. */
static SSL_CTX *server_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    X509 *x = cert(SERVER_PEM);
    EVP_PKEY *k = key(SERVER_KEY_PEM);

    if (ctx == NULL || x == NULL || k == NULL || SSL_CTX_use_certificate(ctx, x) != 1
        || SSL_CTX_use_PrivateKey(ctx, k) != 1) {
        printf("Bail out! server context\n");
        exit(1);
    }
    X509_free(x);
    EVP_PKEY_free(k);
    return ctx;
}

/* Runs both ends' handshakes in turn until both finish. */
static int run(SSL *c, SSL *s)
{
    int cdone = 0, sdone = 0, round;

    for (round = 0; round < 64 && (!cdone || !sdone); round++) {
        int i;

        for (i = 0; i < 2; i++) {
            SSL *x = i == 0 ? c : s;
            int *done = i == 0 ? &cdone : &sdone, r, e;

            if (*done)
                continue;
            r = SSL_do_handshake(x);
            if (r == 1) {
                *done = 1;
                continue;
            }
            e = SSL_get_error(x, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                return 0;
        }
    }
    return cdone && sdone;
}

/* Whether the line holds `tok` at `i`. */
static int at(const char *line, long i, long n, const char *tok)
{
    long l = (long)strlen(tok);

    return i + l <= n && strncmp(line + i, tok, (size_t)l) == 0;
}

/*
 * Prints a real handshake's trace with what varies masked: the numbers after the length labels,
 * hex runs, and the time and ticket_age_add fields.
 */
static void flush_masked(void)
{
    static const char *const labels[] = { "Length = ", "Length=", "length=", "length = ",
        "(len=", "gmt_unix_time=", "ticket_age_add=", "extlen = " };
    char *p;
    long n = BIO_get_mem_data(out, &p), i, start = 0;

    for (i = 0; i <= n; i++) {
        long j;

        if (i < n && p[i] != '\n')
            continue;
        if (i == start && i == n)
            break;
        printf("  | ");
        for (j = start; j < i; j++) {
            size_t k;
            int masked = 0;

            for (k = 0; k < sizeof(labels) / sizeof(labels[0]); k++) {
                if (at(p, j, i, labels[k])) {
                    long l = (long)strlen(labels[k]);

                    printf("%s*", labels[k]);
                    j += l;
                    while (j < i && p[j] != ')' && p[j] != ',' && p[j] != ' ' && p[j] != '\n')
                        j++;
                    j--;
                    masked = 1;
                    break;
                }
            }
            if (!masked && at(p, j, i, "): ")) {
                printf("): *");
                break;
            }
            if (!masked)
                putchar(p[j]);
        }
        printf("\n");
        start = i + 1;
    }
    (void)BIO_reset(out);
}

/* A handshake at `version` with both ends traced, then `after` on the finished client. */
static SSL *traced_handshake(SSL_CTX *cctx, SSL_CTX *sctx, int version, SSL **server)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;

    if (c == NULL || s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1) {
        printf("Bail out! connection\n");
        exit(1);
    }
    SSL_set_min_proto_version(c, version);
    SSL_set_max_proto_version(c, version);
    SSL_set_options(c, SSL_OP_NO_TICKET);
    SSL_set_options(s, SSL_OP_NO_TICKET);
    if (version == TLS1_2_VERSION)
        SSL_set_cipher_list(c, "ECDHE-ECDSA-AES128-GCM-SHA256");
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_set_msg_callback(c, SSL_trace);
    SSL_set_msg_callback_arg(c, out);
    SSL_set_msg_callback(s, SSL_trace);
    SSL_set_msg_callback_arg(s, out);
    check(run(c, s), "the traced handshake completes");
    flush_masked();
    SSL_set_msg_callback(c, NULL);
    SSL_set_msg_callback(s, NULL);
    *server = s;
    return c;
}

int main(void)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = server_ctx(),
            *dctx = SSL_CTX_new(DTLS_client_method());
    SSL *c, *s, *d, *c12, *s12, *c13, *s13;
    X509 *x = cert(SERVER_PEM);
    unsigned char *p;
    int n;

    out = BIO_new(BIO_s_mem());
    if (cctx == NULL || dctx == NULL || out == NULL || x == NULL) {
        printf("Bail out! setup\n");
        return 1;
    }
    p = cert_der;
    n = i2d_X509(x, &p);
    cert_len = n > 0 ? (size_t)n : 0;
    p = dn_der;
    n = i2d_X509_NAME(X509_get_issuer_name(x), &p);
    dn_len = n > 0 ? (size_t)n : 0;
    X509_free(x);
    check(cert_len > 0 && dn_len > 0, "the certificate and name encode");

    c = SSL_new(cctx);
    s = SSL_new(sctx);
    d = SSL_new(dctx);
    if (c == NULL || s == NULL || d == NULL) {
        printf("Bail out! SSL_new\n");
        return 1;
    }
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);

    printf("# -- a fresh TLS client\n");
    hellos(c, 1, 0);
    server_hellos(c, 0);
    common_messages(c, 0);
    records(c, 0);
    printf("# -- a fresh TLS server\n");
    hellos(s, 0, 0);
    server_hellos(s, 1);
    common_messages(s, 1);
    printf("# -- a fresh DTLS client\n");
    hellos(d, 1, 1);
    records(d, 1);

    printf("# -- no connection\n");
    SSL_trace(1, TLS1_2_VERSION, SSL3_RT_ALERT, "\x02\x28", 2, NULL, out);
    check(BIO_ctrl_pending(out) == 0, "nothing is traced without a connection");

    printf("# -- a TLS 1.2 handshake\n");
    c12 = traced_handshake(cctx, sctx, TLS1_2_VERSION, &s12);
    printf("# -- after TLS 1.2, the client\n");
    key_exchanges(c12, 0);
    common_messages(c12, 0);
    printf("# -- after TLS 1.2, the server\n");
    key_exchanges(s12, 0);

    printf("# -- a TLS 1.3 handshake\n");
    c13 = traced_handshake(cctx, sctx, TLS1_3_VERSION, &s13);
    printf("# -- after TLS 1.3, the client\n");
    tls13_messages(c13, 0);
    key_exchanges(c13, 0);
    records(c13, 0);
    printf("# -- after TLS 1.3, the server\n");
    tls13_messages(s13, 0);

    SSL_free(c);
    SSL_free(s);
    SSL_free(d);
    SSL_free(c12);
    SSL_free(s12);
    SSL_free(c13);
    SSL_free(s13);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    SSL_CTX_free(dctx);
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
