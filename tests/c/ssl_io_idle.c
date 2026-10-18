/*
 * Conformance test for libssl's I/O entry points and handshake getters on connections that
 * haven't run a handshake (SSL_do_handshake(3), SSL_read(3), SSL_write(3), SSL_shutdown(3),
 * SSL_get_error(3), SSL_get_current_cipher(3), SSL_get_peer_certificate(3),
 * SSL_get_peer_cert_chain(3), SSL_get0_alpn_selected(3), SSL_pending(3),
 * SSL_get_peer_signature_nid(3), SSL_get_shared_sigalgs(3), SSL_get_negotiated_group(3)): no
 * role set, roles set but nothing sent, SSL_clear, and SSL_get_error's reading of the error
 * queue and the shutdown flags.
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

/* Prints and clears the error queue: library/reason and any data. */
static void errors(void)
{
    unsigned long e;
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static void said(const char *what, SSL *x, int r)
{
    printf("  %s: %d -> %d\n", what, r, SSL_get_error(x, r));
    errors();
}

/* What a connection reports before any handshake. */
static void getters(SSL *x)
{
    const unsigned char *p = (const unsigned char *)"x";
    unsigned int n = 99;
    const char *name = NULL;
    int nid = 99, sign = 99, hash = 99, sighash = 99;
    unsigned char rsig = 99, rhash = 99;
    EVP_PKEY *k = NULL;

    check(SSL_get_current_cipher(x) == NULL, "no current cipher");
    check(SSL_get_pending_cipher(x) == NULL, "no pending cipher");
    check(SSL_get0_peer_certificate(x) == NULL && SSL_get1_peer_certificate(x) == NULL, "no peer certificate");
    check(SSL_get_peer_cert_chain(x) == NULL, "no peer chain");
    check(SSL_get0_verified_chain(x) == NULL, "no verified chain");
    SSL_get0_alpn_selected(x, &p, &n);
    check(p == NULL && n == 0, "no ALPN protocol");
    check(SSL_pending(x) == 0 && SSL_has_pending(x) == 0, "nothing pending");
    check(SSL_get_early_data_status(x) == SSL_EARLY_DATA_NOT_SENT, "early data not sent");
    check(SSL_get_peer_signature_type_nid(x, &nid) == 0 && nid == 99, "no peer signature type");
    check(SSL_get_signature_type_nid(x, &nid) == 0 && nid == 99, "no signature type");
    check(SSL_get_peer_signature_nid(x, &nid) == 0 && nid == 99, "no peer signature hash");
    check(SSL_get_signature_nid(x, &nid) == 0 && nid == 99, "no signature hash");
    check(SSL_get0_peer_signature_name(x, &name) == 0 && name == NULL, "no peer signature name");
    check(SSL_get0_signature_name(x, &name) == 0 && name == NULL, "no signature name");
    check(SSL_get_sigalgs(x, -1, NULL, NULL, NULL, NULL, NULL) == 0, "no peer signature algorithms");
    check(SSL_get_sigalgs(x, 0, &sign, &hash, &sighash, &rsig, &rhash) == 0 && sign == 99 && rsig == 99,
        "entry 0 of none");
    check(SSL_get_shared_sigalgs(x, -1, NULL, NULL, NULL, NULL, NULL) == 0, "no shared signature algorithms");
    check(SSL_get_shared_sigalgs(x, 0, &sign, &hash, &sighash, &rsig, &rhash) == 0 && sign == 99,
        "shared entry 0 of none");
    printf("  negotiated group %d, extms %ld\n", (int)SSL_get_negotiated_group(x), (long)SSL_get_extms_support(x));
    check(SSL_get_peer_tmp_key(x, &k) == 0 && k == NULL, "no peer key share");
    check(SSL_get_error(x, 1) == SSL_ERROR_NONE, "SSL_get_error of a success");
    check(SSL_get_error(x, 0) == SSL_ERROR_SYSCALL, "SSL_get_error of 0 with nothing to say");
    check(SSL_get_error(x, -1) == SSL_ERROR_SYSCALL, "SSL_get_error of -1 with nothing to say");
}

static void test_no_role(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *x = SSL_new(ctx);
    char buf[8];
    size_t n = 7;
    int r;

    printf("# a connection with no role\n");
    getters(x);
    check(SSL_get0_peer_rpk(x) == NULL, "no peer raw public key");
    printf("  cert types: client %d, server %d\n", SSL_get_negotiated_client_cert_type(x),
           SSL_get_negotiated_server_cert_type(x));
    r = SSL_do_handshake(x);
    said("SSL_do_handshake", x, r);
    r = SSL_read(x, buf, sizeof(buf));
    said("SSL_read", x, r);
    r = SSL_peek(x, buf, sizeof(buf));
    said("SSL_peek", x, r);
    r = SSL_write(x, "x", 1);
    said("SSL_write", x, r);
    r = SSL_read_ex(x, buf, sizeof(buf), &n);
    said("SSL_read_ex", x, r);
    printf("  readbytes %zu\n", n);
    r = SSL_peek_ex(x, buf, sizeof(buf), &n);
    said("SSL_peek_ex", x, r);
    r = SSL_write_ex(x, "x", 1, &n);
    said("SSL_write_ex", x, r);
    printf("  written %zu\n", n);
    r = SSL_read(x, buf, -1);
    said("SSL_read of -1", x, r);
    r = SSL_write(x, "x", -1);
    said("SSL_write of -1", x, r);
    r = SSL_shutdown(x);
    said("SSL_shutdown", x, r);
    SSL_free(x);
    SSL_CTX_free(ctx);
}

static void test_roles_before(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *c = SSL_new(ctx), *s = SSL_new(ctx);
    int r;

    printf("# a client and a server before their handshakes\n");
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    getters(c);
    getters(s);
    r = SSL_shutdown(c);
    said("the client's SSL_shutdown", c, r);
    r = SSL_shutdown(s);
    said("the server's SSL_shutdown", s, r);
    SSL_set_quiet_shutdown(c, 1);
    r = SSL_shutdown(c);
    said("quiet, still in init", c, r);
    check(SSL_get_shutdown(c) == 0, "no shutdown flags");
    check(SSL_clear(c) == 1 && SSL_clear(s) == 1, "SSL_clear");
    check(SSL_in_before(c) && SSL_in_init(c), "still before the handshake");
    getters(c);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void test_error_queue(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *x = SSL_new(ctx);

    printf("# SSL_get_error and the error queue\n");
    ERR_raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH);
    check(SSL_get_error(x, -1) == SSL_ERROR_SSL, "an SSL error first");
    check(SSL_get_error(x, 1) == SSL_ERROR_NONE, "success wins over the queue");
    ERR_clear_error();
    ERR_raise(ERR_LIB_SYS, 104);
    check(SSL_get_error(x, 0) == SSL_ERROR_SYSCALL, "a system error is SSL_ERROR_SYSCALL");
    ERR_clear_error();
    ERR_raise(ERR_LIB_EVP, 1);
    check(SSL_get_error(x, 0) == SSL_ERROR_SSL, "another library's error is SSL_ERROR_SSL");
    ERR_clear_error();
    SSL_set_shutdown(x, SSL_RECEIVED_SHUTDOWN);
    check(SSL_get_error(x, 0) == SSL_ERROR_ZERO_RETURN, "RECEIVED (the last warning alert starts as 0, close_notify)");
    check(SSL_get_error(NULL, 1) == SSL_ERROR_NONE, "NULL with success");
    SSL_free(x);
    SSL_CTX_free(ctx);
}

static void test_strings(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *c = SSL_new(ctx), *s = SSL_new(ctx);
    int v;

    printf("# state and alert names\n");
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    printf("  client: %s (%s)\n", SSL_state_string_long(c), SSL_state_string(c));
    printf("  server: %s (%s)\n", SSL_state_string_long(s), SSL_state_string(s));
    for (v = 0; v < 4; v++)
        printf("  level %d: %s %s\n", v, SSL_alert_type_string(v << 8), SSL_alert_type_string_long(v << 8));
    printf("  level -1: %s %s\n", SSL_alert_type_string(-1), SSL_alert_type_string_long(-1));
    for (v = 0; v < 256; v++) {
        const char *a = SSL_alert_desc_string(v), *b = SSL_alert_desc_string_long(v);

        if (strcmp(a, "UK") != 0 || strcmp(b, "unknown") != 0)
            printf("  alert %d: %s %s\n", v, a, b);
    }
    printf("  alert 116 / 0x228 / -1: %s %s / %s / %s\n", SSL_alert_desc_string(116),
        SSL_alert_desc_string_long(116), SSL_alert_desc_string_long(0x228), SSL_alert_desc_string(-1));
    {
        static const int ids[] = { NID_X9_62_prime256v1, NID_secp384r1, NID_X25519, NID_X448,
            NID_ffdhe2048, TLSEXT_nid_unknown | 0x11ec, TLSEXT_nid_unknown | 0x1d,
            TLSEXT_nid_unknown | 0x9999, NID_undef, NID_sha256 };
        size_t i;

        for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            const char *n = SSL_group_to_name(c, ids[i]);

            printf("  group %#x: %s\n", (unsigned)ids[i], n == NULL ? "(NULL)" : n);
        }
        check(SSL_group_to_name(c, NID_X25519) == SSL_group_to_name(c, NID_X25519), "the same name twice");
    }
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(ctx);
}

/* SSL_select_next_proto's result, the offset into whichever list it points to, and the length. */
static void select_one(const char *what, const char *srv, unsigned int sn, const char *cli, unsigned int cn)
{
    unsigned char *out = (unsigned char *)"?";
    unsigned char outlen = 99;
    int r = SSL_select_next_proto(&out, &outlen, (const unsigned char *)srv, sn, (const unsigned char *)cli, cn);
    const char *where = out == NULL ? "NULL"
        : (out >= (unsigned char *)srv && out < (unsigned char *)srv + sn) ? "server"
        : (out >= (unsigned char *)cli && out < (unsigned char *)cli + cn) ? "client" : "elsewhere";

    printf("  %s: %d, %s", what, r, where);
    if (out != NULL)
        printf(" \"%.*s\"", (int)outlen, (const char *)out);
    printf(" (%u)\n", outlen);
}

static void test_select_next_proto(void)
{
    printf("# SSL_select_next_proto\n");
    select_one("overlap", "\x02h2\x08http/1.1", 12, "\x08http/1.1\x02h2", 12);
    select_one("the server's order", "\x08http/1.1\x02h2", 12, "\x02h2\x08http/1.1", 12);
    select_one("no overlap", "\x03" "foo", 4, "\x02h2\x03" "bar", 7);
    select_one("empty client list", "\x02h2", 3, "", 0);
    select_one("an empty first client entry", "\x02h2", 3, "\x00\x02h2", 4);
    select_one("a client entry too long", "\x02h2", 3, "\x05h2", 3);
    select_one("an empty server entry is skipped", "\x00\x02h2", 4, "\x02h2", 3);
    select_one("trailing octets", "\x02h2\x09", 4, "\x02h2\x07", 4);
    select_one("empty server list", "", 0, "\x02h2", 3);
    select_one("a later client entry", "\x03" "bar", 4, "\x02h2\x03" "bar", 7);
}

int main(void)
{
    test_no_role();
    test_roles_before();
    test_error_queue();
    test_strings();
    test_select_next_proto();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
