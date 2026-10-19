/*
 * Conformance test for the PSK callbacks: TLS 1.3's session callbacks
 * (SSL_CTX_set_psk_use_session_callback(3), SSL_CTX_set_psk_find_session_callback(3)) with
 * SHA-256 and SHA-384 sessions, after a HelloRetryRequest (the digest the client's callback
 * gets), failing callbacks and unknown identities, and early data under an external PSK; the
 * TLS 1.2-style callbacks (SSL_CTX_set_psk_client_callback(3),
 * SSL_CTX_set_psk_server_callback(3)) in TLS 1.3 and with TLS 1.2 PSK suites, with and without
 * an identity hint (SSL_CTX_use_psk_identity_hint(3)), over a BIO pair.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* A connection pair over a BIO pair, run to the end of both handshakes: 0, or the error. */
static int connect_pair(SSL_CTX *cctx, SSL_CTX *sctx, SSL **pc, SSL **ps, SSL_SESSION *sess,
                        int version)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    int cdone = 0, sdone = 0, round;

    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_set_max_proto_version(c, version);
    if (sess != NULL)
        SSL_set_session(c, sess);
    *pc = c;
    *ps = s;
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
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                return e;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}


/* Prints and clears the error queue: library/reason. */
static void errors(const char *who)
{
    unsigned long e;

    printf("  %s errors:", who);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static const unsigned char psk_key[48] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
static const char *identity = "client-identity", *server_identity = "client-identity";
static SSL_SESSION *psk_sess;
static int use_calls, find_calls, use_ret = 1, find_ret = 1, client_calls, server_calls;
static char seen_hint[64], seen_identity[64];
static unsigned int client_len = 32;

/* A TLS 1.3 PSK session for a SHA-256 or SHA-384 suite. */
static SSL_SESSION *make_psk(SSL *s, int sha384, uint32_t max_early)
{
    const unsigned char aes128[] = { 0x13, 0x01 }, aes256[] = { 0x13, 0x02 };
    SSL_SESSION *sess = SSL_SESSION_new();

    SSL_SESSION_set1_master_key(sess, psk_key, sha384 ? 48 : 32);
    SSL_SESSION_set_cipher(sess, SSL_CIPHER_find(s, sha384 ? aes256 : aes128));
    SSL_SESSION_set_protocol_version(sess, TLS1_3_VERSION);
    SSL_SESSION_set_max_early_data(sess, max_early);
    return sess;
}

static int use_cb(SSL *s, const EVP_MD *md, const unsigned char **id, size_t *idlen,
                  SSL_SESSION **sess)
{
    (void)s;
    use_calls++;
    printf("  use_session_cb #%d: digest %s\n", use_calls,
           md == NULL ? "NULL" : EVP_MD_get0_name(md));
    if (psk_sess != NULL)
        SSL_SESSION_up_ref(psk_sess);
    *sess = psk_sess;
    *id = (const unsigned char *)identity;
    *idlen = strlen(identity);
    return use_ret;
}

static int find_cb(SSL *s, const unsigned char *id, size_t idlen, SSL_SESSION **sess)
{
    (void)s;
    find_calls++;
    printf("  find_session_cb #%d: identity \"%.*s\"\n", find_calls, (int)idlen,
           (const char *)id);
    *sess = NULL;
    if (idlen == strlen(server_identity) && memcmp(id, server_identity, idlen) == 0
        && psk_sess != NULL) {
        SSL_SESSION_up_ref(psk_sess);
        *sess = psk_sess;
    }
    return find_ret;
}

static unsigned int client_cb(SSL *s, const char *hint, char *id, unsigned int max_id,
                              unsigned char *psk, unsigned int max_psk)
{
    (void)s;
    client_calls++;
    snprintf(seen_hint, sizeof(seen_hint), "%s", hint == NULL ? "(NULL)" : hint);
    printf("  psk_client_callback: hint %s, room %u/%u\n", seen_hint, max_id, max_psk);
    if (client_len == 0)
        return 0;
    snprintf(id, max_id, "%s", identity);
    memcpy(psk, psk_key, client_len);
    return client_len;
}

static unsigned int server_cb(SSL *s, const char *id, unsigned char *psk, unsigned int max_psk)
{
    (void)s;
    server_calls++;
    snprintf(seen_identity, sizeof(seen_identity), "%s", id);
    printf("  psk_server_callback: identity \"%s\", room %u\n", id, max_psk);
    if (strcmp(id, server_identity) != 0)
        return 0;
    memcpy(psk, psk_key, 32);
    return 32;
}

static void reset(void)
{
    use_calls = find_calls = client_calls = server_calls = 0;
    use_ret = find_ret = 1;
    client_len = 32;
    server_identity = identity;
}

static void pair(SSL_CTX **cctx, SSL_CTX **sctx, int version)
{
    *cctx = SSL_CTX_new(TLS_client_method());
    *sctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(*cctx, version);
    SSL_CTX_set_max_proto_version(*cctx, version);
    SSL_CTX_set_min_proto_version(*sctx, version);
    SSL_CTX_set_max_proto_version(*sctx, version);
}

static void report(SSL *c, SSL *s)
{
    const SSL_CIPHER *ci = SSL_get_current_cipher(c);

    printf("  reused %d/%d, suite %s, version %s\n", SSL_session_reused(c),
           SSL_session_reused(s), ci != NULL ? SSL_CIPHER_get_name(ci) : "(none)",
           SSL_get_version(c));
}

static void tls13_session(const char *name, int sha384, const char *server_groups)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    int r;

    printf("# %s\n", name);
    reset();
    pair(&cctx, &sctx, TLS1_3_VERSION);
    SSL_CTX_set_psk_use_session_callback(cctx, use_cb);
    SSL_CTX_set_psk_find_session_callback(sctx, find_cb);
    if (!sha384)
        SSL_CTX_set_ciphersuites(sctx, "TLS_AES_128_GCM_SHA256");
    if (server_groups != NULL)
        SSL_CTX_set1_groups_list(sctx, server_groups);
    c = SSL_new(cctx);
    psk_sess = make_psk(c, sha384, 0);
    SSL_free(c);
    r = connect_pair(cctx, sctx, &c, &s, NULL, TLS1_3_VERSION);
    check(r == 0, name);
    report(c, s);
    errors("client");
    SSL_free(c);
    SSL_free(s);
    SSL_SESSION_free(psk_sess);
    psk_sess = NULL;
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void tls13_failure(const char *name, int use, int find, const char *other_identity)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    int r;

    printf("# %s\n", name);
    reset();
    use_ret = use;
    find_ret = find;
    if (other_identity != NULL)
        server_identity = other_identity;
    pair(&cctx, &sctx, TLS1_3_VERSION);
    SSL_CTX_set_psk_use_session_callback(cctx, use_cb);
    SSL_CTX_set_psk_find_session_callback(sctx, find_cb);
    c = SSL_new(cctx);
    psk_sess = make_psk(c, 0, 0);
    SSL_free(c);
    r = connect_pair(cctx, sctx, &c, &s, NULL, TLS1_3_VERSION);
    printf("  handshake %s\n", r == 0 ? "done" : "failed");
    check(1, name);
    if (r == 0)
        report(c, s);
    errors("both");
    SSL_free(c);
    SSL_free(s);
    SSL_SESSION_free(psk_sess);
    psk_sess = NULL;
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void tls13_early(const char *name, int sha384)
{
    SSL_CTX *cctx, *sctx;
    SSL *c = NULL, *s = NULL;
    BIO *a = NULL, *b = NULL;
    unsigned char buf[64];
    size_t w = 0, n = 0;
    int r;

    printf("# %s\n", name);
    reset();
    pair(&cctx, &sctx, TLS1_3_VERSION);
    SSL_CTX_set_psk_use_session_callback(cctx, use_cb);
    SSL_CTX_set_psk_find_session_callback(sctx, find_cb);
    SSL_CTX_set_max_early_data(sctx, 1024);
    if (!sha384)
        SSL_CTX_set_ciphersuites(sctx, "TLS_AES_128_GCM_SHA256");
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    psk_sess = make_psk(c, sha384, 256);
    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    r = SSL_write_early_data(c, "early", 5, &w);
    printf("  SSL_write_early_data %d, %zu written\n", r, w);
    r = SSL_read_early_data(s, buf, sizeof(buf), &n);
    printf("  SSL_read_early_data %d, \"%.*s\", status %d\n", r, (int)n, buf,
           SSL_get_early_data_status(s));
    r = SSL_connect(c);
    printf("  SSL_connect %d, status %d\n", r, SSL_get_early_data_status(c));
    r = SSL_read_early_data(s, buf, sizeof(buf), &n);
    printf("  SSL_read_early_data %d\n", r);
    check(SSL_do_handshake(s) == 1, name);
    report(c, s);
    errors("both");
    SSL_free(c);
    SSL_free(s);
    SSL_SESSION_free(psk_sess);
    psk_sess = NULL;
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void old_style(const char *name, int version, const char *hint, unsigned int len,
                      const char *other_identity)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    int r;

    printf("# %s\n", name);
    reset();
    client_len = len;
    if (other_identity != NULL)
        server_identity = other_identity;
    pair(&cctx, &sctx, version);
    SSL_CTX_set_psk_client_callback(cctx, client_cb);
    SSL_CTX_set_psk_server_callback(sctx, server_cb);
    if (version < TLS1_3_VERSION) {
        SSL_CTX_set_cipher_list(cctx, "PSK-AES128-GCM-SHA256");
        SSL_CTX_set_cipher_list(sctx, "PSK-AES128-GCM-SHA256");
    }
    if (hint != NULL)
        SSL_CTX_use_psk_identity_hint(sctx, hint);
    r = connect_pair(cctx, sctx, &c, &s, NULL, version);
    printf("  handshake %s, client callback %d, server callback %d\n",
           r == 0 ? "done" : "failed", client_calls, server_calls);
    check(1, name);
    if (r == 0)
        report(c, s);
    errors("both");
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    tls13_session("TLS 1.3, an external PSK (SHA-256)", 0, NULL);
    tls13_session("TLS 1.3, an external PSK (SHA-384)", 1, NULL);
    tls13_session("TLS 1.3, an external PSK after a HelloRetryRequest", 0, "P-384");
    tls13_failure("TLS 1.3, the client's callback fails", 0, 1, NULL);
    tls13_failure("TLS 1.3, the server's callback fails", 1, 0, NULL);
    tls13_failure("TLS 1.3, the server doesn't know the identity", 1, 1, "someone else");
    tls13_early("TLS 1.3, early data under an external PSK (SHA-256)", 0);
    tls13_early("TLS 1.3, early data under an external PSK (SHA-384)", 1);
    old_style("TLS 1.3, the TLS 1.2-style callbacks", TLS1_3_VERSION, NULL, 32, NULL);
    old_style("TLS 1.2, PSK with a hint", TLS1_2_VERSION, "server-hint", 32, NULL);
    old_style("TLS 1.2, PSK without a hint", TLS1_2_VERSION, NULL, 32, NULL);
    old_style("TLS 1.2, the client has no key", TLS1_2_VERSION, NULL, 0, NULL);
    old_style("TLS 1.2, the server doesn't know the identity", TLS1_2_VERSION, NULL, 32,
              "someone else");
    /* An empty identity: OpenSSL copies it with OPENSSL_memdup, which is NULL for nothing. */
    identity = "";
    tls13_failure("TLS 1.3, an external PSK with an empty identity", 1, 1, NULL);
    old_style("TLS 1.3, the TLS 1.2-style callback with an empty identity", TLS1_3_VERSION, NULL,
              32, NULL);
    identity = "client-identity";
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
