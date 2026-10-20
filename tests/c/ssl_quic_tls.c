/*
 * Conformance test for the third-party QUIC stack API (SSL_set_quic_tls_cbs(3),
 * SSL_set_quic_tls_transport_params, SSL_set_quic_tls_early_data_enabled): two TLS SSL objects
 * run a TLS 1.3 handshake through the six callbacks, the way a QUIC stack drives libssl, with
 * the test carrying the CRYPTO data between them by protection level. It prints what both
 * libraries must agree on: the handshake messages each crypto_send call carries and at which
 * level, the secrets yielded (levels, directions, lengths, and whether the two ends agree), the
 * transport parameters each end receives, the alerts, and the error queue's codes. Also: the
 * argument checks, the options and BIOs a QUIC TLS object gets, a got_transport_params or
 * yield_secret callback that fails, a CCM suite, a peer's KeyUpdate, partial crypto_send
 * consumption, NewSessionTickets after the handshake, resumption, and early data.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

/* The queue's codes, oldest first, then empty (no texts: they carry file names and data). */
static void errors(const char *who)
{
    unsigned long e;

    printf("  %s errors:", who);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/* A self-signed Ed25519 certificate for a new key (its signatures, so the handshake's messages,
 * have a fixed size). */
static X509 *ed_cert(EVP_PKEY **pk)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    *pk = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"quic", -1, -1, 0);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 11);
    X509_set_version(x, X509_VERSION_3);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, n);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, *pk);
    X509_sign(x, *pk, NULL);
    X509_NAME_free(n);
    return x;
}

static X509 *cert;
static EVP_PKEY *key;

static const char *level_name(int l)
{
    switch (l) {
    case OSSL_RECORD_PROTECTION_LEVEL_NONE:
        return "initial";
    case OSSL_RECORD_PROTECTION_LEVEL_EARLY:
        return "early";
    case OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE:
        return "handshake";
    case OSSL_RECORD_PROTECTION_LEVEL_APPLICATION:
        return "application";
    }
    return "?";
}

static const char *msg_name(int t)
{
    switch (t) {
    case 1:
        return "ClientHello";
    case 2:
        return "ServerHello";
    case 4:
        return "NewSessionTicket";
    case 5:
        return "EndOfEarlyData";
    case 8:
        return "EncryptedExtensions";
    case 11:
        return "Certificate";
    case 13:
        return "CertificateRequest";
    case 15:
        return "CertificateVerify";
    case 20:
        return "Finished";
    case 24:
        return "KeyUpdate";
    }
    return "?";
}

#define LEVELS 4
#define BUFSZ 65536

/* One end: its SSL, the levels it reads and writes at (from yield_secret), what the peer sent
 * it per level (and how much of that it has taken), the secrets it was given, and its knobs. */
struct end {
    const char *name;
    SSL *ssl;
    struct end *peer;
    int rlevel, wlevel;
    unsigned char in[LEVELS][BUFSZ];
    size_t in_len[LEVELS], in_off[LEVELS];
    size_t lent; /* what crypto_recv_rcd handed out and isn't released yet */
    unsigned char secret[2][LEVELS][64];
    size_t secret_len[2][LEVELS];
    size_t send_limit; /* crypto_send consumes at most this much (0: all) */
    int fail_params, fail_yield_at; /* fail_yield_at: a level + 1, or 0 */
    int quiet; /* don't print the callbacks */
    int alerts;
};

/* The handshake messages in a buffer, by name (a message split across calls shows as "+"). */
static void print_msgs(const unsigned char *b, size_t n)
{
    size_t at = 0;

    while (at + 4 <= n) {
        size_t len = ((size_t)b[at + 1] << 16) | ((size_t)b[at + 2] << 8) | b[at + 3];

        printf(" %s", msg_name(b[at]));
        at += 4 + len;
    }
    if (at != n)
        printf(" +");
}

static int crypto_send(SSL *s, const unsigned char *buf, size_t len, size_t *consumed, void *arg)
{
    struct end *e = arg;
    struct end *p = e->peer;
    size_t n = len;

    if (e->send_limit != 0 && n > e->send_limit)
        n = e->send_limit;
    if (s != e->ssl || p->in_len[e->wlevel] + n > BUFSZ)
        return 0;
    memcpy(p->in[e->wlevel] + p->in_len[e->wlevel], buf, n);
    p->in_len[e->wlevel] += n;
    *consumed = n;
    if (!e->quiet) {
        printf("    %s send %s:", e->name, level_name(e->wlevel));
        if (e->send_limit != 0)
            printf(" %s %zu of %zu", n == len ? "all" : "part", n, len);
        else
            print_msgs(buf, len);
        printf("\n");
    }
    return 1;
}

static int crypto_recv_rcd(SSL *s, const unsigned char **buf, size_t *bytes_read, void *arg)
{
    struct end *e = arg;
    int l = e->rlevel;

    if (s != e->ssl || e->lent != 0)
        return 0;
    *buf = e->in[l] + e->in_off[l];
    *bytes_read = e->in_len[l] - e->in_off[l];
    e->lent = *bytes_read;
    return 1;
}

static int crypto_release_rcd(SSL *s, size_t bytes_read, void *arg)
{
    struct end *e = arg;

    if (s != e->ssl || bytes_read != e->lent)
        return 0;
    e->in_off[e->rlevel] += bytes_read;
    e->lent = 0;
    return 1;
}

static int yield_secret(SSL *s, uint32_t level, int direction, const unsigned char *secret,
                        size_t len, void *arg)
{
    struct end *e = arg;

    if (s != e->ssl || level >= LEVELS || (direction != 0 && direction != 1) || len > 64)
        return 0;
    if (!e->quiet)
        printf("    %s yield %s %s (%zu)\n", e->name, level_name((int)level),
               direction ? "write" : "read", len);
    if (e->fail_yield_at == (int)level + 1)
        return 0;
    memcpy(e->secret[direction][level], secret, len);
    e->secret_len[direction][level] = len;
    if (direction)
        e->wlevel = (int)level;
    else
        e->rlevel = (int)level;
    return 1;
}

static int got_transport_params(SSL *s, const unsigned char *params, size_t len, void *arg)
{
    struct end *e = arg;

    if (s != e->ssl)
        return 0;
    if (!e->quiet)
        printf("    %s got params \"%.*s\"\n", e->name, (int)len, params);
    return !e->fail_params;
}

static int alert(SSL *s, unsigned char code, void *arg)
{
    struct end *e = arg;

    if (s != e->ssl)
        return 0;
    e->alerts++;
    printf("    %s alert %d\n", e->name, code);
    return 1;
}

static const OSSL_DISPATCH fns[] = {
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))crypto_send },
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))crypto_recv_rcd },
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, (void (*)(void))crypto_release_rcd },
    { OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, (void (*)(void))yield_secret },
    { OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))got_transport_params },
    { OSSL_FUNC_SSL_QUIC_TLS_ALERT, (void (*)(void))alert },
    OSSL_DISPATCH_END
};

static const unsigned char alpn[] = { 2, 'h', '3' };

static int select_alpn(SSL *s, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)s;
    (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn, sizeof(alpn), in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    return SSL_TLSEXT_ERR_OK;
}

/* The client's last session. */
static SSL_SESSION *kept;

static int new_session(SSL *s, SSL_SESSION *sess)
{
    (void)s;
    SSL_SESSION_free(kept);
    kept = sess;
    return 1;
}

static SSL_CTX *server_ctx(void)
{
    SSL_CTX *c = SSL_CTX_new(TLS_server_method());

    SSL_CTX_use_certificate(c, cert);
    SSL_CTX_use_PrivateKey(c, key);
    SSL_CTX_set_alpn_select_cb(c, select_alpn, NULL);
    return c;
}

static SSL_CTX *client_ctx(void)
{
    SSL_CTX *c = SSL_CTX_new(TLS_client_method());

    SSL_CTX_set_alpn_protos(c, alpn, sizeof(alpn));
    SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(c, new_session);
    return c;
}

/* Two ends with callbacks and transport parameters set (the server's if `sparams`). */
static void ends(struct end *c, struct end *s, SSL_CTX *cctx, SSL_CTX *sctx, int sparams)
{
    memset(c, 0, sizeof(*c));
    memset(s, 0, sizeof(*s));
    c->name = "client";
    s->name = "server";
    c->peer = s;
    s->peer = c;
    c->ssl = SSL_new(cctx);
    s->ssl = SSL_new(sctx);
    SSL_set_connect_state(c->ssl);
    SSL_set_accept_state(s->ssl);
    if (!SSL_set_quic_tls_cbs(c->ssl, fns, c) || !SSL_set_quic_tls_cbs(s->ssl, fns, s))
        printf("  set_quic_tls_cbs failed\n");
    SSL_set_quic_tls_transport_params(c->ssl, (const unsigned char *)"client tp", 9);
    if (sparams)
        SSL_set_quic_tls_transport_params(s->ssl, (const unsigned char *)"server tp", 9);
}

/* Freed as after a QUIC CONNECTION_CLOSE: shut down, or the client's session is dropped. */
static void free_ends(struct end *c, struct end *s)
{
    SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(s->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_free(c->ssl);
    SSL_free(s->ssl);
}

/* One handshake step of `e`: its return and error, printed when it isn't a want-read. */
static int step(struct end *e)
{
    int r = SSL_do_handshake(e->ssl);
    int err = r == 1 ? SSL_ERROR_NONE : SSL_get_error(e->ssl, r);

    if (r != 1 && err != SSL_ERROR_WANT_READ) {
        printf("  %s do_handshake %d, error %d\n", e->name, r, err);
        errors(e->name);
    }
    return r == 1 ? 1 : err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ? 0 : -1;
}

/* Steps both ends until both finish or one fails (or nothing moves); 1 when both finished. */
static int handshake(struct end *c, struct end *s)
{
    int i;

    /* SSL_do_handshake can return 1 before the handshake is over (a server that accepts early
     * data, after its Finished; a client with early data, after its ClientHello). */
    for (i = 0; i < 40; i++) {
        if (step(c) < 0 || step(s) < 0)
            return 0;
        if (SSL_is_init_finished(c->ssl) && SSL_is_init_finished(s->ssl))
            return 1;
    }
    return 0;
}

/* Whether both ends were given the same secrets at every level (and how many there were). */
static void agree(struct end *c, struct end *s)
{
    int l, n = 0, same = 1;

    for (l = 0; l < LEVELS; l++) {
        if (c->secret_len[1][l] != 0 || s->secret_len[0][l] != 0) {
            n++;
            same &= c->secret_len[1][l] == s->secret_len[0][l]
                && memcmp(c->secret[1][l], s->secret[0][l], c->secret_len[1][l]) == 0;
        }
        if (s->secret_len[1][l] != 0 || c->secret_len[0][l] != 0) {
            n++;
            same &= s->secret_len[1][l] == c->secret_len[0][l]
                && memcmp(s->secret[1][l], c->secret[0][l], s->secret_len[1][l]) == 0;
        }
    }
    printf("  %d secret pairs, %s\n", n, same ? "all the same" : "DIFFERENT");
}

static void negotiated(struct end *e)
{
    const unsigned char *p = NULL;
    unsigned int n = 0;

    SSL_get0_alpn_selected(e->ssl, &p, &n);
    printf("  %s: %s %s, alpn %.*s, reused %d\n", e->name, SSL_get_version(e->ssl),
           SSL_CIPHER_get_name(SSL_get_current_cipher(e->ssl)), (int)n, p != NULL ? (const char *)p : "",
           SSL_session_reused(e->ssl));
}

/* Post-handshake: `e` reads what it was sent (a ticket, a KeyUpdate): the read's result. */
static void post(struct end *e)
{
    unsigned char b[16];
    size_t n = 0;
    int r = SSL_read_ex(e->ssl, b, sizeof(b), &n);

    printf("  %s read %d, error %d\n", e->name, r, SSL_get_error(e->ssl, r));
    errors(e->name);
}

static void test_arguments(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *s = SSL_new(ctx);
    static const OSSL_DISPATCH partial[] = {
        { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))crypto_send },
        { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))crypto_recv_rcd },
        OSSL_DISPATCH_END
    };
    struct end e;
    BIO *r, *w;

    printf("# arguments\n");
    memset(&e, 0, sizeof(e));
    e.ssl = s;
    ERR_clear_error();
    check(SSL_set_quic_tls_transport_params(s, (const unsigned char *)"x", 1) == 0,
          "transport params before the callbacks fail");
    errors("params");
    check(SSL_set_quic_tls_early_data_enabled(s, 1) == 0, "early data before the callbacks fails");
    errors("early");
    check(SSL_set_quic_tls_cbs(s, partial, &e) == 0, "a table without every function fails");
    errors("partial");
    printf("  options before: middlebox %d\n",
           (SSL_get_options(s) & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0);
    check(SSL_set_quic_tls_cbs(s, fns, &e) == 1, "the full table");
    errors("full");
    printf("  options after: middlebox %d, min version %ld\n",
           (SSL_get_options(s) & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0,
           SSL_get_min_proto_version(s));
    r = SSL_get_rbio(s);
    w = SSL_get_wbio(s);
    printf("  bios: %d %d, same %d, null %d\n", r != NULL, w != NULL, r == w,
           r != NULL && BIO_method_type(r) == BIO_TYPE_NULL);
    check(SSL_set_quic_tls_transport_params(s, (const unsigned char *)"x", 1) == 1,
          "transport params after the callbacks");
    check(SSL_set_quic_tls_early_data_enabled(s, 0) == 1, "early data off");
    check(SSL_set_quic_tls_early_data_enabled(s, 1) == 0,
          "early data on, for a client with no session that allows it, fails");
    errors("early on");
    /* The transport parameters extension is registered once per SSL, so a second table is
     * refused (and on the reference the SSL isn't usable after that). */
    check(SSL_set_quic_tls_cbs(s, fns, &e) == 0, "the callbacks again fail");
    errors("again");
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void test_handshake(const char *suite, size_t limit)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    struct end *c = calloc(1, sizeof(*c)), *s = calloc(1, sizeof(*s));
    int ok;

    printf("# handshake %s%s\n", suite, limit ? ", crypto_send takes 100 octets at a time" : "");
    SSL_CTX_set_ciphersuites(cctx, suite);
    SSL_CTX_set_ciphersuites(sctx, suite);
    ends(c, s, cctx, sctx, 1);
    c->send_limit = s->send_limit = limit;
    ok = handshake(c, s);
    check(ok, "the handshake completes");
    agree(c, s);
    negotiated(c);
    negotiated(s);
    printf("  alerts %d %d\n", c->alerts, s->alerts);
    if (ok && !limit) {
        printf("  tickets:\n");
        post(c);
        printf("  KeyUpdate from the client:\n");
        check(SSL_key_update(c->ssl, SSL_KEY_UPDATE_NOT_REQUESTED) == 1, "SSL_key_update");
        step(c);
        post(c);
        post(s);
    }
    free_ends(c, s);
    free(c);
    free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_failures(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    struct end *c = calloc(1, sizeof(*c)), *s = calloc(1, sizeof(*s));

    printf("# the server's got_transport_params fails\n");
    ends(c, s, cctx, sctx, 1);
    s->fail_params = 1;
    check(!handshake(c, s), "the handshake fails");
    free_ends(c, s);

    printf("# the client's got_transport_params fails\n");
    ends(c, s, cctx, sctx, 1);
    c->fail_params = 1;
    check(!handshake(c, s), "the handshake fails");
    free_ends(c, s);

    printf("# the server's handshake yield_secret fails\n");
    ends(c, s, cctx, sctx, 1);
    s->fail_yield_at = OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE + 1;
    check(!handshake(c, s), "the handshake fails");
    free_ends(c, s);

    printf("# the client's application yield_secret fails\n");
    ends(c, s, cctx, sctx, 1);
    c->fail_yield_at = OSSL_RECORD_PROTECTION_LEVEL_APPLICATION + 1;
    check(!handshake(c, s), "the handshake fails");
    free_ends(c, s);

    printf("# the server sets no transport parameters\n");
    ends(c, s, cctx, sctx, 0);
    check(handshake(c, s), "the handshake completes");
    free_ends(c, s);

    free(c);
    free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/* The client's message callback: what it reports, the record headers' octets included. */
static void on_msg(int write_p, int version, int content_type, const void *buf, size_t len,
                   SSL *ssl, void *arg)
{
    const unsigned char *b = buf;
    size_t i;

    (void)ssl;
    (void)arg;
    printf("    msg %s %x %d:", write_p ? "write" : "read", version, content_type);
    if (content_type == SSL3_RT_HANDSHAKE)
        printf(" %s", len > 0 ? msg_name(b[0]) : "-");
    else
        for (i = 0; i < len; i++)
            printf(" %02x", b[i]);
    printf("\n");
}

static void test_others(void)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = server_ctx();
    struct end *c = calloc(1, sizeof(*c)), *s = calloc(1, sizeof(*s));
    int r;

    /* ALPN is the QUIC stack's business here (OpenSSL's own QUIC requires it). */
    printf("# no ALPN, with the client's message callback, then SSL_shutdown\n");
    ends(c, s, cctx, sctx, 1);
    c->quiet = 1;
    SSL_set_msg_callback(c->ssl, on_msg);
    check(handshake(c, s), "the handshake completes");
    negotiated(c);
    SSL_set_msg_callback(c->ssl, NULL);
    r = SSL_shutdown(c->ssl);
    printf("  client shutdown %d, error %d\n", r, SSL_get_error(c->ssl, r));
    errors("client");
    free_ends(c, s);

    free(c);
    free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/* A full handshake that leaves a ticket in `kept` (the server's early data on if `early`). */
static void first(struct end *c, struct end *s, SSL_CTX *cctx, SSL_CTX *sctx, int early)
{
    SSL_SESSION_free(kept);
    kept = NULL;
    ends(c, s, cctx, sctx, 1);
    if (early)
        check(SSL_set_quic_tls_early_data_enabled(s->ssl, 1) == 1, "the server's early data on");
    check(handshake(c, s), "the first handshake completes");
    post(c);
    check(kept != NULL, "a session was kept");
    if (kept != NULL)
        printf("  the session's max_early_data %u\n", SSL_SESSION_get_max_early_data(kept));
    free_ends(c, s);
}

static void test_resumption(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    struct end *c = calloc(1, sizeof(*c)), *s = calloc(1, sizeof(*s));

    printf("# a session\n");
    first(c, s, cctx, sctx, 0);
    printf("# resumption\n");
    ends(c, s, cctx, sctx, 1);
    SSL_set_session(c->ssl, kept);
    check(handshake(c, s), "the handshake completes");
    agree(c, s);
    negotiated(c);
    negotiated(s);
    free_ends(c, s);

    printf("# a session, with the server's early data on\n");
    first(c, s, cctx, sctx, 1);
    printf("# resumption with early data\n");
    ends(c, s, cctx, sctx, 1);
    SSL_set_session(c->ssl, kept);
    check(SSL_set_quic_tls_early_data_enabled(s->ssl, 1) == 1, "the server's early data on");
    check(SSL_set_quic_tls_early_data_enabled(c->ssl, 1) == 1, "the client's early data on");
    check(handshake(c, s), "the handshake completes");
    agree(c, s);
    negotiated(c);
    negotiated(s);
    printf("  early data: client %d, server %d\n", SSL_get_early_data_status(c->ssl),
           SSL_get_early_data_status(s->ssl));
    free_ends(c, s);

    free(c);
    free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    cert = ed_cert(&key);
    test_arguments();
    test_handshake("TLS_AES_128_GCM_SHA256", 0);
    test_handshake("TLS_CHACHA20_POLY1305_SHA256", 0);
    test_handshake("TLS_AES_128_CCM_SHA256", 0);
    test_handshake("TLS_AES_256_GCM_SHA384", 100);
    test_failures();
    test_resumption();
    test_others();
    SSL_SESSION_free(kept);
    X509_free(cert);
    EVP_PKEY_free(key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
