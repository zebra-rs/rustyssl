/*
 * Conformance test for the ticket key callbacks (SSL_CTX_set_tlsext_ticket_key_evp_cb(3), and
 * the deprecated SSL_CTX_set_tlsext_ticket_key_cb(3) with an HMAC_CTX): the server's callback
 * sets up the cipher and HMAC contexts that seal and open its tickets, in TLS 1.3 and 1.2,
 * with AES-128-CBC or AES-256-CBC and HMAC with SHA-256 or SHA-512; its verdicts (use, renew,
 * no ticket, failure) when making and when opening a ticket; a ticket whose HMAC doesn't check.
 *
 * Only deterministic output is printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
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

/* Prints and clears the error queue: library/reason. */
static void errors(void)
{
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBmzCCAUCgAwIBAgIUHfTNPsE5lGD3nT8fR1Nd24C0BsgwCgYIKoZIzj0EAwIw\n"
    "KjEQMA4GA1UECgwHRXhhbXBsZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0y\n"
    "NjEwMTgwOTMyNDZaGA8yMTI2MDkyNDA5MzI0NlowKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
    "A0IABLfBhwdOVIbIOwWlwBUmASMV1CS8SOnPi/viY8J5Ml2EwP5wOJe2mtSxgMlo\n"
    "COh/RepmP8BAKwLO40zMoIv99xOjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n"
    "AQH/BAQDAgEGMB0GA1UdDgQWBBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjO\n"
    "PQQDAgNJADBGAiEA8n+eFk52ddsEdBxGgskm6aD0for7v4Ys0o0bN2t9wq8CIQDY\n"
    "V8DuzBptykbkta8E/bbLFVRo0LjIzjF/bGH+iqEMeA==\n"
    "-----END CERTIFICATE-----\n";

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

/* A client context that trusts the test root and checks the server's certificate. */
static SSL_CTX *client_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    X509 *ca = cert(CA_PEM);

    if (ctx == NULL || ca == NULL || X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca) != 1) {
        printf("Bail out! client context\n");
        exit(1);
    }
    X509_free(ca);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

static int new_sessions = 0;
static SSL_SESSION *last_session = NULL;

static int new_session_cb(SSL *s, SSL_SESSION *sess)
{
    (void)s;
    new_sessions++;
    SSL_SESSION_free(last_session);
    last_session = sess;
    return 1;
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

/* The client reads what the server sent after the handshake (tickets). */
static void drain(SSL *c)
{
    char buf[8];
    size_t n;

    SSL_read_ex(c, buf, sizeof(buf), &n);
    ERR_clear_error();
}

/* Frees both ends after close_notify (a session isn't spoiled by an unclean end). */
static void done(SSL *c, SSL *s)
{
    SSL_shutdown(c);
    SSL_shutdown(s);
    ERR_clear_error();
    SSL_free(c);
    SSL_free(s);
}


/* What the server's callback does: its cipher and digest, its answers, and its HMAC key. */
static const char *cipher_name = "AES-256-CBC", *digest_name = "SHA256";
static int enc_ret = 1, dec_ret = 1, enc_calls = 0, dec_calls = 0, other_hmac_key = 0;

static const unsigned char aes_key[32] = "0123456789abcdef0123456789abcde";

static const unsigned char *hmac_key(int enc)
{
    static const unsigned char a[32] = "hmac-key-hmac-key-hmac-key-hmac";
    static const unsigned char b[32] = "another-hmac-key-another-hmac-k";

    return !enc && other_hmac_key ? b : a;
}

/* The key name and IV a new ticket gets. */
static void name_iv(unsigned char *name, unsigned char *iv)
{
    memset(name, 'n', 16);
    memset(iv, 'i', EVP_MAX_IV_LENGTH);
}

static int evp_cb(SSL *s, unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ctx,
                  EVP_MAC_CTX *hctx, int enc)
{
    OSSL_PARAM params[2];
    EVP_CIPHER *c;
    int ok;

    (void)s;
    if (enc) {
        enc_calls++;
        if (enc_ret <= 0)
            return enc_ret;
        name_iv(name, iv);
    } else {
        dec_calls++;
        printf("  open: key name %s\n", memcmp(name, "nnnnnnnnnnnnnnnn", 16) == 0 ? "ours" : "other");
        if (dec_ret <= 0)
            return dec_ret;
    }
    c = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)digest_name, 0);
    params[1] = OSSL_PARAM_construct_end();
    ok = c != NULL && EVP_CipherInit_ex(ctx, c, NULL, aes_key, iv, enc) == 1
         && EVP_MAC_init(hctx, hmac_key(enc), 32, params) == 1;
    EVP_CIPHER_free(c);
    return ok ? (enc ? enc_ret : dec_ret) : -1;
}

static int legacy_cb(SSL *s, unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ctx,
                     HMAC_CTX *hctx, int enc)
{
    EVP_CIPHER *c;
    EVP_MD *md;
    int ok;

    (void)s;
    if (enc) {
        enc_calls++;
        if (enc_ret <= 0)
            return enc_ret;
        name_iv(name, iv);
    } else {
        dec_calls++;
        if (dec_ret <= 0)
            return dec_ret;
    }
    c = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
    md = EVP_MD_fetch(NULL, digest_name, NULL);
    ok = c != NULL && md != NULL && EVP_CipherInit_ex(ctx, c, NULL, aes_key, iv, enc) == 1
         && HMAC_Init_ex(hctx, hmac_key(enc), 32, md, NULL) == 1;
    EVP_CIPHER_free(c);
    EVP_MD_free(md);
    return ok ? (enc ? enc_ret : dec_ret) : -1;
}

/* A full handshake and its client session (NULL if it failed or got none). */
static SSL_SESSION *full(SSL_CTX *cctx, SSL_CTX *sctx, int version)
{
    SSL *c, *s;
    SSL_SESSION *sess = NULL;
    int r;

    new_sessions = 0;
    enc_calls = dec_calls = 0;
    SSL_SESSION_free(last_session);
    last_session = NULL;
    r = connect_pair(cctx, sctx, &c, &s, NULL, version);
    printf("  full handshake %d\n", r);
    if (r == 0) {
        drain(c);
        sess = last_session;
        printf("  new sessions %d, ticket %d, callback made %d, opened %d\n", new_sessions,
               sess != NULL ? SSL_SESSION_has_ticket(sess) : -1, enc_calls, dec_calls);
        if (sess != NULL)
            SSL_SESSION_up_ref(sess);
    }
    errors();
    done(c, s);
    return sess;
}

static void resume(SSL_CTX *cctx, SSL_CTX *sctx, SSL_SESSION *sess, int version)
{
    SSL *c, *s;
    int r;

    new_sessions = 0;
    enc_calls = dec_calls = 0;
    r = connect_pair(cctx, sctx, &c, &s, sess, version);
    printf("  resumption %d: reused %d\n", r, r == 0 ? SSL_session_reused(c) : -1);
    if (r == 0) {
        drain(c);
        printf("  new sessions %d, callback made %d, opened %d\n", new_sessions, enc_calls,
               dec_calls);
    }
    errors();
    done(c, s);
}

static void run_case(const char *name, int legacy, const char *cipher, const char *digest,
                     int version)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL_SESSION *sess;
    int i;

    printf("# %s, version %x\n", name, version);
    cipher_name = cipher;
    digest_name = digest;
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_sess_set_new_cb(cctx, new_session_cb);
    if (legacy)
        check(SSL_CTX_set_tlsext_ticket_key_cb(sctx, legacy_cb) == 1, "the deprecated callback");
    else
        check(SSL_CTX_set_tlsext_ticket_key_evp_cb(sctx, evp_cb) == 1, "the callback");
    enc_ret = 1;
    for (i = 0; i < 5; i++) {
        static const char *const what[5] = {
            "opened", "renewed", "the callback declines to open it",
            "the callback fails to open it", "the HMAC doesn't check",
        };
        static const int rets[5] = { 1, 2, 0, -1, 1 };

        printf("  -- %s\n", what[i]);
        dec_ret = 1;
        sess = full(cctx, sctx, version);
        check(sess != NULL, "a ticket");
        if (sess == NULL)
            continue;
        dec_ret = rets[i];
        other_hmac_key = i == 4;
        resume(cctx, sctx, sess, version);
        other_hmac_key = 0;
        SSL_SESSION_free(sess);
    }
    printf("  -- no ticket made\n");
    enc_ret = 0;
    SSL_SESSION_free(full(cctx, sctx, version));
    printf("  -- making one fails\n");
    enc_ret = -1;
    SSL_SESSION_free(full(cctx, sctx, version));
    enc_ret = 1;
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    static const int versions[2] = { TLS1_3_VERSION, TLS1_2_VERSION };
    int i;

    for (i = 0; i < 2; i++) {
        run_case("AES-256-CBC, HMAC-SHA256", 0, "AES-256-CBC", "SHA256", versions[i]);
        run_case("AES-128-CBC, HMAC-SHA512", 0, "AES-128-CBC", "SHA512", versions[i]);
        run_case("deprecated callback, AES-128-CBC, HMAC-SHA256", 1, "AES-128-CBC", "SHA256",
                 versions[i]);
    }
    SSL_SESSION_free(last_session);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
