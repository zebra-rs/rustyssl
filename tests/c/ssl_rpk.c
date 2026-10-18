/*
 * Conformance test for raw public keys in handshakes (RFC 7250; SSL_CTX_set1_server_cert_type(3),
 * SSL_add_expected_rpk(3), SSL_get0_peer_rpk(3), SSL_get_negotiated_server_cert_type(3)):
 * TLS 1.3 and TLS 1.2 handshakes over memory BIOs where the server sends a raw public key (from
 * its certificate, or from a key with no certificate), verified against the client's expected
 * keys (DANE): a match, a mismatch and no expected keys with and without SSL_VERIFY_PEER, the
 * verify callback's X509_STORE_CTX_get0_rpk; a client's raw public key for client
 * authentication; raw public keys offered but X.509 negotiated; and resumption (session IDs and
 * tickets), with the peer's key in the session (SSL_SESSION_get0_peer_rpk) and on the resumed
 * connection.
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
#include <openssl/x509_vfy.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void errors(void)
{
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
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

static const unsigned char RPK_FIRST[] = { TLSEXT_cert_type_rpk, TLSEXT_cert_type_x509 };

static X509 *server_cert;
static EVP_PKEY *server_key, *other_key, *client_key;

/* What a case sets up. */
struct setup {
    const char *what;
    int version;
    int server_rpk, client_rpk;      /* the server and client offer raw public keys */
    int with_cert;                   /* the server has its certificate, not just its key */
    int expect;                      /* 0: no expected key, 1: the server's, 2: another */
    int client_mode;                 /* the client's verify mode */
    int client_auth;                 /* the client authenticates with a raw public key */
    int no_ticket;
};

static int verify_cb(int ok, X509_STORE_CTX *xs)
{
    printf("  verify cb ok=%d error=%d rpk %s cert %s\n", ok, X509_STORE_CTX_get_error(xs),
        X509_STORE_CTX_get0_rpk(xs) != NULL ? "set" : "none",
        X509_STORE_CTX_get_current_cert(xs) != NULL ? "set" : "none");
    return ok;
}

/* Runs both ends' handshakes in turn until both finish (1) or one fails (0). */
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
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                errors();
                return 0;
            }
        }
    }
    return cdone && sdone;
}

static void contexts(const struct setup *t, SSL_CTX **cctx, SSL_CTX **sctx)
{
    *cctx = SSL_CTX_new(TLS_client_method());
    *sctx = SSL_CTX_new(TLS_server_method());
    if (*cctx == NULL || *sctx == NULL) {
        printf("Bail out! contexts\n");
        exit(1);
    }
    SSL_CTX_set_min_proto_version(*cctx, t->version);
    SSL_CTX_set_max_proto_version(*cctx, t->version);
    SSL_CTX_set_min_proto_version(*sctx, t->version);
    SSL_CTX_set_max_proto_version(*sctx, t->version);
    SSL_CTX_set_session_id_context(*sctx, (const unsigned char *)"rpk", 3);
    SSL_CTX_set_session_cache_mode(*cctx, SSL_SESS_CACHE_CLIENT);
    if (t->server_rpk && SSL_CTX_set1_server_cert_type(*sctx, RPK_FIRST, sizeof(RPK_FIRST)) != 1) {
        printf("Bail out! server cert type\n");
        exit(1);
    }
    if (t->client_rpk && SSL_CTX_set1_server_cert_type(*cctx, RPK_FIRST, sizeof(RPK_FIRST)) != 1) {
        printf("Bail out! client's server cert type\n");
        exit(1);
    }
    if (t->client_auth) {
        SSL_CTX_set1_client_cert_type(*sctx, RPK_FIRST, sizeof(RPK_FIRST));
        SSL_CTX_set1_client_cert_type(*cctx, RPK_FIRST, sizeof(RPK_FIRST));
    }
    if (t->no_ticket) {
        SSL_CTX_set_options(*cctx, SSL_OP_NO_TICKET);
        SSL_CTX_set_options(*sctx, SSL_OP_NO_TICKET);
    }
    SSL_CTX_dane_enable(*cctx);
    SSL_CTX_dane_enable(*sctx);
}

/* One handshake (resuming `resume` if set); the client's session, or NULL when it failed. */
static SSL_SESSION *connect_once(const struct setup *t, SSL_CTX *cctx, SSL_CTX *sctx,
    SSL_SESSION *resume, SSL_SESSION **server_sess)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    SSL_SESSION *sess = NULL;
    STACK_OF(X509) *chain;
    int ok;

    if (c == NULL || s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1) {
        printf("Bail out! connection\n");
        exit(1);
    }
    if (SSL_use_PrivateKey(s, server_key) != 1
        || (t->with_cert && SSL_use_certificate(s, server_cert) != 1)) {
        printf("Bail out! server key\n");
        exit(1);
    }
    SSL_dane_enable(c, "server.example");
    SSL_dane_enable(s, NULL);
    if (t->expect == 1)
        SSL_add_expected_rpk(c, server_key);
    else if (t->expect == 2)
        SSL_add_expected_rpk(c, other_key);
    SSL_set_verify(c, t->client_mode, verify_cb);
    if (t->client_auth) {
        if (SSL_use_PrivateKey(c, client_key) != 1) {
            printf("Bail out! client key\n");
            exit(1);
        }
        SSL_add_expected_rpk(s, client_key);
        SSL_set_verify(s, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
    }
    if (resume != NULL)
        SSL_set_session(c, resume);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    ok = run(c, s);
    printf("  handshake %s, reused %d, client verify result %ld, server verify result %ld\n",
        ok ? "done" : "failed", SSL_session_reused(c), SSL_get_verify_result(c),
        SSL_get_verify_result(s));
    printf("  server cert type %d/%d, client cert type %d/%d\n",
        SSL_get_negotiated_server_cert_type(c), SSL_get_negotiated_server_cert_type(s),
        SSL_get_negotiated_client_cert_type(c), SSL_get_negotiated_client_cert_type(s));
    printf("  client: peer rpk %s, peer cert %s; server: peer rpk %s, peer cert %s\n",
        SSL_get0_peer_rpk(c) != NULL ? "set" : "none",
        SSL_get0_peer_certificate(c) != NULL ? "set" : "none",
        SSL_get0_peer_rpk(s) != NULL ? "set" : "none",
        SSL_get0_peer_certificate(s) != NULL ? "set" : "none");
    if (SSL_get0_peer_rpk(c) != NULL)
        printf("  client's peer rpk is the server's: %d\n",
            EVP_PKEY_eq(SSL_get0_peer_rpk(c), server_key));
    if (SSL_get0_peer_rpk(s) != NULL)
        printf("  server's peer rpk is the client's: %d\n",
            EVP_PKEY_eq(SSL_get0_peer_rpk(s), client_key));
    chain = SSL_get0_verified_chain(c);
    printf("  client's verified chain %d\n", chain == NULL ? -1 : sk_X509_num(chain));
    errors();
    if (ok) {
        unsigned char buf[1];

        /* TLS 1.3's tickets arrive after the handshake. */
        if (SSL_read(c, buf, sizeof(buf)) <= 0)
            ERR_clear_error();
        sess = SSL_get1_session(c);
        printf("  client session peer rpk %s\n",
            SSL_SESSION_get0_peer_rpk(sess) != NULL ? "set" : "none");
        if (server_sess != NULL) {
            *server_sess = SSL_get1_session(s);
            printf("  server session peer rpk %s\n",
                SSL_SESSION_get0_peer_rpk(*server_sess) != NULL ? "set" : "none");
        }
        SSL_shutdown(c);
        SSL_shutdown(s);
    }
    SSL_free(c);
    SSL_free(s);
    return sess;
}

static void handshake(const struct setup *t)
{
    SSL_CTX *cctx, *sctx;

    printf("# %s, %s\n", t->what, t->version == TLS1_3_VERSION ? "TLS 1.3" : "TLS 1.2");
    contexts(t, &cctx, &sctx);
    SSL_SESSION_free(connect_once(t, cctx, sctx, NULL, NULL));
    check(1, t->what);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void resumption(const struct setup *t)
{
    SSL_CTX *cctx, *sctx;
    SSL_SESSION *sess, *server_sess = NULL;

    printf("# %s, %s\n", t->what, t->version == TLS1_3_VERSION ? "TLS 1.3" : "TLS 1.2");
    contexts(t, &cctx, &sctx);
    sess = connect_once(t, cctx, sctx, NULL, &server_sess);
    check(sess != NULL, "the full handshake");
    if (sess != NULL) {
        SSL_SESSION *again = connect_once(t, cctx, sctx, sess, NULL);

        check(again != NULL, t->what);
        SSL_SESSION_free(again);
    }
    SSL_SESSION_free(sess);
    SSL_SESSION_free(server_sess);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    BIO *b;
    int v;

    b = BIO_new_mem_buf(SERVER_PEM, -1);
    server_cert = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    b = BIO_new_mem_buf(SERVER_KEY_PEM, -1);
    server_key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    other_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    client_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (server_cert == NULL || server_key == NULL || other_key == NULL || client_key == NULL) {
        printf("Bail out! keys\n");
        return 1;
    }
    for (v = 0; v < 2; v++) {
        int version = v == 0 ? TLS1_3_VERSION : TLS1_2_VERSION;
        struct setup cases[] = {
            { "server rpk from its certificate", version, 1, 1, 1, 1, SSL_VERIFY_PEER, 0, 0 },
            { "server rpk from a key alone", version, 1, 1, 0, 1, SSL_VERIFY_PEER, 0, 0 },
            { "a mismatched key, SSL_VERIFY_NONE", version, 1, 1, 1, 2, SSL_VERIFY_NONE, 0, 0 },
            { "no expected key, SSL_VERIFY_NONE", version, 1, 1, 1, 0, SSL_VERIFY_NONE, 0, 0 },
            { "a mismatched key, SSL_VERIFY_PEER", version, 1, 1, 1, 2, SSL_VERIFY_PEER, 0, 0 },
            { "no expected key, SSL_VERIFY_PEER", version, 1, 1, 1, 0, SSL_VERIFY_PEER, 0, 0 },
            { "the client offers rpk, the server doesn't", version, 0, 1, 1, 1, SSL_VERIFY_NONE, 0,
                0 },
            { "the server offers rpk, the client doesn't", version, 1, 0, 1, 1, SSL_VERIFY_NONE, 0,
                0 },
            { "a key alone, X.509 negotiated", version, 0, 1, 0, 1, SSL_VERIFY_NONE, 0, 0 },
            { "client authentication with a key alone", version, 1, 1, 1, 1, SSL_VERIFY_PEER, 1,
                0 },
        };
        struct setup resumed[] = {
            { "resumption", version, 1, 1, 1, 1, SSL_VERIFY_PEER, 0, 0 },
            { "resumption, no ticket", version, 1, 1, 1, 1, SSL_VERIFY_PEER, 0, 1 },
            { "resumption with client authentication", version, 1, 1, 1, 1, SSL_VERIFY_PEER, 1, 0 },
            { "resumption with client authentication, no ticket", version, 1, 1, 1, 1,
                SSL_VERIFY_PEER, 1, 1 },
        };
        size_t i;

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
            handshake(&cases[i]);
        for (i = 0; i < sizeof(resumed) / sizeof(resumed[0]); i++)
            resumption(&resumed[i]);
    }
    X509_free(server_cert);
    EVP_PKEY_free(server_key);
    EVP_PKEY_free(other_key);
    EVP_PKEY_free(client_key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
