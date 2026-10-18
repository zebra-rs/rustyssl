/*
 * Conformance test for SSL_check_chain(3): the CERT_PKEY_* flags of a certificate, its key,
 * and a chain, checked from a certificate callback (SSL_CTX_set_cert_cb(3)) against what the
 * handshake negotiated: the peer's signature algorithms and groups in TLS 1.2 and 1.3, strict
 * mode (SSL_CERT_FLAG_TLS_STRICT), a self-signed certificate, a key that isn't the
 * certificate's, and on a client the server's certificate types and CA names; NULL arguments
 * give 0.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
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


/* A self-signed RSA certificate for a new 2048-bit key. */
static X509 *rsa_cert(EVP_PKEY **pk)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    *pk = EVP_RSA_gen(2048);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"rsa", -1, -1, 0);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
    X509_set_version(x, X509_VERSION_3);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, n);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, *pk);
    X509_sign(x, *pk, EVP_sha256());
    X509_NAME_free(n);
    return x;
}

/* What the certificate callback checks, and the flags it got. */
static X509 *cand_x, *cand_ca;
static EVP_PKEY *cand_pk;
static int cand_flags = -2, null_cert = -2, null_key = -2, cb_calls = 0;

static int cert_cb(SSL *s, void *arg)
{
    STACK_OF(X509) *chain = sk_X509_new_null();

    (void)arg;
    cb_calls++;
    if (cand_ca != NULL)
        sk_X509_push(chain, cand_ca);
    cand_flags = SSL_check_chain(s, cand_x, cand_pk, chain);
    null_cert = SSL_check_chain(s, NULL, cand_pk, chain);
    null_key = SSL_check_chain(s, cand_x, NULL, chain);
    sk_X509_free(chain);
    return 1;
}

/* The flags by name. */
static void show(const char *who)
{
    static const struct {
        int flag;
        const char *name;
    } names[] = {
        { CERT_PKEY_VALID, "VALID" },
        { CERT_PKEY_SIGN, "SIGN" },
        { CERT_PKEY_EE_SIGNATURE, "EE_SIGNATURE" },
        { CERT_PKEY_CA_SIGNATURE, "CA_SIGNATURE" },
        { CERT_PKEY_EE_PARAM, "EE_PARAM" },
        { CERT_PKEY_CA_PARAM, "CA_PARAM" },
        { CERT_PKEY_EXPLICIT_SIGN, "EXPLICIT_SIGN" },
        { CERT_PKEY_ISSUER_NAME, "ISSUER_NAME" },
        { CERT_PKEY_CERT_TYPE, "CERT_TYPE" },
        { CERT_PKEY_SUITEB, "SUITEB" },
    };
    size_t i;

    printf("  %s: %d callback(s), NULL certificate %d, NULL key %d, flags 0x%x:", who, cb_calls,
           null_cert, null_key, (unsigned)cand_flags);
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if ((cand_flags & names[i].flag) != 0)
            printf(" %s", names[i].name);
    printf("\n");
}

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

/*
 * A server-side check: a handshake at `version` with the client's signature algorithms and
 * groups (NULL: the defaults) and the server's certificate flags, its callback checking the
 * candidate.
 */
static void server_side(const char *name, int version, const char *sigalgs, const char *groups,
                        unsigned long cert_flags)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = server_ctx();
    SSL *c, *s;

    printf("# %s\n", name);
    cb_calls = 0;
    cand_flags = null_cert = null_key = -2;
    SSL_CTX_set_cert_cb(sctx, cert_cb, NULL);
    if (cert_flags != 0)
        SSL_CTX_set_cert_flags(sctx, cert_flags);
    if (sigalgs != NULL)
        SSL_CTX_set1_sigalgs_list(cctx, sigalgs);
    if (groups != NULL)
        SSL_CTX_set1_groups_list(cctx, groups);
    if (version < TLS1_2_VERSION) {
        /* TLS 1.1 needs security level 0. */
        SSL_CTX_set_security_level(cctx, 0);
        SSL_CTX_set_security_level(sctx, 0);
        SSL_CTX_set_min_proto_version(sctx, version);
    }
    connect_pair(cctx, sctx, &c, &s, NULL, version);
    ERR_clear_error();
    show("server");
    check(cb_calls > 0, name);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/*
 * A client-side check: the server asks for a certificate (naming `ca_name`'s subject, or no
 * CA names) in TLS 1.2, and the client's callback checks the candidate.
 */
static void client_side(const char *name, X509 *ca_name)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = server_ctx();
    SSL *c, *s;

    printf("# %s\n", name);
    cb_calls = 0;
    cand_flags = null_cert = null_key = -2;
    SSL_CTX_set_cert_cb(cctx, cert_cb, NULL);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER, NULL);
    if (ca_name != NULL) {
        STACK_OF(X509_NAME) *names = sk_X509_NAME_new_null();

        sk_X509_NAME_push(names, X509_NAME_dup(X509_get_subject_name(ca_name)));
        SSL_CTX_set_client_CA_list(sctx, names);
    }
    connect_pair(cctx, sctx, &c, &s, NULL, TLS1_2_VERSION);
    ERR_clear_error();
    show("client");
    check(cb_calls > 0, name);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    X509 *ca = cert(CA_PEM), *leaf = cert(SERVER_PEM), *rsa;
    EVP_PKEY *leaf_key = key(SERVER_KEY_PEM), *rsa_key = NULL;

    rsa = rsa_cert(&rsa_key);
    if (ca == NULL || leaf == NULL || leaf_key == NULL || rsa == NULL) {
        printf("Bail out! test objects\n");
        return 1;
    }
    cand_x = leaf;
    cand_pk = leaf_key;
    cand_ca = ca;
    server_side("TLS 1.2, an EC certificate and its root", TLS1_2_VERSION, NULL, NULL, 0);
    server_side("TLS 1.2, no ECDSA-SHA256 offered", TLS1_2_VERSION,
                "ECDSA+SHA384:RSA+SHA256", NULL, 0);
    server_side("TLS 1.2, P-256 not offered", TLS1_2_VERSION, NULL, "P-384:X25519", 0);
    server_side("TLS 1.2, strict mode", TLS1_2_VERSION, NULL, NULL, SSL_CERT_FLAG_TLS_STRICT);
    server_side("TLS 1.3, an EC certificate and its root", TLS1_3_VERSION, NULL, NULL, 0);
    server_side("TLS 1.3, no ECDSA offered", TLS1_3_VERSION,
                "rsa_pss_rsae_sha256:rsa_pkcs1_sha256", NULL, 0);
    server_side("TLS 1.3, strict mode", TLS1_3_VERSION, NULL, NULL, SSL_CERT_FLAG_TLS_STRICT);
    cand_ca = NULL;
    server_side("TLS 1.2, the certificate alone", TLS1_2_VERSION, NULL, NULL, 0);
    cand_x = rsa;
    cand_pk = rsa_key;
    server_side("TLS 1.2, a self-signed RSA certificate", TLS1_2_VERSION, NULL, NULL, 0);
    server_side("TLS 1.1, a self-signed RSA certificate", TLS1_1_VERSION, NULL, NULL, 0);
    cand_x = leaf;
    cand_pk = rsa_key;
    server_side("TLS 1.2, a certificate with another key", TLS1_2_VERSION, NULL, NULL, 0);
    cand_pk = leaf_key;
    cand_ca = ca;
    client_side("client, no CA names", NULL);
    client_side("client, the root's name", ca);
    client_side("client, another name", rsa);
    printf("SSL_check_chain(NULL, ...) = %d\n", SSL_check_chain(NULL, leaf, leaf_key, NULL));
    X509_free(ca);
    X509_free(leaf);
    X509_free(rsa);
    EVP_PKEY_free(leaf_key);
    EVP_PKEY_free(rsa_key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
