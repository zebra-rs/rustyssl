/*
 * Conformance test for which signature schemes a server's key can make
 * (SSL_CTX_set1_sigalgs_list(3), SSL_get_peer_signature_nid(3),
 * SSL_get_peer_signature_type_nid(3)): an RSA-PSS key restricted to SHA-256 skips the
 * client's preferred SHA-512 scheme (EVP_PKEY_digestsign_supports_digest), and a small RSA key
 * skips the RSA-PSS schemes whose digest it is too short for. With nothing left, the handshake
 * fails.
 *
 * The keys and certificates are made at run time; only deterministic output is printed.
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

/* Prints and clears the error queue: library/reason. */
static void errors(const char *who)
{
    unsigned long e;

    printf("  %s errors:", who);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static void bail(const char *what)
{
    printf("Bail out! %s\n", what);
    exit(1);
}

/* An RSA-PSS key whose parameters restrict it to SHA-256. */
static EVP_PKEY *pss_restricted_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA-PSS", NULL);
    EVP_PKEY *k = NULL;

    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) != 1
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1
        || EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, "SHA256", NULL) != 1
        || EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, "SHA256") != 1
        || EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, 32) != 1 || EVP_PKEY_keygen(ctx, &k) != 1)
        bail("RSA-PSS key");
    EVP_PKEY_CTX_free(ctx);
    return k;
}

/* A self-signed certificate for the key, signed with SHA-256. */
static X509 *self_signed(EVP_PKEY *k)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    if (x == NULL || n == NULL || X509_set_version(x, X509_VERSION_3) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(x), 1) != 1
        || X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"server", -1,
                                      -1, 0) != 1
        || X509_set_subject_name(x, n) != 1 || X509_set_issuer_name(x, n) != 1
        || X509_gmtime_adj(X509_getm_notBefore(x), -3600) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 86400) == NULL || X509_set_pubkey(x, k) != 1
        || X509_sign(x, k, EVP_sha256()) <= 0)
        bail("certificate");
    X509_NAME_free(n);
    return x;
}

/* Runs both ends' handshakes in turn until both finish (0) or one fails (its error). */
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
                errors(i == 0 ? "client" : "server");
                return e;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}

/*
 * A handshake with the server's key and certificate, the client offering `sigalgs` at
 * `version`; prints the scheme the client saw, or the failure.
 */
static void handshake(const char *name, EVP_PKEY *k, X509 *x, int version, const char *sigalgs,
                      int expect_ok)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;
    int ok, nid = NID_undef, type = NID_undef;

    printf("# %s\n", name);
    if (cctx == NULL || sctx == NULL)
        bail("contexts");
    SSL_CTX_set_security_level(cctx, 0);
    SSL_CTX_set_security_level(sctx, 0);
    if (SSL_CTX_use_certificate(sctx, x) != 1 || SSL_CTX_use_PrivateKey(sctx, k) != 1)
        bail("server key");
    SSL_CTX_set_min_proto_version(cctx, version);
    SSL_CTX_set_max_proto_version(cctx, version);
    if (SSL_CTX_set1_sigalgs_list(cctx, sigalgs) != 1)
        bail("sigalgs");
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    if (c == NULL || s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1)
        bail("connection");
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    ok = run(c, s) == 0;
    check(ok == expect_ok, name);
    if (ok) {
        SSL_get_peer_signature_nid(c, &nid);
        SSL_get_peer_signature_type_nid(c, &type);
        printf("  %s, signed with %s/%s\n", SSL_get_version(c), OBJ_nid2sn(type), OBJ_nid2sn(nid));
    }
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    EVP_PKEY *pss = pss_restricted_key(), *small = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)768);
    X509 *pss_cert = self_signed(pss), *small_cert;

    if (small == NULL)
        bail("RSA key");
    small_cert = self_signed(small);
    handshake("TLS 1.3, RSA-PSS key for SHA-256, client prefers SHA-512", pss, pss_cert,
              TLS1_3_VERSION, "rsa_pss_pss_sha512:rsa_pss_pss_sha256", 1);
    handshake("TLS 1.2, RSA-PSS key for SHA-256, client prefers SHA-512", pss, pss_cert,
              TLS1_2_VERSION, "rsa_pss_pss_sha512:rsa_pss_pss_sha256", 1);
    handshake("TLS 1.3, RSA-PSS key for SHA-256, client offers SHA-512 only", pss, pss_cert,
              TLS1_3_VERSION, "rsa_pss_pss_sha512", 0);
    handshake("TLS 1.2, 768-bit RSA key, client prefers RSA-PSS with SHA-512", small, small_cert,
              TLS1_2_VERSION, "rsa_pss_rsae_sha512:rsa_pss_rsae_sha384:rsa_pss_rsae_sha256", 1);
    handshake("TLS 1.3, 768-bit RSA key, client offers RSA-PSS with SHA-512 only", small,
              small_cert, TLS1_3_VERSION, "rsa_pss_rsae_sha512", 0);
    X509_free(pss_cert);
    X509_free(small_cert);
    EVP_PKEY_free(pss);
    EVP_PKEY_free(small);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
