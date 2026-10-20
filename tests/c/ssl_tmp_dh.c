/*
 * Conformance test for a TLS 1.2 server's ephemeral keys: the deprecated tmp_dh callback
 * (SSL_CTX_set_tmp_dh_callback(3)) giving DHE parameters, or NULL, no parameters at all, and
 * SSL_CTX_set_dh_auto(3); and SSL_get_tmp_key(3) on the server between its first flight and
 * the client's key exchange (DHE and ECDHE) and after the handshake, over a BIO pair; and on
 * the client, whose temporary key is its ClientHello's first key share (TLS 1.3's, replaced by
 * the one a TLS 1.3 ServerHello picks or a HelloRetryRequest asks for, kept by TLS 1.2).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/dh.h>
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
static void errors(void)
{
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
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

static DH *dh_params;
static int dh_calls, dh_return_null;

static DH *tmp_dh_cb(SSL *s, int is_export, int keylength)
{
    (void)s;
    dh_calls++;
    printf("  tmp_dh_callback: is_export %d, keylength %d\n", is_export, keylength);
    return dh_return_null ? NULL : dh_params;
}

/* The server's ephemeral key, as SSL_get_tmp_key gives it. */
static void tmp_key(const char *when, SSL *s)
{
    EVP_PKEY *k = NULL;
    long r = SSL_get_tmp_key(s, &k);

    printf("  %s: SSL_get_tmp_key %ld", when, r);
    if (r > 0 && k != NULL)
        printf(", %s, %d bits", EVP_PKEY_get0_type_name(k), EVP_PKEY_get_bits(k));
    printf("\n");
    EVP_PKEY_free(k);
}

/*
 * A TLS 1.2 handshake with `cipher`, the server's DH set up by `mode` (0: none, 1: the
 * callback, 2: dh_auto), stopping after the server's first flight to look at its key.
 */
static void handshake(const char *name, const char *cipher, int mode, X509 *x, EVP_PKEY *pk)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;
    int r, round;

    printf("# %s\n", name);
    dh_calls = 0;
    SSL_CTX_use_certificate(sctx, x);
    SSL_CTX_use_PrivateKey(sctx, pk);
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(cctx, cipher);
    SSL_CTX_set_cipher_list(sctx, cipher);
    if (mode == 1)
        SSL_CTX_set_tmp_dh_callback(sctx, tmp_dh_cb);
    else if (mode == 2)
        SSL_CTX_set_dh_auto(sctx, 1);
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_connect(c);
    SSL_accept(s);
    tmp_key("after the server's first flight", s);
    for (round = 0, r = 0; round < 16 && r != 2; round++) {
        r = (SSL_do_handshake(c) == 1) + (SSL_do_handshake(s) == 1);
        if (SSL_get_error(s, -1) == SSL_ERROR_SSL || SSL_get_error(c, -1) == SSL_ERROR_SSL)
            break;
    }
    printf("  handshake %s, callback %d\n", r == 2 ? "done" : "failed", dh_calls);
    tmp_key("after the handshake", s);
    check(1, name);
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/*
 * The client's temporary key (SSL_get_tmp_key) after its ClientHello and after the handshake,
 * with each side's highest version, the server's ciphers, and each side's groups.
 */
static void client_handshake(const char *name, int cmax, int smax, const char *cipher,
                             const char *cgroups, const char *sgroups, X509 *x, EVP_PKEY *pk)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;
    int r, round;

    printf("# client: %s\n", name);
    SSL_CTX_use_certificate(sctx, x);
    SSL_CTX_use_PrivateKey(sctx, pk);
    if (cmax != 0)
        SSL_CTX_set_max_proto_version(cctx, cmax);
    if (smax != 0)
        SSL_CTX_set_max_proto_version(sctx, smax);
    if (cipher != NULL)
        SSL_CTX_set_cipher_list(sctx, cipher);
    SSL_CTX_set1_groups_list(cctx, cgroups);
    SSL_CTX_set1_groups_list(sctx, sgroups);
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_connect(c);
    tmp_key("after the ClientHello", c);
    for (round = 0, r = 0; round < 16 && r != 2; round++) {
        r = (SSL_do_handshake(c) == 1) + (SSL_do_handshake(s) == 1);
        if (SSL_get_error(s, -1) == SSL_ERROR_SSL || SSL_get_error(c, -1) == SSL_ERROR_SSL)
            break;
    }
    printf("  handshake %s, %s\n", r == 2 ? "done" : "failed", SSL_get_version(c));
    tmp_key("after the handshake", c);
    check(r == 2, name);
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    EVP_PKEY *pk = NULL;
    X509 *x = rsa_cert(&pk);

    dh_params = DH_new_by_nid(NID_ffdhe2048);
    if (x == NULL || pk == NULL || dh_params == NULL) {
        printf("Bail out! test objects\n");
        return 1;
    }
    handshake("DHE with the tmp_dh callback", "DHE-RSA-AES128-SHA", 1, x, pk);
    dh_return_null = 1;
    handshake("DHE, the tmp_dh callback gives NULL", "DHE-RSA-AES128-SHA", 1, x, pk);
    dh_return_null = 0;
    handshake("DHE with no parameters", "DHE-RSA-AES128-SHA", 0, x, pk);
    handshake("DHE with dh_auto", "DHE-RSA-AES128-SHA", 2, x, pk);
    handshake("ECDHE", "ECDHE-RSA-AES128-SHA", 0, x, pk);
    client_handshake("TLS 1.3", 0, 0, NULL, "P-256:X25519", "P-256:X25519", x, pk);
    client_handshake("TLS 1.3 after a HelloRetryRequest", 0, 0, NULL, "P-256:P-384", "P-384",
                     x, pk);
    client_handshake("TLS 1.2 ECDHE, the client TLS 1.2 only", TLS1_2_VERSION, 0,
                     "ECDHE-RSA-AES128-SHA", "P-256", "P-256", x, pk);
    client_handshake("TLS 1.2 RSA after offering TLS 1.3", 0, TLS1_2_VERSION, "AES128-SHA",
                     "P-521", "P-521", x, pk);
    client_handshake("TLS 1.2 ECDHE after offering TLS 1.3", 0, TLS1_2_VERSION,
                     "ECDHE-RSA-AES128-SHA", "X25519:P-256", "P-256", x, pk);
    DH_free(dh_params);
    X509_free(x);
    EVP_PKEY_free(pk);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
