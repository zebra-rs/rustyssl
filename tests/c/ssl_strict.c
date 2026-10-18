/*
 * Conformance test for strict certificate checking (SSL_CERT_FLAG_TLS_STRICT, the
 * StrictCertCheck option of SSL_CONF_cmd(3)): a strict client sends its certificate only when
 * the chain suits the server (its issuer among the server's CA names; an RSA, DSA, or ECDSA key
 * of a type the CertificateRequest lists, which TLS 1.3's lists none of), and a strict server
 * uses a certificate only when every signature in its chain is one the client accepts.
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
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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

static X509_NAME *name(const char *cn)
{
    X509_NAME *n = X509_NAME_new();

    if (n == NULL
        || X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1,
                                      0) != 1)
        bail("name");
    return n;
}

/* A certificate for `k` named `cn`, issued by `issuer` (NULL: self-signed) with `ikey`. */
static X509 *issue(EVP_PKEY *k, const char *cn, X509 *issuer, EVP_PKEY *ikey, int ca)
{
    X509 *x = X509_new();
    X509_NAME *n = name(cn);
    X509V3_CTX v3;
    X509_EXTENSION *ext;

    if (x == NULL || X509_set_version(x, X509_VERSION_3) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(x), ca ? 1 : 2) != 1
        || X509_set_subject_name(x, n) != 1
        || X509_set_issuer_name(x, issuer != NULL ? X509_get_subject_name(issuer) : n) != 1
        || X509_gmtime_adj(X509_getm_notBefore(x), -3600) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 86400) == NULL || X509_set_pubkey(x, k) != 1)
        bail("certificate");
    X509V3_set_ctx(&v3, issuer != NULL ? issuer : x, x, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &v3, NID_basic_constraints, ca ? "critical,CA:TRUE" : "CA:FALSE");
    if (ext == NULL || X509_add_ext(x, ext, -1) != 1)
        bail("extension");
    X509_EXTENSION_free(ext);
    if (X509_sign(x, ikey != NULL ? ikey : k, EVP_sha256()) <= 0)
        bail("signature");
    X509_NAME_free(n);
    return x;
}

static int accept_any(int ok, X509_STORE_CTX *xs)
{
    (void)ok;
    (void)xs;
    return 1;
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

static EVP_PKEY *rsa_root_key, *rsa_key, *ec_key, *other_key;
static X509 *root, *other_root, *rsa_cert, *ec_cert;

struct setup {
    const char *name;
    int version;
    int client_strict;
    int server_strict;
    /* The client authenticates with `client_key`/`client_cert` (NULL: none). */
    EVP_PKEY *client_key;
    X509 *client_cert;
    /* The CA names the server asks for: 0 none, 1 the client's issuer, 2 another. */
    int ca_names;
    /* The server's certificate, and the client's signature algorithms (NULL: the defaults). */
    EVP_PKEY *server_key;
    X509 *server_cert;
    const char *client_sigalgs;
    const char *cipher;
    int expect_ok;
};

static void handshake(const struct setup *t)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;
    int ok;

    printf("# %s\n", t->name);
    if (cctx == NULL || sctx == NULL)
        bail("contexts");
    SSL_CTX_set_security_level(cctx, 0);
    SSL_CTX_set_security_level(sctx, 0);
    if (SSL_CTX_use_certificate(sctx, t->server_cert) != 1
        || SSL_CTX_use_PrivateKey(sctx, t->server_key) != 1)
        bail("server key");
    if (t->server_strict)
        SSL_CTX_set_cert_flags(sctx, SSL_CERT_FLAG_TLS_STRICT);
    if (t->client_strict)
        SSL_CTX_set_cert_flags(cctx, SSL_CERT_FLAG_TLS_STRICT);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, accept_any);
    if (t->client_key != NULL) {
        STACK_OF(X509_NAME) *names = sk_X509_NAME_new_null();

        if (SSL_CTX_use_certificate(cctx, t->client_cert) != 1
            || SSL_CTX_use_PrivateKey(cctx, t->client_key) != 1)
            bail("client key");
        SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, accept_any);
        if (t->ca_names != 0) {
            X509 *ca = t->ca_names == 1 ? root : other_root;

            sk_X509_NAME_push(names, X509_NAME_dup(X509_get_subject_name(ca)));
        }
        SSL_CTX_set_client_CA_list(sctx, names);
    }
    SSL_CTX_set_max_proto_version(cctx, t->version);
    if (t->client_sigalgs != NULL && SSL_CTX_set1_sigalgs_list(cctx, t->client_sigalgs) != 1)
        bail("sigalgs");
    if (t->cipher != NULL && SSL_CTX_set_cipher_list(cctx, t->cipher) != 1)
        bail("cipher");
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    if (c == NULL || s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1)
        bail("connection");
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    ok = run(c, s) == 0;
    check(ok == t->expect_ok, t->name);
    if (ok)
        printf("  %s, %s, client certificate %s\n", SSL_get_version(c),
               SSL_CIPHER_get_name(SSL_get_current_cipher(c)),
               SSL_get0_peer_certificate(s) != NULL ? "sent" : "not sent");
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    EVP_PKEY *pss_key;
    X509 *pss_cert;
    EVP_PKEY_CTX *pctx;

    rsa_root_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    other_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    rsa_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    ec_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA-PSS", NULL);
    pss_key = NULL;
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) != 1 || EVP_PKEY_keygen(pctx, &pss_key) != 1)
        bail("RSA-PSS key");
    EVP_PKEY_CTX_free(pctx);
    if (rsa_root_key == NULL || other_key == NULL || rsa_key == NULL || ec_key == NULL)
        bail("keys");
    root = issue(rsa_root_key, "root", NULL, NULL, 1);
    other_root = issue(other_key, "other root", NULL, NULL, 1);
    rsa_cert = issue(rsa_key, "rsa", root, rsa_root_key, 0);
    ec_cert = issue(ec_key, "ec", root, rsa_root_key, 0);
    pss_cert = issue(pss_key, "pss", root, rsa_root_key, 0);
    {
        struct setup tests[] = {
            { "TLS 1.2, strict client, issuer among the CA names", TLS1_2_VERSION, 1, 0, ec_key,
              ec_cert, 1, rsa_key, rsa_cert, NULL, NULL, 1 },
            { "TLS 1.2, strict client, another CA named", TLS1_2_VERSION, 1, 0, ec_key, ec_cert, 2,
              rsa_key, rsa_cert, NULL, NULL, 0 },
            { "TLS 1.2, default client, another CA named", TLS1_2_VERSION, 0, 0, ec_key, ec_cert,
              2, rsa_key, rsa_cert, NULL, NULL, 1 },
            { "TLS 1.2, strict client, no CA names", TLS1_2_VERSION, 1, 0, ec_key, ec_cert, 0,
              rsa_key, rsa_cert, NULL, NULL, 1 },
            { "TLS 1.3, strict client with an RSA key", TLS1_3_VERSION, 1, 0, rsa_key, rsa_cert,
              1, rsa_key, rsa_cert, NULL, NULL, 0 },
            { "TLS 1.3, strict client with an RSA-PSS key", TLS1_3_VERSION, 1, 0, pss_key,
              pss_cert, 1, rsa_key, rsa_cert, NULL, NULL, 1 },
            { "TLS 1.3, strict client with an RSA-PSS key, another CA named", TLS1_3_VERSION, 1, 0,
              pss_key, pss_cert, 2, rsa_key, rsa_cert, NULL, NULL, 0 },
            { "TLS 1.2, default server, ECDSA only, its CA signed with RSA", TLS1_2_VERSION, 0, 0,
              NULL, NULL, 0, ec_key, ec_cert, "ECDSA+SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256", 1 },
            { "TLS 1.2, strict server, ECDSA only, its CA signed with RSA", TLS1_2_VERSION, 0, 1,
              NULL, NULL, 0, ec_key, ec_cert, "ECDSA+SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256", 0 },
            { "TLS 1.2, strict server, RSA accepted too", TLS1_2_VERSION, 0, 1, NULL, NULL, 0,
              ec_key, ec_cert, "ECDSA+SHA256:RSA+SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256", 1 },
            { "TLS 1.3, strict server", TLS1_3_VERSION, 0, 1, NULL, NULL, 0, ec_key, ec_cert,
              "ecdsa_secp256r1_sha256", NULL, 1 },
        };
        size_t i;

        for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
            handshake(&tests[i]);
    }
    X509_free(root);
    X509_free(other_root);
    X509_free(rsa_cert);
    X509_free(ec_cert);
    X509_free(pss_cert);
    EVP_PKEY_free(rsa_root_key);
    EVP_PKEY_free(other_key);
    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(ec_key);
    EVP_PKEY_free(pss_key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
