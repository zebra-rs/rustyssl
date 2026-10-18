/*
 * Conformance test for certificates whose keys are the providers' TLS-SIGALG key types
 * (ML-DSA-44, ML-DSA-65, ML-DSA-87 from the default provider): each takes a slot of its own
 * after the built-in ones (SSL_CTX_use_certificate(3), SSL_CTX_set_current_cert(3)), signs
 * TLS 1.3 handshakes with its scheme (SSL_get_peer_signature_type_nid(3)), serves client
 * authentication, and can't serve TLS 1.2.
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

static EVP_PKEY *key(const char *type)
{
    EVP_PKEY *k = strcmp(type, "RSA") == 0 ? EVP_PKEY_Q_keygen(NULL, NULL, type, (size_t)2048)
                                           : EVP_PKEY_Q_keygen(NULL, NULL, type);

    if (k == NULL)
        bail(type);
    return k;
}

/* A self-signed certificate for the key (ML-DSA signs without a separate digest). */
static X509 *self_signed(EVP_PKEY *k, const char *cn)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    if (x == NULL || n == NULL || X509_set_version(x, X509_VERSION_3) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(x), 1) != 1
        || X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1,
                                      0) != 1
        || X509_set_subject_name(x, n) != 1 || X509_set_issuer_name(x, n) != 1
        || X509_gmtime_adj(X509_getm_notBefore(x), -3600) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 86400) == NULL || X509_set_pubkey(x, k) != 1
        || X509_sign(x, k, EVP_PKEY_is_a(k, "RSA") ? EVP_sha256() : NULL) <= 0)
        bail("certificate");
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

/* The scheme `x` saw its peer sign with. */
static void peer_scheme(const char *who, SSL *x)
{
    int nid = NID_undef, type = NID_undef;
    const char *name = NULL;

    SSL_get_peer_signature_nid(x, &nid);
    SSL_get_peer_signature_type_nid(x, &type);
    SSL_get0_peer_signature_name(x, &name);
    printf("  %s saw %s/%s (%s)\n", who, OBJ_nid2sn(type), OBJ_nid2sn(nid),
           name != NULL ? name : "none");
}

struct setup {
    const char *name;
    EVP_PKEY *skeys[2];
    X509 *scerts[2];
    EVP_PKEY *ckey;
    X509 *ccert;
    int version;
    const char *sigalgs;
    int expect_ok;
};

static void handshake(const struct setup *t)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;
    int ok, i;

    printf("# %s\n", t->name);
    if (cctx == NULL || sctx == NULL)
        bail("contexts");
    for (i = 0; i < 2; i++)
        if (t->skeys[i] != NULL
            && (SSL_CTX_use_certificate(sctx, t->scerts[i]) != 1
                || SSL_CTX_use_PrivateKey(sctx, t->skeys[i]) != 1))
            bail("server key");
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, accept_any);
    if (t->ckey != NULL) {
        if (SSL_CTX_use_certificate(cctx, t->ccert) != 1
            || SSL_CTX_use_PrivateKey(cctx, t->ckey) != 1)
            bail("client key");
        SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, accept_any);
    }
    SSL_CTX_set_max_proto_version(cctx, t->version);
    if (t->sigalgs != NULL && SSL_CTX_set1_sigalgs_list(cctx, t->sigalgs) != 1)
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
    check(ok == t->expect_ok, t->name);
    if (ok) {
        printf("  %s\n", SSL_get_version(c));
        peer_scheme("client", c);
        if (t->ckey != NULL)
            peer_scheme("server", s);
    }
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/* The slots a context holds, from SSL_CERT_SET_FIRST through SSL_CERT_SET_NEXT. */
static void slots(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    EVP_PKEY *rsa = key("RSA"), *m44 = key("ML-DSA-44"), *m87 = key("ML-DSA-87"),
             *m65 = key("ML-DSA-65");
    X509 *xr = self_signed(rsa, "rsa"), *x44 = self_signed(m44, "mldsa44"),
         *x87 = self_signed(m87, "mldsa87");
    int r, n = 0;

    printf("# slots\n");
    if (ctx == NULL)
        bail("context");
    check(SSL_CTX_use_certificate(ctx, x87) == 1 && SSL_CTX_use_PrivateKey(ctx, m87) == 1,
          "an ML-DSA-87 certificate and key");
    check(SSL_CTX_use_certificate(ctx, xr) == 1 && SSL_CTX_use_PrivateKey(ctx, rsa) == 1,
          "an RSA certificate and key");
    check(SSL_CTX_use_cert_and_key(ctx, x44, m44, NULL, 1) == 1,
          "an ML-DSA-44 certificate and key together");
    check(SSL_CTX_use_cert_and_key(ctx, x44, m44, NULL, 0) == 0, "not replaced without override");
    errors("not replaced");
    /* A key alone in an empty slot: no certificate there to check it against. */
    printf("  ML-DSA-65 key alone: %d\n", SSL_CTX_use_PrivateKey(ctx, m65));
    printf("  check: %d\n", SSL_CTX_check_private_key(ctx));
    errors("check");
    /* The same key again: it replaces itself. */
    printf("  ML-DSA-65 key again: %d\n", SSL_CTX_use_PrivateKey(ctx, m65));
    for (r = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST); r == 1 && n < 20;
         r = SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_NEXT)) {
        X509 *x = SSL_CTX_get0_certificate(ctx);
        EVP_PKEY *k = SSL_CTX_get0_privatekey(ctx);

        n++;
        printf("  slot: certificate %s, key %s\n",
               x != NULL ? EVP_PKEY_get0_type_name(X509_get0_pubkey(x)) : "none",
               k != NULL ? EVP_PKEY_get0_type_name(k) : "none");
    }
    ERR_clear_error();
    SSL_CTX_free(ctx);
    X509_free(xr);
    X509_free(x44);
    X509_free(x87);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(m44);
    EVP_PKEY_free(m65);
    EVP_PKEY_free(m87);
}

static EVP_PKEY *cb_keys[2];
static X509 *cb_certs[2];

/*
 * A certificate callback that reads what the handshake decided so far, checks both candidate
 * certificates (ML-DSA-65, RSA) with SSL_check_chain, and installs the first one valid.
 */
static int cert_cb(SSL *s, void *arg)
{
    int i, n, sign = 0, hash = 0, sighash = 0;
    unsigned char rsig = 0, rhash = 0;

    (void)arg;
    n = SSL_get_sigalgs(s, -1, NULL, NULL, NULL, NULL, NULL);
    printf("  in the callback: version %04x, peer sigalgs %d, shared(-1) %d\n",
           (unsigned)SSL_version(s), n > 0, SSL_get_shared_sigalgs(s, -1, NULL, NULL, NULL, NULL, NULL));
    if (SSL_get_shared_sigalgs(s, 0, &sign, &hash, &sighash, &rsig, &rhash) > 0)
        printf("  first shared: %s/%s %s %02x%02x\n", OBJ_nid2sn(sign), OBJ_nid2sn(hash),
               OBJ_nid2sn(sighash), rhash, rsig);
    for (i = 0; i < 2; i++) {
        int rv = SSL_check_chain(s, cb_certs[i], cb_keys[i], NULL);

        printf("  check_chain %s: %#x\n", EVP_PKEY_get0_type_name(cb_keys[i]), (unsigned)rv);
        if ((rv & CERT_PKEY_VALID) != 0) {
            printf("  use %d\n", SSL_use_cert_and_key(s, cb_certs[i], cb_keys[i], NULL, 1));
            break;
        }
    }
    return 1;
}

static void callback_handshake(const char *name, int version, const char *sigalgs, int expect_ok)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;
    int ok;

    printf("# %s\n", name);
    if (cctx == NULL || sctx == NULL)
        bail("contexts");
    SSL_CTX_set_cert_cb(sctx, cert_cb, NULL);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, accept_any);
    SSL_CTX_set_max_proto_version(cctx, version);
    if (sigalgs != NULL && SSL_CTX_set1_sigalgs_list(cctx, sigalgs) != 1)
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
        printf("  %s\n", SSL_get_version(c));
        peer_scheme("client", c);
    }
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    EVP_PKEY *m44 = key("ML-DSA-44"), *m65 = key("ML-DSA-65"), *m87 = key("ML-DSA-87"),
             *rsa = key("RSA");
    X509 *x44 = self_signed(m44, "mldsa44"), *x65 = self_signed(m65, "mldsa65"),
         *x87 = self_signed(m87, "mldsa87"), *xr = self_signed(rsa, "rsa");
    struct setup tests[] = {
        { "TLS 1.3, an ML-DSA-65 server", { m65, NULL }, { x65, NULL }, NULL, NULL,
          TLS1_3_VERSION, NULL, 1 },
        { "TLS 1.3, an ML-DSA-44 server", { m44, NULL }, { x44, NULL }, NULL, NULL,
          TLS1_3_VERSION, NULL, 1 },
        { "TLS 1.3, RSA and ML-DSA-87, the client prefers ML-DSA", { rsa, m87 }, { xr, x87 },
          NULL, NULL, TLS1_3_VERSION, "mldsa87:rsa_pss_rsae_sha256", 1 },
        { "TLS 1.3, RSA and ML-DSA-87, the client prefers RSA", { rsa, m87 }, { xr, x87 }, NULL,
          NULL, TLS1_3_VERSION, "rsa_pss_rsae_sha256:mldsa87", 1 },
        { "TLS 1.3, ML-DSA-87, the client offers mldsa65 only", { m87, NULL }, { x87, NULL },
          NULL, NULL, TLS1_3_VERSION, "mldsa65", 0 },
        { "TLS 1.2, an ML-DSA-65 server", { m65, NULL }, { x65, NULL }, NULL, NULL,
          TLS1_2_VERSION, NULL, 0 },
        { "TLS 1.2, RSA and ML-DSA-65", { m65, rsa }, { x65, xr }, NULL, NULL, TLS1_2_VERSION,
          NULL, 1 },
        { "TLS 1.3, an ML-DSA-44 client certificate", { rsa, NULL }, { xr, NULL }, m44, x44,
          TLS1_3_VERSION, NULL, 1 },
    };
    size_t i;

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
        handshake(&tests[i]);
    cb_keys[0] = m65;
    cb_certs[0] = x65;
    cb_keys[1] = rsa;
    cb_certs[1] = xr;
    callback_handshake("TLS 1.3, chosen in the certificate callback", TLS1_3_VERSION, NULL, 1);
    /* SSL_check_chain doesn't look at versions: the ML-DSA certificate is installed, and fails. */
    callback_handshake("TLS 1.2, chosen in the certificate callback", TLS1_2_VERSION, NULL, 0);
    callback_handshake("TLS 1.3, the client offers RSA-PSS only", TLS1_3_VERSION,
                       "rsa_pss_rsae_sha256", 1);
    slots();
    X509_free(x44);
    X509_free(x65);
    X509_free(x87);
    X509_free(xr);
    EVP_PKEY_free(m44);
    EVP_PKEY_free(m65);
    EVP_PKEY_free(m87);
    EVP_PKEY_free(rsa);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
