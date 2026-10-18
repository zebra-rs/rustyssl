/*
 * Conformance test for the group, signature algorithm, and certificate type lists
 * (SSL_CTX_set1_groups_list(3), SSL_CTX_set1_groups(3), SSL_CTX_get0_implemented_groups(3),
 * SSL_get1_groups(3), SSL_get_shared_group(3), SSL_get0_group_name(3),
 * SSL_CTX_set1_sigalgs_list(3), SSL_CTX_set1_client_sigalgs(3), SSL_get1_builtin_sigalgs(3),
 * SSL_CTX_set1_client_cert_type(3), SSL_get1_supported_ciphers(3),
 * SSL_CTX_set_security_callback(3)): 3.5's group list syntax (tuples, key shares, ignored and
 * removed groups, the DEFAULT pseudo groups) and its errors, groups by NID and from an EC key,
 * the providers' groups by version, signature algorithm lists and pairs and their syntax
 * checks, certificate type lists, the suites a connection can use, and handshakes that show
 * the lists and a security callback in effect.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
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

/* The errors recorded, with their data. */
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

/* Runs both ends' handshakes until both finish (0) or one fails (its SSL_get_error value). */
static int run(SSL *c, SSL *s)
{
    int cdone = 0, sdone = 0, round;
    BIO *a = NULL, *b = NULL;

    if (BIO_new_bio_pair(&a, 0, &b, 0) != 1) {
        printf("Bail out! BIO pair\n");
        exit(1);
    }
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
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

static const char *const group_lists[] = {
    "X25519", "x25519:P-256:secp384r1", "P-256:P-256", "*X25519:*P-256", "?nonsense:X448",
    "nonsense:X448", "X25519 / P-256 : P-384", "*X25519 / *P-256 / *P-384 / *P-521 / *X448",
    "*X25519:*P-256:*P-384:*P-521", "DEFAULT", "default:-X25519", "DEFAULT_SUITE_B", "*DEFAULT",
    "P-256:DEFAULT", "X25519:-X25519", "-X25519:X25519", "?*nonsense", "**X25519", "??X25519",
    "--X25519", "-?X25519", "*", "?", "X25519:", ":X25519", "X25519::P-256", "X25519//P-256",
    "/", "", "   ", " X25519 ", "?DEFAULT", "-DEFAULT", "DEFAULTS", "dEfAuLt_SuItE_b",
    "GC256A", "?GC256A:P-256", "ffdhe2048:ffdhe8192", "X25519MLKEM768:SecP256r1MLKEM768",
    "brainpoolP256r1tls13", "prime256v1", "P-256 / / P-384", "P-256:-P-384",
    "P-256 / X448 : -P-256", "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabc",
    "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcd",
};

static void groups_lists(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s = SSL_new(ctx);
    size_t i;
    long r;

    printf("# group lists\n");
    for (i = 0; i < sizeof(group_lists) / sizeof(group_lists[0]); i++) {
        printf("  '%s': ctx %ld", group_lists[i], SSL_CTX_set1_groups_list(ctx, group_lists[i]));
        printf(" ssl %ld", SSL_set1_groups_list(s, group_lists[i]));
        r = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 1, (void *)group_lists[i]);
        printf(" check %ld\n", r);
        errors();
    }
    check(SSL_CTX_ctrl(NULL, SSL_CTRL_SET_GROUPS_LIST, 1, "X25519") == 0, "a syntax check needs a context");
    errors();
    check(SSL_CTX_set1_groups_list(NULL, "X25519") == 0, "a NULL context");
    errors();
    check(SSL_CTX_set1_curves_list(ctx, "P-256:P-384") == 1, "SSL_CTX_set1_curves_list");
    check(SSL_set1_curves_list(s, "P-521") == 1, "SSL_set1_curves_list");

    printf("# groups by NID\n");
    {
        int ok[] = { NID_X9_62_prime256v1, NID_secp384r1, NID_X25519, NID_ffdhe2048 };
        int dup[] = { NID_secp384r1, NID_secp384r1 };
        int unknown[] = { NID_sha256 };
        int ffdup[] = { NID_ffdhe2048, NID_ffdhe2048 };
        int mixed[] = { NID_ffdhe2048, NID_secp224r1 };

        check(SSL_CTX_set1_groups(ctx, ok, 4) == 1, "SSL_CTX_set1_groups");
        check(SSL_CTX_set1_groups(ctx, dup, 2) == 0, "a duplicate");
        check(SSL_CTX_set1_groups(ctx, ffdup, 2) == 0, "a duplicate FFDHE group");
        check(SSL_CTX_set1_groups(ctx, unknown, 1) == 0, "not a group");
        check(SSL_CTX_set1_groups(ctx, mixed, 2) == 1, "FFDHE and EC groups");
        check(SSL_CTX_set1_groups(ctx, ok, 0) == 0, "none");
        errors();
        check(SSL_set1_groups(s, ok, 2) == 1, "SSL_set1_groups");
        check(SSL_set1_curves(s, dup, 2) == 0, "SSL_set1_curves");
        check(SSL_CTX_set1_curves(ctx, ok, 1) == 1, "SSL_CTX_set1_curves");
        errors();
    }

    printf("# an EC key's group\n");
    {
        EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp384r1);
        EC_KEY *none = EC_KEY_new();

        check(SSL_CTX_set_tmp_ecdh(ctx, ec) == 1, "SSL_CTX_set_tmp_ecdh");
        check(SSL_set_tmp_ecdh(s, ec) == 1, "SSL_set_tmp_ecdh");
        check(SSL_CTX_set_tmp_ecdh(ctx, NULL) == 0, "a NULL key");
        errors();
        check(SSL_CTX_set_tmp_ecdh(ctx, none) == 0, "a key without a group");
        errors();
        check(SSL_CTX_set_ecdh_auto(ctx, 1) == 1 && SSL_set_ecdh_auto(s, 0) == 0, "the ECDH auto macros");
        EC_KEY_free(ec);
        EC_KEY_free(none);
    }
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void implemented(int min, int max)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    STACK_OF(OPENSSL_CSTRING) *sk = sk_OPENSSL_CSTRING_new_null();
    int i, all;

    SSL_CTX_set_min_proto_version(ctx, min);
    SSL_CTX_set_max_proto_version(ctx, max);
    for (all = 0; all < 2; all++) {
        check(SSL_CTX_get0_implemented_groups(ctx, all, sk) == 1, "SSL_CTX_get0_implemented_groups");
        printf("  %x-%x all %d (%d):", min, max, all, sk_OPENSSL_CSTRING_num(sk));
        for (i = 0; i < sk_OPENSSL_CSTRING_num(sk); i++)
            printf(" %s", sk_OPENSSL_CSTRING_value(sk, i));
        printf("\n");
        while (sk_OPENSSL_CSTRING_num(sk) > 0)
            sk_OPENSSL_CSTRING_pop(sk);
    }
    check(SSL_CTX_get0_implemented_groups(ctx, 0, NULL) == 0, "a NULL stack");
    sk_OPENSSL_CSTRING_free(sk);
    SSL_CTX_free(ctx);
}

static const char *const sigalg_lists[] = {
    "RSA+SHA256", "rsa_pss_rsae_sha256:ECDSA+SHA384", "ed25519:ed448", "RSA-PSS+SHA256:PSS+SHA512",
    "DSA+SHA256", "ECDSA+SHA1:RSA+SHA224", "rsa_pkcs1_sha256", "RSA+SHA256:RSA+SHA256", "nonsense",
    "?nonsense:RSA+SHA256", "?nonsense", "", "RSA+", "+SHA256", "RSA+nonsense", "SHA256+RSA",
    "RSA+SHA256+x", "ECDSA+SHA512:ecdsa_secp521r1_sha512", "RSA:SHA256", "rsa+sha256",
    "ecdsa_brainpoolP256r1_sha256", "gostr34102012_256", "gost2012_256", "mldsa65",
    "rsa_pkcs1_md5_sha1", "RSA+MD5-SHA1", "RSA+md5", "ECDSA+SHA256::RSA+SHA256",
    "abcdefghijabcdefghijabcdefghijabcdefghi", "abcdefghijabcdefghijabcdefghijabcdefghij",
};

static void sigalgs(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s = SSL_new(ctx);
    size_t i;
    char *builtin;

    printf("# signature algorithm lists\n");
    for (i = 0; i < sizeof(sigalg_lists) / sizeof(sigalg_lists[0]); i++) {
        printf("  '%s': ctx %ld", sigalg_lists[i], SSL_CTX_set1_sigalgs_list(ctx, sigalg_lists[i]));
        printf(" client %ld", SSL_CTX_set1_client_sigalgs_list(ctx, sigalg_lists[i]));
        printf(" ssl %ld", SSL_set1_sigalgs_list(s, sigalg_lists[i]));
        printf("\n");
        errors();
    }
    check(SSL_set1_client_sigalgs_list(s, "ECDSA+SHA256") == 1, "SSL_set1_client_sigalgs_list");
    check(SSL_CTX_set1_sigalgs_list(ctx, NULL) == 0, "a NULL list");
    errors();
    {
        char many[2048] = "";

        for (i = 0; i < 70; i++)
            strcat(many, i == 0 ? "RSA+SHA256" : ":RSA+SHA256");
        check(SSL_CTX_set1_sigalgs_list(ctx, many) == 1, "duplicates don't count");
        many[0] = '\0';
        for (i = 0; i < 10; i++)
            strcat(many, "ed25519:ed448:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA256:ECDSA+SHA384:");
        strcat(many, "ECDSA+SHA512");
        check(SSL_CTX_set1_sigalgs_list(ctx, many) == 1, "a long list");
        errors();
    }

    printf("# signature algorithm pairs\n");
    {
        int ok[] = { NID_sha256, EVP_PKEY_RSA, NID_sha384, EVP_PKEY_EC, NID_sha512, EVP_PKEY_RSA_PSS };
        int odd[] = { NID_sha256, EVP_PKEY_RSA, NID_sha384 };
        int bad[] = { NID_sha256, EVP_PKEY_DH };
        int ed[] = { NID_undef, EVP_PKEY_ED25519 };
        int gost[] = { NID_id_GostR3411_2012_256, NID_id_GostR3410_2012_256 };

        check(SSL_CTX_set1_sigalgs(ctx, ok, 6) == 1, "SSL_CTX_set1_sigalgs");
        check(SSL_CTX_set1_sigalgs(ctx, odd, 3) == 0, "an odd count");
        check(SSL_CTX_set1_sigalgs(ctx, bad, 2) == 0, "no such pair");
        check(SSL_CTX_set1_sigalgs(ctx, ed, 2) == 1, "EdDSA");
        check(SSL_CTX_set1_sigalgs(ctx, gost, 2) == 1, "GOST is in the table");
        check(SSL_CTX_set1_sigalgs(ctx, ok, 0) == 0, "none");
        check(SSL_CTX_set1_client_sigalgs(ctx, ok, 2) == 1, "SSL_CTX_set1_client_sigalgs");
        check(SSL_set1_sigalgs(s, ok, 4) == 1, "SSL_set1_sigalgs");
        check(SSL_set1_client_sigalgs(s, bad, 2) == 0, "SSL_set1_client_sigalgs");
        errors();
    }

    builtin = SSL_get1_builtin_sigalgs(NULL);
    printf("  builtin: %s\n", builtin == NULL ? "(null)" : builtin);
    OPENSSL_free(builtin);
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void show_types(const char *label, unsigned char *t, size_t len)
{
    size_t i;

    printf("  %s:", label);
    if (t == NULL)
        printf(" (null)");
    for (i = 0; i < len; i++)
        printf(" %d", t[i]);
    printf(" (%zu)\n", len);
}

static void cert_types(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s;
    unsigned char both[] = { TLSEXT_cert_type_rpk, TLSEXT_cert_type_x509 };
    unsigned char dup[] = { TLSEXT_cert_type_x509, TLSEXT_cert_type_x509 };
    unsigned char pgp[] = { TLSEXT_cert_type_pgp };
    unsigned char *t = (unsigned char *)"x";
    size_t len = 99;

    printf("# certificate types\n");
    check(SSL_CTX_get0_client_cert_type(ctx, &t, &len) == 1, "SSL_CTX_get0_client_cert_type");
    show_types("ctx client", t, len);
    check(SSL_CTX_set1_client_cert_type(ctx, both, 2) == 1, "SSL_CTX_set1_client_cert_type");
    check(SSL_CTX_set1_server_cert_type(ctx, both + 1, 1) == 1, "SSL_CTX_set1_server_cert_type");
    check(SSL_CTX_set1_client_cert_type(ctx, dup, 2) == 0, "a duplicate");
    check(SSL_CTX_set1_client_cert_type(ctx, pgp, 1) == 0, "OpenPGP");
    check(SSL_CTX_set1_client_cert_type(ctx, NULL, 1) == 0, "NULL with a length");
    check(SSL_CTX_set1_client_cert_type(ctx, both, 0) == 0, "a list without a length");
    SSL_CTX_get0_client_cert_type(ctx, &t, &len);
    show_types("ctx client", t, len);
    SSL_CTX_get0_server_cert_type(ctx, &t, &len);
    show_types("ctx server", t, len);
    check(SSL_CTX_get0_server_cert_type(ctx, NULL, &len) == 0, "a NULL slot");
    s = SSL_new(ctx);
    SSL_get0_client_cert_type(s, &t, &len);
    show_types("ssl client", t, len);
    SSL_get0_server_cert_type(s, &t, &len);
    show_types("ssl server", t, len);
    check(SSL_set1_server_cert_type(s, NULL, 0) == 1, "cleared");
    check(SSL_set1_client_cert_type(s, both + 1, 1) == 1, "SSL_set1_client_cert_type");
    check(SSL_set1_server_cert_type(s, pgp, 1) == 0, "SSL_set1_server_cert_type");
    SSL_get0_client_cert_type(s, &t, &len);
    show_types("ssl client", t, len);
    SSL_get0_server_cert_type(s, &t, &len);
    show_types("ssl server", t, len);
    check(SSL_get0_client_cert_type(s, &t, NULL) == 0 && SSL_get0_client_cert_type(NULL, &t, &len) == 0,
          "NULL arguments");
    SSL_CTX_get0_client_cert_type(ctx, &t, &len);
    show_types("ctx client still", t, len);
    check(SSL_set1_client_cert_type(NULL, both, 2) == 0, "a NULL connection");
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void ciphers(const char *label, SSL *s)
{
    STACK_OF(SSL_CIPHER) *sk = SSL_get1_supported_ciphers(s);
    int i;

    printf("  %s:", label);
    if (sk == NULL)
        printf(" (null)");
    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++)
        printf(" %s", SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)));
    printf("\n");
    sk_SSL_CIPHER_free(sk);
}

static void supported_ciphers(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *s = SSL_new(ctx);

    printf("# supported ciphers\n");
    SSL_set_cipher_list(s, "ECDHE:PSK:aNULL:@SECLEVEL=0");
    ciphers("client", s);
    SSL_set_max_proto_version(s, TLS1_2_VERSION);
    ciphers("TLS 1.2", s);
    SSL_set1_sigalgs_list(s, "RSA+SHA256");
    ciphers("RSA signatures only", s);
    SSL_set_min_proto_version(s, TLS1_3_VERSION);
    SSL_set_max_proto_version(s, TLS1_3_VERSION);
    ciphers("TLS 1.3", s);
    SSL_set_min_proto_version(s, TLS1_2_VERSION);
    SSL_set_cipher_list(s, "AES128:@SECLEVEL=3");
    ciphers("level 3", s);
    check(SSL_get1_supported_ciphers(NULL) == NULL, "a NULL connection");
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static int sec_calls = 0;

/* Refuses X25519 and P-256 (the groups' code points as OpenSSL passes them). */
static int sec_cb(const SSL *s, const SSL_CTX *ctx, int op, int bits, int nid, void *other, void *ex)
{
    (void)s;
    (void)ctx;
    (void)bits;
    (void)ex;
    sec_calls++;
    if ((op & SSL_SECOP_OTHER_TYPE) == SSL_SECOP_OTHER_CURVE
        && (nid == NID_X25519 || nid == NID_X9_62_prime256v1)) {
        (void)other;

        return 0;
    }
    return 1;
}

static void handshake(const char *label, const char *cgroups, const char *sgroups, const char *csigalgs,
                      int custom)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    int nid = 0, r, n, i;

    printf("# handshake: %s\n", label);
    if (cgroups != NULL)
        check(SSL_CTX_set1_groups_list(cctx, cgroups) == 1, "the client's groups");
    if (sgroups != NULL)
        check(SSL_CTX_set1_groups_list(sctx, sgroups) == 1, "the server's groups");
    if (csigalgs != NULL)
        check(SSL_CTX_set1_sigalgs_list(cctx, csigalgs) == 1, "the client's signature algorithms");
    if (custom) {
        sec_calls = 0;
        SSL_CTX_set_security_callback(cctx, sec_cb);
    }
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    r = run(c, s);
    check(r == 0, "the handshake");
    errors();
    if (r == 0) {
        printf("  group: %s %s (%ld)\n", SSL_get0_group_name(c), SSL_get0_group_name(s), SSL_get_negotiated_group(s));
        SSL_get_peer_signature_nid(c, &nid);
        printf("  server signs with %s\n", OBJ_nid2sn(nid));
        n = SSL_get1_groups(s, NULL);
        printf("  the client's groups (%d):", n);
        if (n > 0) {
            int *g = OPENSSL_malloc(sizeof(int) * (size_t)n);

            SSL_get1_groups(s, g);
            for (i = 0; i < n; i++)
                printf(" %d", g[i]);
            OPENSSL_free(g);
        }
        printf("\n");
        n = (int)SSL_get_shared_group(s, -1);
        printf("  shared (%d):", n);
        for (i = 0; i < n; i++)
            printf(" %ld", SSL_get_shared_group(s, i));
        printf(" past the end %ld client %ld\n", SSL_get_shared_group(s, n), SSL_get_shared_group(c, -1));
        if (custom)
            printf("  the security callback ran: %s\n", sec_calls > 0 ? "yes" : "no");
    }
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    groups_lists();
    printf("# implemented groups\n");
    implemented(0, 0);
    implemented(TLS1_2_VERSION, TLS1_2_VERSION);
    implemented(TLS1_3_VERSION, 0);
    sigalgs();
    cert_types();
    supported_ciphers();
    handshake("defaults", NULL, NULL, NULL, 0);
    handshake("P-384", "P-384:X25519", "P-384:P-521", NULL, 0);
    handshake("a key share retried", "*X25519:P-384", "P-384", NULL, 0);
    handshake("tuples", "X25519:P-256:P-384", "P-384 / X25519:P-256", NULL, 0);
    handshake("signature algorithms", NULL, NULL, "ecdsa_secp256r1_sha256", 0);
    handshake("a security callback", "X25519:P-256:P-384", NULL, NULL, 1);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
