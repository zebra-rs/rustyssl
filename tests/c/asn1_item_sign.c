/*
 * Conformance test for signing and verifying ASN.1 items (ASN1_item_sign(3),
 * ASN1_item_verify(3), ASN1_item_sign_ctx, ASN1_item_verify_ctx, their _ex forms, and the
 * deprecated ASN1_sign and ASN1_verify), in TAP format: a name signed and verified with RSA
 * (PKCS #1 and PSS, provided and legacy keys), RSA-PSS keys with restrictions, EC, Ed25519,
 * Ed448, and SM2 with a distinguishing ID; the AlgorithmIdentifiers each sets; signatures that
 * don't verify (changed data, another ID, bits left over, an unknown algorithm, the wrong kind
 * of key); and contexts that aren't ready.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
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

static void hex(const char *label, const unsigned char *p, long n)
{
    long i;

    printf("  %s (%ld):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : " ", p[i]);
    printf("\n");
}

static const char RSA_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMi4lsw3V+p0fyND\n"
    "xX6kDI5szmj95NnIS5em4J8P+erkW7rXZZRxomWFtVs1+aBb4IxsPmQUC9PL//km\n"
    "REXs3QZ4pxJAHyctspNrbhCVFT6TkvYOr+tC6/dsIRNqYvlNJTZwgsPFFGeYzLzM\n"
    "ZNxLMHLxZ9Khzsaf+PUZ7vC2n7MBAgMBAAECgYEAna18MMLNGo4XjgFgNOL0RjIt\n"
    "WAcTbw3MbD6Yt/uZ7S8k7DrnPlyiITSPSi61gYaLeGRUAtRIkkHwPK4V9gRjf5r0\n"
    "+ddHrpzJKpQlMV0QEhuOXfIpRQK0coyUV9Aug7LmxfRIJqdyyVDCgwknlN7SO1Go\n"
    "2leIw4ewwnrzxzNPzBECQQD6uCGV2ZOSlXTFDNEb3LFH0Z3jnOC3OrGSlMxc7Lzj\n"
    "r3gDCjpO6ZkFSS42I8uB0hG0zfcKE1yr3RZskAz0WBYNAkEAzPLekFt+97fO0dIm\n"
    "vnIz0oSbjFXwyH/D5eAXoc9sccL+GvnunAkjo2lxPaVWElW40/+SETH34HdLLIlW\n"
    "23XnxQJALdidy5kNszBBOgct9bpVcJyUEpsNPHQvJG6xMAzaPYhImcW1A9kTcjP/\n"
    "j0bcX9DaDAXdtqnzuDmlcBSnSccRwQJBAJOpQHWdlmMACYDe+o8oVPIOHMwFd0/d\n"
    "zdSnmh85BRcJuG7TN/kwFH8+DxqtLtBS9rG3ZxQAfmk5Se4ynWPNFUkCQQCIE0V3\n"
    "+0aLGAjIN2UVYnm0ySml9rRU1fyu5n7+VjTMZESK4drPYcHUIIw/SSPRnqIqjtb5\n"
    "h7EBN26AcOWkTIGi\n"
    "-----END PRIVATE KEY-----\n";

static const char PSS_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICjAIBADAjBgkqhkiG9w0BAQowFqAPMA0GCWCGSAFlAwQCAQUAogMCASAEggJg\n"
    "MIICXAIBAAKBgQCgiPp0IaUC+j11kwX6dplX2X9V1cgmzX/K3SoCVpZAP4OliSJX\n"
    "X6d1SI7xx6ReXgK7ct/ZXv9CPxl/5Khj+1RnUxiWEY1fiV8/vw/nizTP4mJYnLj9\n"
    "o9GowjHEV9q9dp/t2sRNM/DuHC1VzV/qnzdYfK2YHLPI7LcC0cNHam0P8QIDAQAB\n"
    "AoGBAIKEGyuDlwa+sG0ApWGmPrF/sNj2QA3cEUO7X8Ya43lEqiFRRsxGhn0CCsVj\n"
    "jKz0PcBserXdWCZh6rdiDc2LrmgxLIeOVEzonxGc+bLe6p4Ya8OIHmOSg2Q6+ium\n"
    "MM9ud0tPi0UjZnZ57cvxUbE53gkrepKGUhExVYwyAROnlGjhAkEAzQJOEA9k2rL/\n"
    "MY6HdxFLfuMtlTgCh6IAS5M0C8gdjWKTBUe0FQHxsdyMd+TXZEyAxrw+QgOhCZjS\n"
    "Q67jHDrSdQJBAMh22cibJZ8igxZEe3PUgUocG0fC4fLhiALa1ud4qFAkQaxCn0ve\n"
    "SSStEI/ZXjkMDosdl4qVIw59ksX1/9ji4A0CQBwNnLEF6j8jD1iwsEjSzQnn/GzW\n"
    "5UG6IWA2HIEgOSsHuiaW0UWupmw4SeB+KBtJfLW1PK+732V4zA0G+Xz7b6ECQHTM\n"
    "0v3Qb+41pJ1Pz4JguegdUkPQp+flQmMvcPGzWpY/WchtlPUWkhV9hN3br8ubW8nw\n"
    "twA2/xMNVXxkZerP3e0CQAyTXZ90gssH7nTlJJ54OQDC220j28kfLZBTWK/evyRT\n"
    "z9EBzQkcSf3b6AgMlGDWfhsxB36iznjBrYHMPa/ovpo=\n"
    "-----END PRIVATE KEY-----\n";

static const char EC_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOemUpeykgSE1rLlH\n"
    "3fPOAKOIoMBM0znLrB7aLijA3A6hRANCAAQbxAGoVUf1jXcfSz0KimynyxRdk9h1\n"
    "DdrEBWduotJFTj8R7mZ3jRDCqrIH/QEUUd6zLrWNYM/oUBa4Eqb8eJu7\n"
    "-----END PRIVATE KEY-----\n";

static const char ED25519_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIBMZcdaUx3rv5fkNMkj2dpg2fneVU8VRATyitLupcC8e\n"
    "-----END PRIVATE KEY-----\n";

static const char ED448_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MEcCAQAwBQYDK2VxBDsEOcynKXP3TsTJPMm9iRuYHyxLTvEiujkGLlo6LcBLPPOC\n"
    "Qymz8964oFIVIqi1M32nCgFh3kGcXJMIOg==\n"
    "-----END PRIVATE KEY-----\n";

static const char SM2_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgViyNy/bE8KxG+8TU\n"
    "n6QRMu5rbBBVwn9rcnuIQdXi4N2hRANCAASdaIvAlB6n915dB6SzJV+GDklvcBgD\n"
    "HyhB1PFPyMVjxstXzrsSBWTkxLYanfamtKPv7mHe4EJ9duIVFumuUK3Y\n"
    "-----END PRIVATE KEY-----\n";

static EVP_PKEY *key(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free(b);
    return k;
}

static X509_NAME *name(const char *cn)
{
    X509_NAME *n = X509_NAME_new();

    X509_NAME_add_entry_by_txt(n, "O", MBSTRING_ASC, (const unsigned char *)"rustyssl", -1, -1, 0);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    return n;
}

static void show_algor(const char *label, const X509_ALGOR *a)
{
    unsigned char *der = NULL;
    int len = i2d_X509_ALGOR(a, &der);

    hex(label, der, len);
    OPENSSL_free(der);
}

/* The signature's flags (bits left) and, when `deterministic`, its octets. */
static void show_sig(const ASN1_BIT_STRING *sig, int deterministic)
{
    printf("  signature flags %lx\n", sig->flags);
    if (deterministic)
        hex("octets", ASN1_STRING_get0_data(sig), ASN1_STRING_length(sig));
    else
        printf("  signature made: %d\n", ASN1_STRING_length(sig) > 0);
}

/* Signs a name with `k` and `md`, shows both AlgorithmIdentifiers and the signature, and checks
 * it verifies, and that a changed name doesn't. */
static void sign_verify(const char *label, EVP_PKEY *k, const EVP_MD *md, int deterministic)
{
    X509_NAME *n = name(label), *other = name("someone else");
    X509_ALGOR *a1 = X509_ALGOR_new(), *a2 = X509_ALGOR_new();
    ASN1_BIT_STRING *sig = ASN1_BIT_STRING_new();
    int r;

    printf("# %s\n", label);
    r = ASN1_item_sign(ASN1_ITEM_rptr(X509_NAME), a1, a2, sig, n, k, md);
    printf("  sign: %d\n", r > 0 ? 1 : r);
    if (r <= 0)
        errors();
    check(r == ASN1_STRING_length(sig), "returns the signature's length");
    show_algor("algorithm", a1);
    check(X509_ALGOR_cmp(a1, a2) == 0, "both AlgorithmIdentifiers set alike");
    show_sig(sig, deterministic);
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), a1, sig, n, k);
    check(r == 1, "verifies");
    if (r != 1)
        errors();
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), a1, sig, other, k);
    printf("  changed data: %d\n", r);
    errors();
    {
        /* Through a digest context whose key context has the key. */
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(k, NULL);

        EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
        r = ASN1_item_verify_ctx(ASN1_ITEM_rptr(X509_NAME), a1, sig, n, mctx);
        check(r == 1, "verifies through a context");
        if (r != 1)
            errors();
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_CTX_free(pctx);
    }
    X509_NAME_free(n);
    X509_NAME_free(other);
    X509_ALGOR_free(a1);
    X509_ALGOR_free(a2);
    ASN1_BIT_STRING_free(sig);
}

static void test_keys(void)
{
    EVP_PKEY *rsa = key(RSA_PEM), *pss = key(PSS_PEM), *ec = key(EC_PEM);
    EVP_PKEY *ed25519 = key(ED25519_PEM), *ed448 = key(ED448_PEM);
    EVP_PKEY *legacy = EVP_PKEY_new();
    RSA *r = EVP_PKEY_get1_RSA(rsa);

    check(rsa != NULL && pss != NULL && ec != NULL && ed25519 != NULL && ed448 != NULL, "keys read");
    check(EVP_PKEY_set1_RSA(legacy, r) == 1, "a legacy RSA key");
    RSA_free(r);
    sign_verify("RSA SHA-256", rsa, EVP_sha256(), 1);
    sign_verify("RSA SHA-1", rsa, EVP_sha1(), 1);
    sign_verify("legacy RSA SHA-384", legacy, EVP_sha384(), 1);
    sign_verify("RSA-PSS key SHA-256", pss, EVP_sha256(), 0);
    sign_verify("EC SHA-256", ec, EVP_sha256(), 0);
    sign_verify("EC SHA3-256", ec, EVP_sha3_256(), 0);
    sign_verify("Ed25519", ed25519, NULL, 1);
    sign_verify("Ed448", ed448, NULL, 1);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(pss);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(ed25519);
    EVP_PKEY_free(ed448);
    EVP_PKEY_free(legacy);
}

/* PSS through a context: the AlgorithmIdentifier from its settings, verified by the item's
 * AlgorithmIdentifier alone (the legacy method's item_verify for a legacy key). */
static void pss_ctx(const char *label, EVP_PKEY *k, int saltlen, const EVP_MD *mgf1)
{
    X509_NAME *n = name(label);
    X509_ALGOR *a1 = X509_ALGOR_new();
    ASN1_BIT_STRING *sig = ASN1_BIT_STRING_new();
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int r;

    printf("# %s\n", label);
    check(EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), NULL, k) == 1, "sign init");
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltlen);
    if (mgf1 != NULL)
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1);
    r = ASN1_item_sign_ctx(ASN1_ITEM_rptr(X509_NAME), a1, NULL, sig, n, mctx);
    printf("  sign: %d\n", r > 0 ? 1 : r);
    if (r <= 0)
        errors();
    show_algor("algorithm", a1);
    show_sig(sig, 0);
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), a1, sig, n, k);
    check(r == 1, "verifies");
    if (r != 1)
        errors();
    EVP_MD_CTX_free(mctx);
    X509_NAME_free(n);
    X509_ALGOR_free(a1);
    ASN1_BIT_STRING_free(sig);
}

static void test_pss(void)
{
    EVP_PKEY *rsa = key(RSA_PEM), *legacy = EVP_PKEY_new();
    RSA *r = EVP_PKEY_get1_RSA(rsa);

    EVP_PKEY_set1_RSA(legacy, r);
    RSA_free(r);
    pss_ctx("PSS digest salt", rsa, RSA_PSS_SALTLEN_DIGEST, NULL);
    pss_ctx("PSS max salt, MGF1 SHA-1", rsa, RSA_PSS_SALTLEN_MAX, EVP_sha1());
    pss_ctx("PSS salt 20", rsa, 20, NULL);
    pss_ctx("legacy PSS digest salt", legacy, RSA_PSS_SALTLEN_DIGEST, NULL);
    pss_ctx("legacy PSS auto digest max", legacy, RSA_PSS_SALTLEN_AUTO_DIGEST_MAX, EVP_sha512());
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(legacy);
}

static void test_id(void)
{
    EVP_PKEY *k = key(SM2_PEM);
    X509_NAME *n = name("SM2");
    X509_ALGOR *a1 = X509_ALGOR_new();
    ASN1_BIT_STRING *sig = ASN1_BIT_STRING_new();
    ASN1_OCTET_STRING *id = ASN1_OCTET_STRING_new(), *other = ASN1_OCTET_STRING_new();
    int r;

    printf("# SM2 with an ID\n");
    ASN1_OCTET_STRING_set(id, (const unsigned char *)"alice@example.com", -1);
    ASN1_OCTET_STRING_set(other, (const unsigned char *)"bob@example.com", -1);
    r = ASN1_item_sign_ex(ASN1_ITEM_rptr(X509_NAME), a1, NULL, sig, n, id, k, EVP_sm3(), NULL, NULL);
    printf("  sign: %d\n", r > 0 ? 1 : r);
    if (r <= 0)
        errors();
    show_algor("algorithm", a1);
    r = ASN1_item_verify_ex(ASN1_ITEM_rptr(X509_NAME), a1, sig, n, id, k, NULL, NULL);
    check(r == 1, "verifies with the ID");
    if (r != 1)
        errors();
    r = ASN1_item_verify_ex(ASN1_ITEM_rptr(X509_NAME), a1, sig, n, other, k, NULL, NULL);
    printf("  another ID: %d\n", r);
    errors();
    r = ASN1_item_verify_ex(ASN1_ITEM_rptr(X509_NAME), a1, sig, n, NULL, k, NULL, NULL);
    printf("  the default ID: %d\n", r);
    errors();
    EVP_PKEY_free(k);
    X509_NAME_free(n);
    X509_ALGOR_free(a1);
    ASN1_BIT_STRING_free(sig);
    ASN1_OCTET_STRING_free(id);
    ASN1_OCTET_STRING_free(other);
}

static void test_failures(void)
{
    EVP_PKEY *rsa = key(RSA_PEM), *ec = key(EC_PEM), *ed = key(ED25519_PEM);
    X509_NAME *n = name("failures");
    X509_ALGOR *a1 = X509_ALGOR_new(), *bad = X509_ALGOR_new();
    ASN1_BIT_STRING *sig = ASN1_BIT_STRING_new();
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx;
    int r;

    printf("# failures\n");
    r = ASN1_item_sign(ASN1_ITEM_rptr(X509_NAME), a1, NULL, sig, n, ed, EVP_sha256());
    printf("  Ed25519 with SHA-256: %d\n", r);
    errors();
    r = ASN1_item_sign(ASN1_ITEM_rptr(X509_NAME), a1, NULL, sig, n, rsa, EVP_md5_sha1());
    printf("  RSA with MD5-SHA1: %d\n", r);
    errors();
    /* A context with a key, but not for signing. */
    EVP_DigestInit_ex(mctx, EVP_sha256(), NULL);
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx = EVP_PKEY_CTX_new(rsa, NULL));
    r = ASN1_item_sign_ctx(ASN1_ITEM_rptr(X509_NAME), a1, NULL, sig, n, mctx);
    printf("  a context not initialised for signing: %d\n", r);
    errors();
    EVP_MD_CTX_set_pkey_ctx(mctx, NULL);
    EVP_PKEY_CTX_free(pctx);
    r = ASN1_item_sign(ASN1_ITEM_rptr(X509_NAME), a1, NULL, sig, n, rsa, EVP_sha256());
    check(r > 0, "signed");
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), a1, sig, n, ec);
    printf("  an EC key for an RSA signature: %d\n", r);
    errors();
    X509_ALGOR_set0(bad, OBJ_txt2obj("1.2.3.4", 1), V_ASN1_UNDEF, NULL);
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), bad, sig, n, rsa);
    printf("  an unknown algorithm: %d\n", r);
    errors();
    X509_ALGOR_set0(bad, OBJ_nid2obj(NID_rsassaPss), V_ASN1_UNDEF, NULL);
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), bad, sig, n, rsa);
    printf("  PSS without parameters: %d\n", r);
    errors();
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), bad, sig, n, ec);
    printf("  PSS with an EC key: %d\n", r);
    errors();
    X509_ALGOR_set0(bad, OBJ_nid2obj(NID_ED25519), V_ASN1_NULL, NULL);
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), bad, sig, n, ed);
    printf("  Ed25519 with a NULL parameter: %d\n", r);
    errors();
    X509_ALGOR_set0(bad, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);
    sig->flags = (sig->flags & ~0x07L) | ASN1_STRING_FLAG_BITS_LEFT | 3;
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), bad, sig, n, rsa);
    printf("  bits left: %d\n", r);
    errors();
    sig->flags &= ~0x07L;
    ASN1_STRING_set(sig, "\x01\x02", 2);
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), bad, sig, n, rsa);
    printf("  a short signature: %d\n", r);
    errors();
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), a1, sig, n, NULL);
    printf("  no key: %d\n", r);
    errors();
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(ed);
    X509_NAME_free(n);
    X509_ALGOR_free(a1);
    X509_ALGOR_free(bad);
    ASN1_BIT_STRING_free(sig);
}

/* The deprecated forms, over an i2d function. */
static void test_old(void)
{
    EVP_PKEY *rsa = key(RSA_PEM);
    X509_NAME *n = name("old"), *other = name("other");
    X509_ALGOR *a1 = X509_ALGOR_new(), *a2 = X509_ALGOR_new();
    ASN1_BIT_STRING *sig = ASN1_BIT_STRING_new();
    int r;

    printf("# ASN1_sign, ASN1_verify\n");
    X509_ALGOR_set0(a2, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_UNDEF, NULL);
    r = ASN1_sign((i2d_of_void *)i2d_X509_NAME, a1, a2, sig, (char *)n, rsa, EVP_sha256());
    printf("  sign: %d\n", r);
    show_algor("algorithm", a1);
    show_algor("second algorithm", a2);
    show_sig(sig, 1);
    r = ASN1_verify((i2d_of_void *)i2d_X509_NAME, a1, sig, (char *)n, rsa);
    check(r == 1, "verifies");
    if (r != 1)
        errors();
    r = ASN1_verify((i2d_of_void *)i2d_X509_NAME, a1, sig, (char *)other, rsa);
    printf("  changed data: %d\n", r);
    errors();
    r = ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), a1, sig, n, rsa);
    check(r == 1, "the item form verifies it too");
    r = ASN1_sign((i2d_of_void *)i2d_X509_NAME, a1, NULL, sig, (char *)n, rsa, EVP_md5_sha1());
    printf("  MD5-SHA1: %d\n", r);
    errors();
    X509_ALGOR_set0(a1, OBJ_txt2obj("1.2.3.4", 1), V_ASN1_UNDEF, NULL);
    r = ASN1_verify((i2d_of_void *)i2d_X509_NAME, a1, sig, (char *)n, rsa);
    printf("  an unknown algorithm: %d\n", r);
    errors();
    EVP_PKEY_free(rsa);
    X509_NAME_free(n);
    X509_NAME_free(other);
    X509_ALGOR_free(a1);
    X509_ALGOR_free(a2);
    ASN1_BIT_STRING_free(sig);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    test_keys();
    test_pss();
    test_id();
    test_failures();
    test_old();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
