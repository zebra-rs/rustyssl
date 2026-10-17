/*
 * Conformance test for certificate requests (X509_REQ_new(3), X509_REQ_get_extensions(3),
 * X509_REQ_sign(3), X509_REQ_verify(3), X509_REQ_add1_attr(3), X509_to_X509_REQ,
 * X509_REQ_to_X509, PEM_read_bio_X509_REQ(3)), in TAP format: requests decoded (RSA, Ed25519,
 * and EC with attributes and requested extensions) with their fields, encodings, and
 * digests; signatures verified and refused; requests built and signed deterministically;
 * attributes added and deleted; extensions requested, merged, and read back (from either
 * attribute in the list, or a changed list); the version rules; copies, references, and the
 * PEM, BIO, and FILE forms; and conversions to and from certificates.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
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

static BIO *out;

static void flush_out(void)
{
    char *data;
    long n = BIO_get_mem_data(out, &data);

    fwrite(data, 1, (size_t)n, stdout);
    (void)BIO_reset(out);
}

static const char LEAF_CSR_PEM[] =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIIBdjCB4AIBADA3MQswCQYDVQQGEwJKUDERMA8GA1UECgwIcnVzdHlzc2wxFTAT\n"
    "BgNVBAMMDGxlYWYuZXhhbXBsZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\n"
    "yLiWzDdX6nR/I0PFfqQMjmzOaP3k2chLl6bgnw/56uRbutdllHGiZYW1WzX5oFvg\n"
    "jGw+ZBQL08v/+SZERezdBninEkAfJy2yk2tuEJUVPpOS9g6v60Lr92whE2pi+U0l\n"
    "NnCCw8UUZ5jMvMxk3EswcvFn0qHOxp/49Rnu8LafswECAwEAAaAAMA0GCSqGSIb3\n"
    "DQEBCwUAA4GBAHbCYhkMYdR9kNdZgUt5XCkGCVoCrJsBbvjH7ZTp8ksM9bpHtHMF\n"
    "hW8OnxIQRdlapXs+4GzUrMADXCw+fKkBpo2Gt9CK0CIDxboHbvZCJeientTR/aFm\n"
    "K4bR/Ugni25wvXWemPna3UESE64G5/HAyIVhwuMOyRWHpmYihVVF4We1\n"
    "-----END CERTIFICATE REQUEST-----\n";

static const char EXT_CSR_PEM[] =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIIBSTCB8QIBADAWMRQwEgYDVQQDDAtyZXEuZXhhbXBsZTBZMBMGByqGSM49AgEG\n"
    "CCqGSM49AwEHA0IABBvEAahVR/WNdx9LPQqKbKfLFF2T2HUN2sQFZ26i0kVOPxHu\n"
    "ZneNEMKqsgf9ARRR3rMutY1gz+hQFrgSpvx4m7ugeTAWBgkqhkiG9w0BCQIxCQwH\n"
    "bXkgdW5pdDAYBgkqhkiG9w0BCQcxCwwJc2VjcmV0MTIzMEUGCSqGSIb3DQEJDjE4\n"
    "MDYwJwYDVR0RBCAwHoILcmVxLmV4YW1wbGWCD3d3dy5yZXEuZXhhbXBsZTALBgNV\n"
    "HQ8EBAMCB4AwCgYIKoZIzj0EAwIDRwAwRAIgP/53i96vRLLjlcMA1tJVxt8lNMal\n"
    "5r3TAB1E341T1XwCIDboBgY5DR1GgQc9sq1B0So6RzQ3z48M+zI3KZrR52+l\n"
    "-----END CERTIFICATE REQUEST-----\n";

static const char ED_CSR_PEM[] =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIGQMEQCAQAwETEPMA0GA1UEAwwGZWQgcmVxMCowBQYDK2VwAyEAuNhxQSv61lvh\n"
    "zOw9ja9vUr7Ox3zmUjSLdY9uES9cEnqgADAFBgMrZXADQQCqZfD4Jf2FBkNpIGmp\n"
    "AIrlYv9+wxgtFX3Q8Voybju3y+IbF8zqgN1qVyGpGaGLijPaVVdYuQd3NYX/RqEP\n"
    "rw8F\n"
    "-----END CERTIFICATE REQUEST-----\n";

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBmTCCAT+gAwIBAgIIEjRWeJCrze8wCgYIKoZIzj0EAwIwMjELMAkGA1UEBhMC\n"
    "SlAxETAPBgNVBAoMCHJ1c3R5c3NsMRAwDgYDVQQDDAdUZXN0IENBMB4XDTI2MTAx\n"
    "NzExNTcyOVoXDTM2MTAxNDExNTcyOVowMjELMAkGA1UEBhMCSlAxETAPBgNVBAoM\n"
    "CHJ1c3R5c3NsMRAwDgYDVQQDDAdUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
    "AQcDQgAEG8QBqFVH9Y13H0s9Copsp8sUXZPYdQ3axAVnbqLSRU4/Ee5md40Qwqqy\n"
    "B/0BFFHesy61jWDP6FAWuBKm/Hibu6M/MD0wDwYDVR0TAQH/BAUwAwEB/zALBgNV\n"
    "HQ8EBAMCAQYwHQYDVR0OBBYEFFT/pnuNPm1SB+yJgcMJY5Cw5uK3MAoGCCqGSM49\n"
    "BAMCA0gAMEUCIHcVN0GtOf7I7yBYW9wwXEqBZhVMdJVutI2PwKohj1fhAiEA/yez\n"
    "gwPyEeIQYZLF0ykw0qkc1dxRgdA6ClD8WGALKOM=\n"
    "-----END CERTIFICATE-----\n";

static const char EC_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOemUpeykgSE1rLlH\n"
    "3fPOAKOIoMBM0znLrB7aLijA3A6hRANCAAQbxAGoVUf1jXcfSz0KimynyxRdk9h1\n"
    "DdrEBWduotJFTj8R7mZ3jRDCqrIH/QEUUd6zLrWNYM/oUBa4Eqb8eJu7\n"
    "-----END PRIVATE KEY-----\n";

static const char RSA_KEY_PEM[] =
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

static const char ED_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIBMZcdaUx3rv5fkNMkj2dpg2fneVU8VRATyitLupcC8e\n"
    "-----END PRIVATE KEY-----\n";

static X509_REQ *read_req(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509_REQ *x = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static EVP_PKEY *read_key(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free(b);
    return k;
}

static void show_der(const char *label, const X509_REQ *x)
{
    unsigned char *der = NULL;
    int len = i2d_X509_REQ(x, &der);

    hex(label, der, len);
    OPENSSL_free(der);
}

static void show_exts(const char *label, STACK_OF(X509_EXTENSION) *exts)
{
    int i;

    if (exts == NULL) {
        printf("  %s: NULL\n", label);
        errors();
        return;
    }
    printf("  %s: %d\n", label, sk_X509_EXTENSION_num(exts));
    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *e = sk_X509_EXTENSION_value(exts, i);

        printf("    %s critical %d, %d octets\n",
               OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(e))),
               X509_EXTENSION_get_critical(e), ASN1_STRING_length(X509_EXTENSION_get_data(e)));
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
}

static void show(const char *label, X509_REQ *x)
{
    const ASN1_BIT_STRING *sig;
    const X509_ALGOR *alg;
    char buf[256];
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    EVP_PKEY *pk = X509_REQ_get0_pubkey(x);
    int i;

    printf("# %s\n", label);
    printf("  version %ld, subject %s\n", X509_REQ_get_version(x),
           X509_NAME_oneline(X509_REQ_get_subject_name(x), buf, sizeof(buf)));
    printf("  key: %s, %d bits\n", pk == NULL ? "(none)" : EVP_PKEY_get0_type_name(pk),
           EVP_PKEY_get_bits(pk));
    check(X509_PUBKEY_get0(X509_REQ_get_X509_PUBKEY(x)) == pk, "the SubjectPublicKeyInfo's key");
    X509_REQ_get0_signature(x, &sig, &alg);
    printf("  signature nid %d (%s), %d octets\n", X509_REQ_get_signature_nid(x),
           OBJ_nid2sn(X509_REQ_get_signature_nid(x)), ASN1_STRING_length(sig));
    printf("  attributes: %d\n", X509_REQ_get_attr_count(x));
    for (i = 0; i < X509_REQ_get_attr_count(x); i++) {
        X509_ATTRIBUTE *a = X509_REQ_get_attr(x, i);
        ASN1_TYPE *t = X509_ATTRIBUTE_get0_type(a, 0);

        printf("    %s: %d values, the first of type %d\n",
               OBJ_nid2sn(OBJ_obj2nid(X509_ATTRIBUTE_get0_object(a))), X509_ATTRIBUTE_count(a),
               t == NULL ? -1 : t->type);
    }
    show_exts("extensions", X509_REQ_get_extensions(x));
    check(X509_REQ_digest(x, EVP_sha256(), md, &mdlen) == 1, "digest");
    hex("sha256", md, mdlen);
    printf("  verifies with its own key: %d\n", X509_REQ_verify(x, pk));
}

static void test_decode(void)
{
    X509_REQ *leaf = read_req(LEAF_CSR_PEM), *ext = read_req(EXT_CSR_PEM), *ed = read_req(ED_CSR_PEM);
    X509_REQ *y, *z;
    EVP_PKEY *rsa = read_key(RSA_KEY_PEM), *ec = read_key(EC_KEY_PEM);
    unsigned char *der = NULL, *p;
    const unsigned char *q;
    int len, n;
    char *pem;
    long plen;
    BIO *b;
    FILE *f;
    X509_REQ_INFO *ri;

    check(leaf != NULL && ext != NULL && ed != NULL, "requests read");
    show("RSA", leaf);
    show("EC with attributes", ext);
    show("Ed25519", ed);

    printf("# keys and signatures\n");
    printf("  private keys: %d %d\n", X509_REQ_check_private_key(leaf, rsa),
           X509_REQ_check_private_key(ext, ec));
    printf("  the wrong key: %d\n", X509_REQ_check_private_key(leaf, ec));
    errors();
    printf("  verify with the wrong key: %d\n", X509_REQ_verify(leaf, X509_REQ_get0_pubkey(ext)));
    errors();
    printf("  verify_ex: %d\n", X509_REQ_verify_ex(ext, X509_REQ_get0_pubkey(ext), NULL, NULL));

    printf("# encodings\n");
    len = i2d_X509_REQ(ext, &der);
    q = der;
    y = d2i_X509_REQ(NULL, &q, len);
    check(y != NULL && q == der + len, "decoded");
    p = NULL;
    n = i2d_X509_REQ(y, &p);
    check(n == len && memcmp(p, der, (size_t)n) == 0, "and encoded as it was");
    OPENSSL_free(p);
    p = NULL;
    n = i2d_re_X509_REQ_tbs(y, &p);
    q = p;
    ri = d2i_X509_REQ_INFO(NULL, &q, n);
    check(ri != NULL, "the CertificationRequestInfo decoded");
    printf("  tbs %d, again %d\n", n, i2d_X509_REQ_INFO(ri, NULL));
    X509_REQ_INFO_free(ri);
    OPENSSL_free(p);
    q = der;
    check(d2i_X509_REQ(&y, &q, len - 2) == NULL, "cut short");
    errors();
    X509_REQ_free(y);
    z = X509_REQ_dup(ext);
    check(z != NULL && i2d_X509_REQ(z, NULL) == len, "copied");
    check(X509_REQ_get0_pubkey(z) != X509_REQ_get0_pubkey(ext), "with its own key");
    check(EVP_PKEY_eq(X509_REQ_get0_pubkey(z), X509_REQ_get0_pubkey(ext)) == 1, "the same key");
    X509_REQ_free(z);
    b = BIO_new(BIO_s_mem());
    check(i2d_X509_REQ_bio(b, ext) == 1, "to a BIO");
    y = d2i_X509_REQ_bio(b, NULL);
    check(y != NULL, "from a BIO");
    X509_REQ_free(y);
    BIO_free(b);
    f = tmpfile();
    check(i2d_X509_REQ_fp(f, ext) == 1, "to a FILE");
    rewind(f);
    y = d2i_X509_REQ_fp(f, NULL);
    check(y != NULL, "from a FILE");
    X509_REQ_free(y);
    rewind(f);
    check(PEM_write_X509_REQ(f, ext) == 1, "PEM to a FILE");
    rewind(f);
    y = PEM_read_X509_REQ(f, NULL, NULL, NULL);
    check(y != NULL, "PEM from a FILE");
    X509_REQ_free(y);
    fclose(f);
    check(PEM_write_bio_X509_REQ(out, ext) == 1, "PEM written");
    plen = BIO_get_mem_data(out, &pem);
    check(plen == (long)strlen(EXT_CSR_PEM) && memcmp(pem, EXT_CSR_PEM, (size_t)plen) == 0,
          "as it was read");
    (void)BIO_reset(out);
    check(PEM_write_bio_X509_REQ_NEW(out, ed) == 1, "the old PEM name");
    plen = BIO_get_mem_data(out, &pem);
    printf("  %.*s", (int)(strchr(pem, '\n') - pem + 1), pem);
    y = PEM_read_bio_X509_REQ(out, NULL, NULL, NULL);
    check(y != NULL, "read back");
    X509_REQ_free(y);
    (void)BIO_reset(out);
    f = tmpfile();
    check(PEM_write_X509_REQ_NEW(f, ed) == 1, "the old name to a FILE");
    fclose(f);
    OPENSSL_free(der);
    X509_REQ_free(leaf);
    X509_REQ_free(ext);
    X509_REQ_free(ed);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
}

static STACK_OF(X509_EXTENSION) *two_exts(int first, int second)
{
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();

    ASN1_OCTET_STRING_set(os, (const unsigned char *)"\x30\x00", 2);
    sk_X509_EXTENSION_push(exts, X509_EXTENSION_create_by_NID(NULL, first, 1, os));
    ASN1_OCTET_STRING_set(os, (const unsigned char *)"\x03\x02\x07\x80", 4);
    sk_X509_EXTENSION_push(exts, X509_EXTENSION_create_by_NID(NULL, second, 0, os));
    ASN1_OCTET_STRING_free(os);
    return exts;
}

static void test_build(void)
{
    X509_REQ *x = X509_REQ_new(), *d;
    EVP_PKEY *ed = read_key(ED_KEY_PEM), *rsa = read_key(RSA_KEY_PEM);
    X509_NAME *n = X509_NAME_new();
    STACK_OF(X509_EXTENSION) *exts;
    X509_ATTRIBUTE *a;
    ASN1_BIT_STRING *bs;
    X509_ALGOR *alg = X509_ALGOR_new();
    int nids[] = { NID_ms_ext_req, NID_undef }, *saved;
    int r;

    printf("# building\n");
    printf("  new: version %ld, attributes %d, extensions:\n", X509_REQ_get_version(x),
           X509_REQ_get_attr_count(x));
    show_exts("extensions", X509_REQ_get_extensions(x));
    show_der("empty", x);
    errors();
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"built", -1, -1, 0);
    check(X509_REQ_set_subject_name(x, n) == 1, "subject set");
    check(X509_REQ_set_pubkey(x, ed) == 1, "key set");
    printf("  set_version 1: %d, 3: %d\n", X509_REQ_set_version(x, X509_REQ_VERSION_1),
           X509_REQ_set_version(x, 2));
    errors();
    r = X509_REQ_sign(x, ed, NULL);
    printf("  signed: %d\n", r);
    show_der("Ed25519", x);
    check(X509_REQ_verify(x, ed) == 1, "verifies");

    printf("# attributes\n");
    check(X509_REQ_add1_attr_by_txt(x, "challengePassword", MBSTRING_ASC,
                                    (const unsigned char *)"pw", -1) == 1, "by name");
    check(X509_REQ_add1_attr_by_NID(x, NID_pkcs9_unstructuredName, V_ASN1_UTF8STRING,
                                    (const unsigned char *)"unit", 4) == 1, "by NID");
    check(X509_REQ_add1_attr_by_OBJ(x, OBJ_nid2obj(NID_pkcs9_emailAddress), MBSTRING_ASC,
                                    (const unsigned char *)"a@b.c", -1) == 1, "by object");
    printf("  unknown name: %d\n", X509_REQ_add1_attr_by_txt(x, "nosuch", MBSTRING_ASC,
                                                           (const unsigned char *)"x", -1));
    errors();
    printf("  count %d, by NID %d, by OBJ %d\n", X509_REQ_get_attr_count(x),
           X509_REQ_get_attr_by_NID(x, NID_pkcs9_unstructuredName, -1),
           X509_REQ_get_attr_by_OBJ(x, OBJ_nid2obj(NID_pkcs9_emailAddress), -1));
    printf("  verifies after the change: %d\n", X509_REQ_verify(x, ed));
    errors();
    a = X509_REQ_delete_attr(x, 2);
    check(a != NULL && X509_REQ_get_attr_count(x) == 2, "one deleted");
    check(X509_REQ_add1_attr(x, a) == 1, "and added back");
    X509_ATTRIBUTE_free(a);
    check(X509_REQ_delete_attr(x, 9) == NULL, "none at 9");

    printf("# extensions\n");
    exts = two_exts(NID_basic_constraints, NID_key_usage);
    check(X509_REQ_add_extensions(x, exts) == 1, "added");
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    show_exts("read back", X509_REQ_get_extensions(x));
    exts = two_exts(NID_key_usage, NID_ext_key_usage);
    check(X509_REQ_add_extensions(x, exts) == 1, "more, merged");
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    show_exts("merged", X509_REQ_get_extensions(x));
    printf("  attributes now %d, the extensions at %d\n", X509_REQ_get_attr_count(x),
           X509_REQ_get_attr_by_NID(x, NID_ext_req, -1));
    check(X509_REQ_add_extensions(x, NULL) == 1, "none to add");
    exts = two_exts(NID_subject_key_identifier, NID_crl_distribution_points);
    check(X509_REQ_add_extensions_nid(x, exts, NID_ms_ext_req) == 1, "as Microsoft's");
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    printf("  is an extension NID: %d %d %d\n", X509_REQ_extension_nid(NID_ext_req),
           X509_REQ_extension_nid(NID_ms_ext_req), X509_REQ_extension_nid(NID_commonName));
    saved = X509_REQ_get_extension_nids();
    printf("  the list: %d %d %d\n", saved[0], saved[1], saved[2]);
    X509_REQ_set_extension_nids(nids);
    show_exts("Microsoft's only", X509_REQ_get_extensions(x));
    check(X509_REQ_extension_nid(NID_ext_req) == 0, "extensionRequest isn't one now");
    X509_REQ_set_extension_nids(saved);
    show_exts("the first again", X509_REQ_get_extensions(x));
    printf("  a second extensionRequest: %d\n",
           X509_REQ_add1_attr_by_NID(x, NID_ext_req, V_ASN1_UTF8STRING,
                                     (const unsigned char *)"x", 1));
    errors();
    show_exts("still the first", X509_REQ_get_extensions(x));
    d = X509_REQ_new();
    X509_REQ_add1_attr_by_NID(d, NID_ext_req, V_ASN1_UTF8STRING, (const unsigned char *)"x", 1);
    show_exts("a broken one", X509_REQ_get_extensions(d));
    X509_REQ_free(d);

    printf("# signing again\n");
    r = X509_REQ_sign(x, rsa, EVP_sha256());
    printf("  RSA signed: %d\n", r);
    show_der("RSA", x);
    check(X509_REQ_verify(x, rsa) == 1, "verifies");
    X509_REQ_get0_signature(x, (const ASN1_BIT_STRING **)&bs, NULL);
    bs = ASN1_STRING_dup(bs);
    X509_REQ_set0_signature(x, bs);
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha512WithRSAEncryption), V_ASN1_NULL, NULL);
    check(X509_REQ_set1_signature_algo(x, alg) == 1, "AlgorithmIdentifier set");
    printf("  after: nid %d, verify %d\n", X509_REQ_get_signature_nid(x), X509_REQ_verify(x, rsa));
    errors();
    X509_REQ_free(x);
    X509_NAME_free(n);
    X509_ALGOR_free(alg);
    EVP_PKEY_free(ed);
    EVP_PKEY_free(rsa);
}

static void test_convert(void)
{
    BIO *b = BIO_new_mem_buf(CA_PEM, -1);
    X509 *ca = PEM_read_bio_X509(b, NULL, NULL, NULL), *c;
    EVP_PKEY *ec = read_key(EC_KEY_PEM), *rsa = read_key(RSA_KEY_PEM);
    X509_REQ *x;
    char buf[256];
    int days;

    BIO_free(b);
    printf("# conversions\n");
    x = X509_to_X509_REQ(ca, NULL, NULL);
    check(x != NULL, "a request for the certificate, unsigned");
    show_der("unsigned", x);
    X509_REQ_free(x);
    x = X509_to_X509_REQ(ca, ec, EVP_sha384());
    check(x != NULL && X509_REQ_verify(x, ec) == 1, "signed");
    printf("  nid %d, version %ld, attributes %d\n", X509_REQ_get_signature_nid(x),
           X509_REQ_get_version(x), X509_REQ_get_attr_count(x));
    c = X509_REQ_to_X509(x, 30, ec);
    printf("  a certificate signed by EC with MD5: %p\n", (void *)c);
    errors();
    c = X509_REQ_to_X509(x, 30, rsa);
    check(c != NULL, "a certificate for it, RSA with MD5");
    printf("  version %ld, nid %d (%s), subject %s, issued by itself %d\n", X509_get_version(c),
           X509_get_signature_nid(c), OBJ_nid2sn(X509_get_signature_nid(c)),
           X509_NAME_oneline(X509_get_subject_name(c), buf, sizeof(buf)),
           X509_NAME_cmp(X509_get_issuer_name(c), X509_get_subject_name(c)));
    ASN1_TIME_diff(&days, NULL, X509_get0_notBefore(c), X509_get0_notAfter(c));
    printf("  valid for %d days, verifies %d\n", days, X509_verify(c, rsa));
    errors();
    X509_free(c);
    X509_REQ_add1_attr_by_txt(x, "challengePassword", MBSTRING_ASC, (const unsigned char *)"p", -1);
    c = X509_REQ_to_X509(x, 1, rsa);
    printf("  with an attribute: version %ld\n", c == NULL ? -1 : X509_get_version(c));
    errors();
    X509_free(c);
    X509_REQ_free(x);
    X509_free(ca);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(rsa);
}

static void test_misc(void)
{
    X509_REQ *x = X509_REQ_new_ex(NULL, "provider=default");
    ASN1_OCTET_STRING *id = ASN1_OCTET_STRING_new();
    X509_REQ_INFO *ri = X509_REQ_INFO_new();
    unsigned char *der = NULL;
    int len;

    printf("# misc\n");
    len = i2d_X509_REQ_INFO(ri, &der);
    printf("  a new CertificationRequestInfo: %d\n", len);
    errors();
    OPENSSL_free(der);
    X509_REQ_INFO_free(ri);
    check(ASN1_ITEM_rptr(X509_REQ) != NULL && ASN1_ITEM_rptr(X509_REQ_INFO) != NULL, "the items");
    check(x != NULL, "new in a library context");
    X509_REQ_set0_distinguishing_id(x, id);
    check(X509_REQ_get0_distinguishing_id(x) == id, "distinguishing ID");
    X509_REQ_set0_distinguishing_id(x, NULL);
    printf("  NULL request: sign %d, tbs %d, delete %p, add %d, verify %d\n",
           X509_REQ_sign(NULL, NULL, NULL), i2d_re_X509_REQ_tbs(NULL, NULL),
           (void *)X509_REQ_delete_attr(NULL, 0), X509_REQ_add1_attr(NULL, NULL),
           X509_REQ_get_pubkey(NULL) == NULL);
    errors();
    printf("  sign_ctx NULL: %d, set_version NULL: %d\n", X509_REQ_sign_ctx(NULL, NULL),
           X509_REQ_set_version(NULL, 0));
    errors();
    X509_REQ_free(x);
    X509_REQ_free(NULL);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    out = BIO_new(BIO_s_mem());
    test_decode();
    test_build();
    test_convert();
    test_misc();
    flush_out();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
