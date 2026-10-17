/*
 * Conformance test for certificates (X509_new(3), d2i_X509(3), X509_get_subject_name(3),
 * X509_get0_notBefore(3), X509_get_ext(3), X509_sign(3), X509_verify(3), X509_digest(3),
 * X509_check_private_key(3), X509_cmp_time(3), PEM_read_bio_X509(3)), in TAP format:
 * certificates decoded (EC, RSA-PSS, Ed25519, a leaf an EC CA issued, and OpenSSL's trusted
 * form) and their fields, encodings (re-encoded byte for byte until a setter changes them),
 * fingerprints, hashes, and comparisons; signatures verified and refused; certificates built
 * and signed (deterministically, Ed25519 and RSA); the extension list; the trusted form and
 * the PEM, BIO, and FILE forms; references, copies, and ex_data; the time helpers; and the
 * Suite B check.
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

static const char LEAF_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIB4jCCAYegAwIBAgIBAjAKBggqhkjOPQQDAjAyMQswCQYDVQQGEwJKUDERMA8G\n"
    "A1UECgwIcnVzdHlzc2wxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjYxMDE3MTE1NzM5\n"
    "WhcNMjcxMDE3MTE1NzM5WjA3MQswCQYDVQQGEwJKUDERMA8GA1UECgwIcnVzdHlz\n"
    "c2wxFTATBgNVBAMMDGxlYWYuZXhhbXBsZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw\n"
    "gYkCgYEAyLiWzDdX6nR/I0PFfqQMjmzOaP3k2chLl6bgnw/56uRbutdllHGiZYW1\n"
    "WzX5oFvgjGw+ZBQL08v/+SZERezdBninEkAfJy2yk2tuEJUVPpOS9g6v60Lr92wh\n"
    "E2pi+U0lNnCCw8UUZ5jMvMxk3EswcvFn0qHOxp/49Rnu8LafswECAwEAAaNCMEAw\n"
    "HQYDVR0OBBYEFKCMlHF3cFgXmTPrEaihCYlLwkHUMB8GA1UdIwQYMBaAFFT/pnuN\n"
    "Pm1SB+yJgcMJY5Cw5uK3MAoGCCqGSM49BAMCA0kAMEYCIQChEnDI0pmlznyMYuj5\n"
    "utDLTEUQyid+qvtbPwoWcvsrzAIhANwsrhJhuCTt0lh4Hz7Jty6cHAl8fswn+Dr5\n"
    "DL9DOFV8\n"
    "-----END CERTIFICATE-----\n";

static const char PSS_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICGzCCAVCgAwIBAgIBAzBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUA\n"
    "oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwDjEMMAoGA1UEAwwD\n"
    "UFNTMB4XDTI2MTAxNzExNTczOVoXDTI2MTExNjExNTczOVowDjEMMAoGA1UEAwwD\n"
    "UFNTMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIuJbMN1fqdH8jQ8V+pAyO\n"
    "bM5o/eTZyEuXpuCfD/nq5Fu612WUcaJlhbVbNfmgW+CMbD5kFAvTy//5JkRF7N0G\n"
    "eKcSQB8nLbKTa24QlRU+k5L2Dq/rQuv3bCETamL5TSU2cILDxRRnmMy8zGTcSzBy\n"
    "8WfSoc7Gn/j1Ge7wtp+zAQIDAQABoyEwHzAdBgNVHQ4EFgQUoIyUcXdwWBeZM+sR\n"
    "qKEJiUvCQdQwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgIFAKEcMBoGCSqG\n"
    "SIb3DQEBCDANBglghkgBZQMEAgIFAKIDAgEwA4GBAHjZXpIPcBM8Qyazzc4IS2NV\n"
    "uUiGNJXCdUQhq5qeBgCqN+e+GHE1Vp4fQEjGlHbwbNYLHisG4dgN7SWq7RuJOJ8O\n"
    "tiLKYIKpXozJsxajb/ODL6rxaaO5zNpr9pfoItSgT52bhTUHjUSaJ1sr5DWZREUe\n"
    "GEJi1GO7f5BuBjlPrXZT\n"
    "-----END CERTIFICATE-----\n";

static const char ED_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIHzMIGmoAMCAQICAQQwBQYDK2VwMBIxEDAOBgNVBAMMB0VkMjU1MTkwHhcNMjYx\n"
    "MDE3MTE1NzM5WhcNMjYxMTE2MTE1NzM5WjASMRAwDgYDVQQDDAdFZDI1NTE5MCow\n"
    "BQYDK2VwAyEAuNhxQSv61lvhzOw9ja9vUr7Ox3zmUjSLdY9uES9cEnqjITAfMB0G\n"
    "A1UdDgQWBBQF9XKRzyTHVxOlkwHteKrmtgyGAjAFBgMrZXADQQAqO/w+PludG6b4\n"
    "gaRBPE3Fq7TZpNXylLKYTBTXlsdvkrgJUURfV8bQZldJkNxTxHyk6tsncza1p7GX\n"
    "OtQ25cEE\n"
    "-----END CERTIFICATE-----\n";

static const char TRUSTED_PEM[] =
    "-----BEGIN TRUSTED CERTIFICATE-----\n"
    "MIIBmTCCAT+gAwIBAgIIEjRWeJCrze8wCgYIKoZIzj0EAwIwMjELMAkGA1UEBhMC\n"
    "SlAxETAPBgNVBAoMCHJ1c3R5c3NsMRAwDgYDVQQDDAdUZXN0IENBMB4XDTI2MTAx\n"
    "NzExNTcyOVoXDTM2MTAxNDExNTcyOVowMjELMAkGA1UEBhMCSlAxETAPBgNVBAoM\n"
    "CHJ1c3R5c3NsMRAwDgYDVQQDDAdUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
    "AQcDQgAEG8QBqFVH9Y13H0s9Copsp8sUXZPYdQ3axAVnbqLSRU4/Ee5md40Qwqqy\n"
    "B/0BFFHesy61jWDP6FAWuBKm/Hibu6M/MD0wDwYDVR0TAQH/BAUwAwEB/zALBgNV\n"
    "HQ8EBAMCAQYwHQYDVR0OBBYEFFT/pnuNPm1SB+yJgcMJY5Cw5uK3MAoGCCqGSM49\n"
    "BAMCA0gAMEUCIHcVN0GtOf7I7yBYW9wwXEqBZhVMdJVutI2PwKohj1fhAiEA/yez\n"
    "gwPyEeIQYZLF0ykw0qkc1dxRgdA6ClD8WGALKOMwEzAKBggrBgEFBQcDAQwFbXkg\n"
    "Q0E=\n"
    "-----END TRUSTED CERTIFICATE-----\n";

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

static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

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

static void show_name(const char *label, const X509_NAME *n)
{
    char buf[256];

    printf("  %s: %s\n", label, n == NULL ? "(none)" : X509_NAME_oneline(n, buf, sizeof(buf)));
}

static void show_time(const char *label, const ASN1_TIME *t)
{
    printf("  %s: type %d [%.*s]\n", label, ASN1_STRING_type(t), ASN1_STRING_length(t),
           (const char *)ASN1_STRING_get0_data(t));
}

static void show_algor(const char *label, const X509_ALGOR *a)
{
    unsigned char *der = NULL;
    int len = i2d_X509_ALGOR(a, &der);

    hex(label, der, len);
    OPENSSL_free(der);
}

static void show_der(const char *label, const X509 *x)
{
    unsigned char *der = NULL;
    int len = i2d_X509(x, &der);

    hex(label, der, len);
    OPENSSL_free(der);
}

static void show(const char *label, X509 *x)
{
    const ASN1_BIT_STRING *sig, *iuid, *suid;
    const X509_ALGOR *alg;
    EVP_PKEY *pk = X509_get0_pubkey(x);
    const ASN1_INTEGER *serial = X509_get0_serialNumber(x);
    int i;

    printf("# %s\n", label);
    printf("  version %ld, serial", X509_get_version(x));
    for (i = 0; i < ASN1_STRING_length(serial); i++)
        printf(" %02x", ASN1_STRING_get0_data(serial)[i]);
    printf(" (type %d)\n", ASN1_STRING_type(serial));
    show_name("issuer", X509_get_issuer_name(x));
    show_name("subject", X509_get_subject_name(x));
    show_time("notBefore", X509_get0_notBefore(x));
    show_time("notAfter", X509_get0_notAfter(x));
    printf("  signature nid %d (%s), type %d\n", X509_get_signature_nid(x),
           OBJ_nid2sn(X509_get_signature_nid(x)), X509_get_signature_type(x));
    X509_get0_signature(&sig, &alg, x);
    show_algor("signature algorithm", alg);
    check(X509_ALGOR_cmp(alg, X509_get0_tbs_sigalg(x)) == 0, "the TBS algorithm is the same");
    printf("  signature: %d octets, flags %lx\n", ASN1_STRING_length(sig), sig->flags & 0x0f);
    printf("  key: %s, %d bits\n", pk == NULL ? "(none)" : EVP_PKEY_get0_type_name(pk),
           EVP_PKEY_get_bits(pk));
    check(X509_get_X509_PUBKEY(x) != NULL && X509_PUBKEY_get0(X509_get_X509_PUBKEY(x)) == pk,
          "the SubjectPublicKeyInfo's key");
    hex("key bits", X509_get0_pubkey_bitstr(x)->data, X509_get0_pubkey_bitstr(x)->length);
    X509_get0_uids(x, &iuid, &suid);
    printf("  uids: %p %p\n", (void *)iuid, (void *)suid);
    printf("  extensions: %d (%d in the list)\n", X509_get_ext_count(x),
           sk_X509_EXTENSION_num(X509_get0_extensions(x)));
    for (i = 0; i < X509_get_ext_count(x); i++) {
        X509_EXTENSION *e = X509_get_ext(x, i);

        printf("    %d: %s critical %d, %d octets\n", i,
               OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(e))),
               X509_EXTENSION_get_critical(e), ASN1_STRING_length(X509_EXTENSION_get_data(e)));
    }
    printf("  hashes: issuer %08lx subject %08lx old %08lx %08lx, issuer+serial %08lx\n",
           X509_issuer_name_hash(x), X509_subject_name_hash(x), X509_issuer_name_hash_old(x),
           X509_subject_name_hash_old(x), X509_issuer_and_serial_hash(x));
}

static void fingerprints(X509 *x)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    ASN1_OCTET_STRING *d;
    EVP_MD *used = NULL;
    int fallback = -1;

    check(X509_digest(x, EVP_sha1(), md, &len) == 1, "SHA-1 fingerprint");
    hex("sha1", md, len);
    check(X509_digest(x, EVP_sha256(), md, &len) == 1, "SHA-256 fingerprint");
    hex("sha256", md, len);
    check(X509_pubkey_digest(x, EVP_sha1(), md, &len) == 1, "the key's SHA-1");
    hex("key sha1", md, len);
    d = X509_digest_sig(x, &used, &fallback);
    printf("  digest_sig: %s, fallback %d\n", used == NULL ? "(none)" : EVP_MD_get0_name(used),
           fallback);
    if (d != NULL)
        hex("digest", ASN1_STRING_get0_data(d), ASN1_STRING_length(d));
    else
        errors();
    ASN1_OCTET_STRING_free(d);
    EVP_MD_free(used);
}

static void test_decode(void)
{
    X509 *ca = read_cert(CA_PEM), *leaf = read_cert(LEAF_PEM), *pss = read_cert(PSS_PEM);
    X509 *ed = read_cert(ED_PEM);
    EVP_PKEY *rsa = read_key(RSA_KEY_PEM), *ec = read_key(EC_KEY_PEM);
    STACK_OF(X509) *sk = sk_X509_new_null(), *copy;
    int depth = -1;

    check(ca != NULL && leaf != NULL && pss != NULL && ed != NULL, "certificates read");
    show("CA", ca);
    fingerprints(ca);
    show("leaf", leaf);
    fingerprints(leaf);
    show("RSA-PSS", pss);
    fingerprints(pss);
    show("Ed25519", ed);
    fingerprints(ed);

    printf("# verifying\n");
    printf("  CA by itself %d, leaf by the CA %d, Ed25519 %d, PSS %d\n",
           X509_verify(ca, X509_get0_pubkey(ca)), X509_verify(leaf, X509_get0_pubkey(ca)),
           X509_verify(ed, X509_get0_pubkey(ed)), X509_verify(pss, X509_get0_pubkey(pss)));
    printf("  leaf by itself %d\n", X509_verify(leaf, X509_get0_pubkey(leaf)));
    errors();
    printf("  CA by the leaf's key %d\n", X509_verify(ca, X509_get0_pubkey(leaf)));
    errors();
    printf("  private keys: leaf %d, CA %d\n", X509_check_private_key(leaf, rsa),
           X509_check_private_key(ca, ec));
    printf("  the CA with the RSA key %d\n", X509_check_private_key(ca, rsa));
    errors();
    printf("  the leaf with the EC key %d\n", X509_check_private_key(leaf, ec));
    errors();

    printf("# comparisons\n");
    printf("  issuer_and_serial %d %d %d, issuer_name %d, subject_name %d %d\n",
           X509_issuer_and_serial_cmp(ca, leaf), X509_issuer_and_serial_cmp(leaf, ca),
           X509_issuer_and_serial_cmp(ca, ca), X509_issuer_name_cmp(leaf, ca),
           X509_subject_name_cmp(leaf, ca), X509_subject_name_cmp(ca, ca));
    sk_X509_push(sk, ca);
    sk_X509_push(sk, leaf);
    sk_X509_push(sk, ed);
    check(X509_find_by_subject(sk, X509_get_subject_name(leaf)) == leaf, "found by subject");
    check(X509_find_by_subject(sk, X509_get_subject_name(pss)) == NULL, "no such subject");
    check(X509_find_by_issuer_and_serial(sk, X509_get_issuer_name(leaf),
                                         X509_get0_serialNumber(leaf)) == leaf,
          "found by issuer and serial");
    check(X509_find_by_issuer_and_serial(sk, X509_get_issuer_name(leaf),
                                         X509_get0_serialNumber(ca)) == ca,
          "the CA by its serial");
    check(X509_find_by_issuer_and_serial(NULL, NULL, NULL) == NULL, "no stack");
    copy = X509_chain_up_ref(sk);
    check(copy != NULL && sk_X509_num(copy) == 3 && sk_X509_value(copy, 1) == leaf,
          "the chain with references");
    printf("  suite B: CA %d, with its chain %d (depth %d)\n",
           X509_chain_check_suiteb(&depth, ca, NULL, X509_V_FLAG_SUITEB_128_LOS_ONLY),
           X509_chain_check_suiteb(&depth, NULL, sk, X509_V_FLAG_SUITEB_128_LOS_ONLY), depth);
    depth = -1;
    printf("  suite B: 192-bit only %d (depth %d), no flags %d\n",
           X509_chain_check_suiteb(&depth, ca, NULL, X509_V_FLAG_SUITEB_192_LOS), depth,
           X509_chain_check_suiteb(&depth, leaf, NULL, 0));
    printf("  pubkey parameters %d\n", X509_get_pubkey_parameters(NULL, copy));
    errors();
    OSSL_STACK_OF_X509_free(copy);
    sk_X509_free(sk);
    X509_free(ca);
    X509_free(leaf);
    X509_free(pss);
    X509_free(ed);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
}

static void test_encodings(void)
{
    BIO *b = BIO_new_mem_buf(CA_PEM, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL), *y, *z;
    unsigned char *der = NULL, *tbs = NULL, *p;
    const unsigned char *q;
    int len, tlen, n;
    X509_CINF *ci;
    FILE *f;
    time_t t = 2000000000;
    char *pem;
    long plen;

    BIO_free(b);
    printf("# encodings\n");
    len = i2d_X509(x, &der);
    tlen = i2d_re_X509_tbs(x, &tbs);
    printf("  der %d, tbs %d\n", len, tlen);
    q = tbs;
    ci = d2i_X509_CINF(NULL, &q, tlen);
    check(ci != NULL && q == tbs + tlen, "the TBSCertificate decoded");
    p = NULL;
    n = i2d_X509_CINF(ci, &p);
    check(n == tlen && memcmp(p, tbs, (size_t)n) == 0, "and encoded again");
    OPENSSL_free(p);
    X509_CINF_free(ci);
    OPENSSL_free(tbs);
    q = der;
    y = d2i_X509(NULL, &q, len);
    check(y != NULL && q == der + len, "decoded");
    q = der;
    check(d2i_X509(&y, &q, len - 1) == NULL, "a truncated certificate");
    errors();
    q = der;
    z = d2i_X509(&y, &q, len);
    check(z == y, "decoded again into the same");
    X509_time_adj(X509_getm_notBefore(z), 0, &t);
    p = NULL;
    n = i2d_X509(z, &p);
    check(n == len && memcmp(p, der, (size_t)len) == 0,
          "changed in place, it still encodes as decoded");
    OPENSSL_free(p);
    show_time("changed notBefore", X509_get0_notBefore(z));
    tlen = i2d_re_X509_tbs(z, NULL);
    p = NULL;
    n = i2d_X509(z, &p);
    check(n == len && memcmp(p, der, (size_t)len) != 0, "re-encoded, the change shows");
    OPENSSL_free(p);
    X509_free(z);

    b = BIO_new(BIO_s_mem());
    check(i2d_X509_bio(b, x) == 1, "to a BIO");
    y = d2i_X509_bio(b, NULL);
    check(y != NULL && X509_cmp_time(X509_get0_notBefore(y), &t) != 0, "from a BIO");
    X509_free(y);
    BIO_free(b);
    f = tmpfile();
    check(f != NULL && i2d_X509_fp(f, x) == 1, "to a FILE");
    rewind(f);
    y = d2i_X509_fp(f, NULL);
    check(y != NULL, "from a FILE");
    X509_free(y);
    rewind(f);
    check(PEM_write_X509(f, x) == 1, "PEM to a FILE");
    rewind(f);
    y = PEM_read_X509(f, NULL, NULL, NULL);
    check(y != NULL, "PEM from a FILE");
    X509_free(y);
    fclose(f);

    printf("# PEM\n");
    check(PEM_write_bio_X509(out, x) == 1, "written");
    plen = BIO_get_mem_data(out, &pem);
    check(plen == (long)strlen(CA_PEM) && memcmp(pem, CA_PEM, (size_t)plen) == 0,
          "as it was read");
    (void)BIO_reset(out);
    b = BIO_new_mem_buf(TRUSTED_PEM, -1);
    y = PEM_read_bio_X509(b, NULL, NULL, NULL);
    printf("  a trusted certificate as a plain one: %p\n", (void *)y);
    errors();
    BIO_free(b);
    b = BIO_new_mem_buf(TRUSTED_PEM, -1);
    y = PEM_read_bio_X509_AUX(b, NULL, NULL, NULL);
    check(y != NULL, "read as trusted");
    BIO_free(b);
    p = NULL;
    printf("  i2d_X509 %d, i2d_X509_AUX %d\n", i2d_X509(y, NULL), n = i2d_X509_AUX(y, &p));
    hex("aux der", p + len, n - len);
    q = p;
    z = d2i_X509_AUX(NULL, &q, n);
    check(z != NULL && q == p + n, "the trusted form decoded");
    X509_free(z);
    q = p;
    z = d2i_X509_AUX(NULL, &q, len);
    check(z != NULL && q == p + len, "without its auxiliary data");
    X509_free(z);
    q = p;
    z = d2i_X509_AUX(NULL, &q, len + 3);
    printf("  broken auxiliary data: %p\n", (void *)z);
    errors();
    OPENSSL_free(p);
    check(PEM_write_bio_X509_AUX(out, y) == 1, "trusted written");
    plen = BIO_get_mem_data(out, &pem);
    check(plen == (long)strlen(TRUSTED_PEM) && memcmp(pem, TRUSTED_PEM, (size_t)plen) == 0,
          "as it was read");
    (void)BIO_reset(out);
    X509_free(y);
    b = BIO_new_mem_buf(CA_PEM, -1);
    y = PEM_read_bio_X509_AUX(b, NULL, NULL, NULL);
    check(y != NULL, "a plain certificate read as trusted");
    printf("  its trusted form adds %d octets\n", i2d_X509_AUX(y, NULL) - len);
    BIO_free(b);
    f = tmpfile();
    check(PEM_write_X509_AUX(f, y) == 1, "trusted PEM to a FILE");
    rewind(f);
    z = PEM_read_X509_AUX(f, NULL, NULL, NULL);
    check(z != NULL, "and back");
    fclose(f);
    X509_free(z);
    X509_free(y);
    OPENSSL_free(der);
    X509_free(x);
}

static void test_build(void)
{
    X509 *x = X509_new(), *d;
    EVP_PKEY *ed = read_key(ED_KEY_PEM), *rsa = read_key(RSA_KEY_PEM);
    X509_NAME *n = X509_NAME_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    ASN1_TIME *tm;
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    X509_EXTENSION *ext;
    time_t t = 1700000000;
    int r, idx;

    printf("# building\n");
    printf("  new: version %ld, issuer %d entries, key %s, notBefore %s\n", X509_get_version(x),
           X509_NAME_entry_count(X509_get_issuer_name(x)),
           X509_get0_pubkey(x) == NULL ? "none" : "set",
           X509_get0_notBefore(x) == NULL ? "NULL" : "made");
    show_der("empty", x);
    errors();
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"built", -1, -1, 0);
    ASN1_INTEGER_set(serial, 77);
    check(X509_set_serialNumber(x, serial) == 1, "serial set");
    check(X509_set_issuer_name(x, n) == 1 && X509_set_subject_name(x, n) == 1, "names set");
    check(X509_get_subject_name(x) != n, "a copy");
    tm = X509_time_adj_ex(NULL, 0, 0, &t);
    show_time("time", tm);
    check(X509_set1_notBefore(x, tm) == 1, "notBefore set");
    X509_time_adj_ex(tm, 3650, 60, &t);
    show_time("adjusted", tm);
    check(X509_set1_notAfter(x, tm) == 1, "notAfter set");
    check(X509_set1_notAfter(x, X509_get0_notAfter(x)) == 1, "set to itself");
    check(X509_set1_notBefore(x, NULL) == 0, "a NULL time refused");
    check(X509_set_pubkey(x, ed) == 1, "key set");
    check(X509_set_version(x, X509_VERSION_1) == 1 && X509_get_version(x) == 0, "version 1");
    r = X509_sign(x, ed, NULL);
    printf("  signed: %d, version %ld\n", r, X509_get_version(x));
    show_der("v1 Ed25519", x);
    check(X509_verify(x, ed) == 1, "verifies");
    ASN1_OCTET_STRING_set(os, (const unsigned char *)"\x30\x03\x01\x01\xff", 5);
    ext = X509_EXTENSION_create_by_NID(NULL, NID_basic_constraints, 1, os);
    check(X509_add_ext(x, ext, -1) == 1, "an extension added");
    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_set(os, (const unsigned char *)"\x03\x02\x01\x06", 4);
    ext = X509_EXTENSION_create_by_NID(NULL, NID_key_usage, 0, os);
    check(X509_add_ext(x, ext, 0) == 1, "another at the front");
    X509_EXTENSION_free(ext);
    printf("  by NID %d %d, by OBJ %d, critical %d %d, unknown NID %d\n",
           X509_get_ext_by_NID(x, NID_basic_constraints, -1),
           X509_get_ext_by_NID(x, NID_subject_alt_name, -1),
           X509_get_ext_by_OBJ(x, OBJ_nid2obj(NID_key_usage), -1),
           X509_get_ext_by_critical(x, 1, -1), X509_get_ext_by_critical(x, 0, 0),
           X509_get_ext_by_NID(x, 99999, -1));
    printf("  still encodes as signed: %d\n", X509_verify(x, ed));
    r = X509_sign(x, ed, NULL);
    printf("  signed again: %d, version %ld\n", r, X509_get_version(x));
    show_der("v3 Ed25519", x);
    show_algor("algorithm", X509_get0_tbs_sigalg(x));
    check(X509_verify(x, ed) == 1, "verifies");
    r = X509_sign(x, rsa, EVP_sha256());
    printf("  RSA signed: %d\n", r);
    show_der("v3 RSA", x);
    check(X509_verify(x, rsa) == 1, "verifies");
    printf("  with the wrong key: %d\n", X509_verify(x, ed));
    errors();
    {
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        EVP_PKEY *pk = X509_get_pubkey(x);

        check(EVP_DigestSignInit(mctx, NULL, NULL, NULL, ed) == 1, "a signing context");
        r = X509_sign_ctx(x, mctx);
        printf("  signed through a context: %d, verifies %d\n", r, X509_verify(x, ed));
        show_der("v3 Ed25519 again", x);
        check(pk != NULL && EVP_PKEY_eq(pk, ed) == 1, "the key, with a reference");
        EVP_PKEY_free(pk);
        EVP_MD_CTX_free(mctx);
        check(ASN1_INTEGER_get(X509_get_serialNumber(x)) == 77, "the serial number");
        check(X509_getm_notAfter(x) == X509_get0_notAfter(x), "notAfter, to change");
    }
    d = X509_dup(x);
    check(d != NULL && i2d_X509(d, NULL) == i2d_X509(x, NULL), "copied");
    X509_free(d);
    ext = X509_delete_ext(x, 0);
    check(ext != NULL && X509_get_ext_count(x) == 1, "one deleted");
    X509_EXTENSION_free(ext);
    ext = X509_delete_ext(x, 0);
    check(ext != NULL && X509_get0_extensions(x) == NULL, "the last one deleted, the list too");
    X509_EXTENSION_free(ext);
    check(X509_delete_ext(x, 0) == NULL, "none left");
    idx = X509_get_ext_by_NID(x, NID_basic_constraints, -1);
    printf("  by NID without extensions %d, count %d\n", idx, X509_get_ext_count(x));
    check(X509_set_version(x, 5) == 1 && X509_get_version(x) == 5, "any version");
    r = X509_sign(x, rsa, EVP_md5_sha1());
    printf("  MD5-SHA1: %d\n", r);
    errors();
    printf("  set on NULL: %d %d %d\n", X509_set_version(NULL, 2), X509_set_pubkey(NULL, ed),
           X509_sign(NULL, ed, NULL));
    errors();

    printf("# ex_data, references\n");
    idx = X509_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    check(X509_set_ex_data(x, idx, (void *)"data") == 1, "ex_data set");
    check(strcmp(X509_get_ex_data(x, idx), "data") == 0, "and got");
    d = X509_dup(x);
    check(X509_get_ex_data(d, idx) == NULL, "a copy has none");
    X509_free(d);
    check(X509_up_ref(x) == 1, "a reference");
    X509_free(x);
    check(X509_get_version(x) == 5, "still there");
    os = ASN1_OCTET_STRING_new();
    X509_set0_distinguishing_id(x, os);
    check(X509_get0_distinguishing_id(x) == os, "distinguishing ID");
    X509_set0_distinguishing_id(x, NULL);
    check(X509_get0_distinguishing_id(x) == NULL, "taken away");
    d = X509_new_ex(NULL, "provider=default");
    check(d != NULL, "new in a library context");
    X509_free(d);
    X509_free(x);
    X509_free(NULL);
    X509_NAME_free(n);
    ASN1_INTEGER_free(serial);
    ASN1_TIME_free(tm);
    ASN1_OCTET_STRING_free(os == NULL ? NULL : NULL);
    EVP_PKEY_free(ed);
    EVP_PKEY_free(rsa);
}

static void cmp_time(const char *label, const char *s, int type, time_t t)
{
    ASN1_TIME *tm = ASN1_TIME_new();

    ASN1_STRING_set(tm, s, -1);
    tm->type = type;
    printf("  %s: %d\n", label, X509_cmp_time(tm, &t));
    ASN1_TIME_free(tm);
}

static void test_times(void)
{
    time_t t = 1700000000;
    ASN1_TIME *tm;
    ASN1_UTCTIME *u = ASN1_UTCTIME_new();
    ASN1_GENERALIZEDTIME *g = ASN1_GENERALIZEDTIME_new();

    printf("# times\n");
    cmp_time("earlier", "231114221319Z", V_ASN1_UTCTIME, t);
    cmp_time("the same", "231114221320Z", V_ASN1_UTCTIME, t);
    cmp_time("later", "231114221321Z", V_ASN1_UTCTIME, t);
    cmp_time("generalized later", "20231114221321Z", V_ASN1_GENERALIZEDTIME, t);
    cmp_time("generalized earlier", "19991231235959Z", V_ASN1_GENERALIZEDTIME, t);
    cmp_time("no Z", "2311142213200", V_ASN1_UTCTIME, t);
    cmp_time("a fraction", "20231114221320.5Z", V_ASN1_GENERALIZEDTIME, t);
    cmp_time("an offset", "231114221320+0100", V_ASN1_UTCTIME, t);
    cmp_time("short", "2311142213Z", V_ASN1_UTCTIME, t);
    cmp_time("letters", "23111422132AZ", V_ASN1_UTCTIME, t);
    cmp_time("an octet string", "231114221320Z", V_ASN1_OCTET_STRING, t);
    cmp_time("month 13", "231314221320Z", V_ASN1_UTCTIME, t);
    tm = X509_time_adj(NULL, -86400, &t);
    show_time("a day before", tm);
    printf("  current: %d %d\n", X509_cmp_current_time(tm),
           X509_cmp_time(tm, NULL));
    ASN1_TIME_free(tm);
    tm = X509_gmtime_adj(NULL, 0);
    check(tm != NULL && ASN1_STRING_type(tm) == V_ASN1_UTCTIME, "now, as a UTCTime");
    ASN1_TIME_free(tm);
    printf("  a UTCTime past 2050: %s, length %d type %d\n",
           X509_time_adj_ex(u, 36500, 0, &t) == u ? "itself" : "NULL", ASN1_STRING_length(u),
           ASN1_STRING_type(u));
    errors();
    check(X509_time_adj_ex(g, 1, 1, &t) == g && ASN1_STRING_type(g) == V_ASN1_GENERALIZEDTIME,
          "a GeneralizedTime stays one");
    show_time("generalized", g);
    tm = ASN1_TIME_new();
    check(X509_time_adj_ex(tm, 36500, 0, &t) == tm, "an ASN1_TIME takes either");
    show_time("past 2050", tm);
    ASN1_TIME_free(tm);
    ASN1_UTCTIME_free(u);
    ASN1_GENERALIZEDTIME_free(g);
}

static void test_items(void)
{
    X509_VAL *v = X509_VAL_new();
    X509_CERT_AUX *a = X509_CERT_AUX_new();
    X509_CINF *ci = X509_CINF_new();
    unsigned char *der = NULL;
    const unsigned char *q;
    int len;
    time_t t = 1700000000;

    printf("# items\n");
    v->notBefore = X509_time_adj(v->notBefore, 0, &t);
    v->notAfter = X509_time_adj(v->notAfter, 60, &t);
    len = i2d_X509_VAL(v, &der);
    hex("validity", der, len);
    q = der;
    X509_VAL_free(v);
    v = d2i_X509_VAL(NULL, &q, len);
    check(v != NULL && q == der + len, "decoded");
    OPENSSL_free(der);
    der = NULL;
    len = i2d_X509_CERT_AUX(a, &der);
    hex("empty aux", der, len);
    q = der;
    X509_CERT_AUX_free(a);
    a = d2i_X509_CERT_AUX(NULL, &q, len);
    check(a != NULL, "decoded");
    OPENSSL_free(der);
    der = NULL;
    len = i2d_X509_CINF(ci, &der);
    printf("  empty TBSCertificate: %d\n", len);
    errors();
    OPENSSL_free(der);
    check(ASN1_ITEM_rptr(X509) != NULL && ASN1_ITEM_rptr(X509_CINF) != NULL
              && ASN1_ITEM_rptr(X509_VAL) != NULL && ASN1_ITEM_rptr(X509_CERT_AUX) != NULL,
          "the items");
    X509_VAL_free(v);
    X509_CERT_AUX_free(a);
    X509_CINF_free(ci);
}

static void test_defaults(void)
{
    printf("# defaults\n");
    printf("  env %s %s\n", X509_get_default_cert_dir_env(), X509_get_default_cert_file_env());
    check(strncmp(X509_get_default_cert_dir(), X509_get_default_cert_area(),
                  strlen(X509_get_default_cert_area())) == 0, "the directory is in the area");
    printf("  under the area: %s %s %s\n",
           X509_get_default_cert_dir() + strlen(X509_get_default_cert_area()),
           X509_get_default_cert_file() + strlen(X509_get_default_cert_area()),
           X509_get_default_private_dir() + strlen(X509_get_default_cert_area()));
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    out = BIO_new(BIO_s_mem());
    test_decode();
    test_encodings();
    test_build();
    test_times();
    test_items();
    test_defaults();
    flush_out();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
