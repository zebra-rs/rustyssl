/*
 * Conformance test for DANE's settings and records (SSL_CTX_dane_enable(3),
 * SSL_CTX_dane_mtype_set(3), SSL_dane_enable(3), SSL_dane_tlsa_add(3), SSL_dane_set_flags(3),
 * SSL_get0_dane_authority(3), SSL_get0_dane_tlsa(3), SSL_get0_dane): enabling a context and a
 * connection (with its SNI name and reference identifier), matching types, every check a TLSA
 * record goes through, flags, and what a connection reports before any handshake.
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


static X509 *cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

/* Adds a record and prints the result and errors. */
static int add(SSL *s, int usage, int selector, int mtype, const unsigned char *data, size_t len,
               const char *what)
{
    int r = SSL_dane_tlsa_add(s, (uint8_t)usage, (uint8_t)selector, (uint8_t)mtype, data, len);

    printf("  %d %d %d (%zu octets) -> %d\n", usage, selector, mtype, len, r);
    errors();
    check(1, what);
    return r;
}

static void report(SSL *s)
{
    X509 *mcert = (X509 *)1;
    EVP_PKEY *mspki = (EVP_PKEY *)1;
    uint8_t u = 9, sel = 9, mt = 9;
    const unsigned char *data = (const unsigned char *)"x";
    size_t dlen = 99;
    int a = SSL_get0_dane_authority(s, &mcert, &mspki);
    int t = SSL_get0_dane_tlsa(s, &u, &sel, &mt, &data, &dlen);

    printf("  authority %d (%s, %s) tlsa %d (%d %d %d, %zu)\n", a, mcert == (X509 *)1 ? "untouched" : "set",
           mspki == (EVP_PKEY *)1 ? "untouched" : "set", t, u, sel, mt, dlen);
}

int main(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *s = SSL_new(ctx), *s2;
    X509 *ca = cert(CA_PEM), *leaf = cert(SERVER_PEM);
    unsigned char *ca_der = NULL, *spki = NULL, digest[64], junk[40];
    int ca_len = i2d_X509(ca, &ca_der), spki_len = i2d_PUBKEY(X509_get0_pubkey(leaf), &spki);
    unsigned int dlen = 0;
    const char *name;

    setvbuf(stdout, NULL, _IONBF, 0);
    memset(junk, 0x30, sizeof(junk));

    printf("# before enabling\n");
    report(s);
    check(SSL_get0_dane(s) != NULL, "SSL_get0_dane");
    check(add(s, 3, 1, 1, digest, 32, "a record") == -1, "a record needs DANE");
    check(SSL_dane_enable(s, "server.example") == 0, "the context isn't DANE-enabled");
    errors();

    printf("# the context\n");
    check(SSL_CTX_dane_enable(ctx) == 1, "SSL_CTX_dane_enable");
    check(SSL_CTX_dane_enable(ctx) == 1, "again");
    check(SSL_CTX_dane_mtype_set(ctx, EVP_sha256(), 0, 1) == 0, "Full(0) takes no digest");
    errors();
    check(SSL_CTX_dane_mtype_set(ctx, NULL, 0, 0) == 1, "Full(0) without one");
    check(SSL_CTX_dane_mtype_set(ctx, EVP_sha1(), 4, 3) == 1, "a private matching type");
    check(SSL_CTX_dane_mtype_set(ctx, NULL, 2, 5) == 1, "SHA2-512 disabled");
    printf("  ctx flags %lx", SSL_CTX_dane_set_flags(ctx, DANE_FLAG_NO_DANE_EE_NAMECHECKS));
    printf(" %lx", SSL_CTX_dane_set_flags(ctx, 0x10));
    printf(" %lx", SSL_CTX_dane_clear_flags(ctx, 0x10));
    printf(" %lx\n", SSL_CTX_dane_clear_flags(ctx, 0));

    printf("# a connection\n");
    s2 = SSL_new(ctx);
    printf("  ssl flags %lx", SSL_dane_set_flags(s2, 0x20));
    printf(" %lx", SSL_dane_clear_flags(s2, DANE_FLAG_NO_DANE_EE_NAMECHECKS));
    printf(" %lx\n", SSL_dane_clear_flags(s2, 0));
    check(SSL_set_tlsext_host_name(s2, "sni.example") == 1, "an SNI name first");
    check(SSL_dane_enable(s2, "server.example") == 1, "SSL_dane_enable");
    name = SSL_get_servername(s2, TLSEXT_NAMETYPE_host_name);
    printf("  SNI %s\n", name == NULL ? "(null)" : name);
    check(SSL_dane_enable(s2, "server.example") == 0, "already enabled");
    errors();
    report(s2);
    check(SSL_dane_enable(s, "server.example") == 1, "the first connection now");
    name = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    printf("  SNI %s\n", name == NULL ? "(null)" : name);
    {
        SSL *s3 = SSL_new(ctx);

        check(SSL_dane_enable(s3, "") == -1, "an empty base domain");
        errors();
        SSL_free(s3);
    }

    printf("# records\n");
    EVP_Digest(spki, (size_t)spki_len, digest, &dlen, EVP_sha256(), NULL);
    add(s, 3, 1, 1, digest, 32, "DANE-EE SPKI SHA2-256");
    add(s, 3, 1, 1, digest, 31, "a short digest");
    add(s, 3, 1, 1, NULL, 32, "no data");
    add(s, 3, 1, 1, NULL, 0, "no data, no length");
    add(s, 4, 1, 1, digest, 32, "a bad usage");
    add(s, 3, 2, 1, digest, 32, "a bad selector");
    add(s, 3, 1, 2, digest, 64, "a disabled matching type");
    add(s, 3, 1, 3, digest, 32, "an unknown matching type");
    EVP_Digest(spki, (size_t)spki_len, digest, &dlen, EVP_sha1(), NULL);
    add(s, 3, 1, 4, digest, 20, "the private matching type");
    add(s, 2, 0, 0, ca_der, (size_t)ca_len, "DANE-TA Cert Full");
    add(s, 2, 0, 0, ca_der, (size_t)ca_len - 1, "a truncated certificate");
    add(s, 0, 0, 0, junk, sizeof(junk), "not a certificate");
    add(s, 1, 0, 0, ca_der, (size_t)ca_len, "PKIX-EE Cert Full");
    add(s, 2, 1, 0, spki, (size_t)spki_len, "DANE-TA SPKI Full");
    add(s, 3, 1, 0, junk, sizeof(junk), "not a key");
    add(s, 2, 1, 0, spki, (size_t)spki_len + 1, "a key with trailing data");
    add(s, 0, 1, 1, digest, 32, "PKIX-TA SPKI SHA2-256");
    add(s, 1, 0, 0, NULL, 0, "Full with no data");
    report(s);
    check(SSL_dane_tlsa_add(NULL, 3, 1, 1, digest, 32) == 0, "a NULL connection");
    check(SSL_get0_dane_authority(NULL, NULL, NULL) == -1 && SSL_get0_dane_tlsa(NULL, NULL, NULL, NULL, NULL, NULL) == -1,
          "NULL connections");

    OPENSSL_free(ca_der);
    OPENSSL_free(spki);
    X509_free(ca);
    X509_free(leaf);
    SSL_free(s);
    SSL_free(s2);
    SSL_CTX_free(ctx);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
