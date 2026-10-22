/*
 * Conformance test for envelope encryption (EVP_SealInit(3), EVP_OpenInit(3)), PEM_SignInit
 * and friends (pem.h), and PKCS1_MGF1 (rsa.h), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both (TEST_PLAN.md, layer L4). The sealed key and IV are random,
 * so only what doesn't depend on them is printed.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The queued errors' library and reason (not the function or file), then cleared. */
static void errors(void)
{
    unsigned long e;

    while ((e = ERR_get_error()) != 0)
        printf("  error: lib %d reason %d\n", ERR_GET_LIB(e), ERR_GET_REASON(e));
}

static void hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
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

static EVP_PKEY *key(void)
{
    BIO *b = BIO_new_mem_buf(RSA_PEM, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free(b);
    return k;
}

static const char MESSAGE[] = "an envelope's message, longer than one block of the cipher";

/* Sealed for one key (twice: the key itself listed twice), opened, and the second message. */
static void seal_and_open(EVP_PKEY *k, const EVP_CIPHER *cipher, const char *name)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ek1[256], ek2[256], *ek[2] = { ek1, ek2 };
    int ekl[2] = { 0, 0 }, n, len, total;
    unsigned char iv[EVP_MAX_IV_LENGTH], ct[256], pt[256];
    EVP_PKEY *keys[2] = { k, k };
    char what[128];

    snprintf(what, sizeof(what), "%s: EVP_SealInit for two keys returns 2", name);
    n = EVP_SealInit(ctx, cipher, ek, ekl, iv, keys, 2);
    check(n == 2, what);
    printf("  %s: encrypted key lengths %d %d, IV length %d, key length %d\n", name, ekl[0], ekl[1],
           EVP_CIPHER_CTX_get_iv_length(ctx), EVP_CIPHER_CTX_get_key_length(ctx));
    total = 0;
    check(EVP_SealUpdate(ctx, ct, &len, (const unsigned char *)MESSAGE, (int)strlen(MESSAGE)) == 1, "EVP_SealUpdate");
    total += len;
    check(EVP_SealFinal(ctx, ct + total, &len) == 1, "EVP_SealFinal");
    total += len;
    printf("  %s: ciphertext %d octets\n", name, total);

    snprintf(what, sizeof(what), "%s: EVP_OpenInit with the second encrypted key", name);
    check(EVP_OpenInit(ctx, cipher, ek2, ekl[1], iv, k) == 1, what);
    n = 0;
    check(EVP_OpenUpdate(ctx, pt, &len, ct, total) == 1, "EVP_OpenUpdate");
    n += len;
    check(EVP_OpenFinal(ctx, pt + n, &len) == 1, "EVP_OpenFinal");
    n += len;
    check(n == (int)strlen(MESSAGE) && memcmp(pt, MESSAGE, n) == 0, "the message comes back");

    /* The context is ready for another message under the same key and IV. */
    check(EVP_OpenUpdate(ctx, pt, &len, ct, total) == 1 && EVP_OpenFinal(ctx, pt + len, &n) == 1
          && len + n == (int)strlen(MESSAGE), "and again after EVP_OpenFinal");

    EVP_CIPHER_CTX_free(ctx);
}

static void seal_edges(EVP_PKEY *k)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[EVP_MAX_IV_LENGTH], ek1[256], *ek[1] = { ek1 };
    int ekl[1];
    EVP_PKEY *keys[1] = { k };

    check(EVP_SealInit(ctx, EVP_aes_128_cbc(), NULL, NULL, iv, NULL, 0) == 1,
          "EVP_SealInit without keys only sets the cipher");
    check(EVP_CIPHER_CTX_get0_cipher(ctx) != NULL, "which the context has");
    check(EVP_SealInit(ctx, NULL, ek, ekl, iv, keys, -1) == 1, "a negative count is no keys");
    check(EVP_SealInit(ctx, NULL, ek, ekl, iv, keys, 1) == 1, "the context's cipher with a NULL type");
    check(EVP_OpenInit(ctx, EVP_aes_128_cbc(), NULL, 0, NULL, NULL) == 1,
          "EVP_OpenInit without a key only sets the cipher");
    /* Fixed octets: under implicit rejection, a bad ciphertext decrypts to a synthetic key whose
     * length depends on it, and a random one is 16 octets (AES-128's key) about once in 250. */
    memset(ek1, 0x5a, 3);
    check(EVP_OpenInit(ctx, NULL, ek1, 3, iv, k) == 0, "a short encrypted key fails");
    errors();
    EVP_CIPHER_CTX_free(ctx);
}

static void pem_sign(EVP_PKEY *k)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char sig[512];
    unsigned int siglen = 0;

    check(PEM_SignInit(ctx, (EVP_MD *)EVP_sha256()) == 1, "PEM_SignInit");
    check(PEM_SignUpdate(ctx, (const unsigned char *)"one ", 4) == 1
          && PEM_SignUpdate(ctx, (const unsigned char *)"two", 3) == 1, "PEM_SignUpdate twice");
    check(PEM_SignFinal(ctx, sig, &siglen, k) == 1, "PEM_SignFinal");
    /* PKCS #1 v1.5 is deterministic: the base64 is the same on both libraries. */
    printf("  signature (%u): %.*s\n", siglen, (int)siglen, sig);
    check(siglen == strlen((char *)sig), "NUL-terminated, without line breaks");
    check(PEM_SignInit(ctx, (EVP_MD *)EVP_sha1()) == 1 && PEM_SignUpdate(ctx, NULL, 0) == 1
          && PEM_SignFinal(ctx, sig, &siglen, k) == 1, "an empty message with SHA-1");
    printf("  empty (%u): %.*s\n", siglen, (int)siglen, sig);
    check(PEM_SignInit(ctx, (EVP_MD *)EVP_sha256()) == 1 && PEM_SignFinal(ctx, sig, &siglen, NULL) == 0,
          "PEM_SignFinal without a key fails");
    errors();
    EVP_MD_CTX_free(ctx);
}

static void mgf1(void)
{
    unsigned char mask[100], seed[] = "seed";

    memset(mask, 0xaa, sizeof(mask));
    check(PKCS1_MGF1(mask, 45, seed, 4, EVP_sha256()) == 0, "PKCS1_MGF1 of 45 octets with SHA-256");
    hex("mask", mask, 46);
    check(PKCS1_MGF1(mask, 20, seed, 4, EVP_sha1()) == 0, "exactly one SHA-1 block");
    hex("mask", mask, 21);
    check(PKCS1_MGF1(mask, 64, NULL, 0, EVP_sha512()) == 0, "an empty seed");
    hex("mask", mask, 64);
    memset(mask, 0xaa, sizeof(mask));
    check(PKCS1_MGF1(mask, 0, seed, 4, EVP_sha256()) == 0 && mask[0] == 0xaa, "no octets: success, untouched");
    check(PKCS1_MGF1(mask, -1, seed, 4, EVP_sha256()) == 0 && mask[0] == 0xaa, "a negative length too");
    check(PKCS1_MGF1(mask, 10, seed, 4, NULL) == -1, "no digest: -1");
    errors();
    check(PKCS1_MGF1(mask, 0, seed, 4, NULL) == -1, "no digest, even for nothing");
    errors();
}

int main(void)
{
    EVP_PKEY *k = key();

    check(k != NULL, "the RSA key loads");
    seal_and_open(k, EVP_aes_128_cbc(), "AES-128-CBC");
    seal_and_open(k, EVP_aes_256_ctr(), "AES-256-CTR");
    seal_and_open(k, EVP_chacha20(), "ChaCha20");
    seal_edges(k);
    pem_sign(k);
    mgf1();
    EVP_PKEY_free(k);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
