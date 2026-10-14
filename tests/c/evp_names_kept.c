/*
 * Conformance test for the names the *_names_do_all functions give their callbacks, in TAP
 * format: OpenSSL's point into the library context's name map, so a caller may keep them
 * (OpenSSL's `openssl list` collects them and prints them later). For each kind of method
 * (digest, cipher, MAC, KDF, random generator, key manager, signature, opaque key manager),
 * the names are collected, the method freed, other methods fetched, and the names printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

struct names {
    const char *list[16];
    int n;
};

static void collect(const char *name, void *data)
{
    struct names *names = data;

    if (names->n < 16)
        names->list[names->n++] = name;
}

/* Fetches and frees a few methods, so freed memory gets reused. */
static void churn(void)
{
    int i;

    for (i = 0; i < 20; i++) {
        EVP_MD *md = EVP_MD_fetch(NULL, i % 2 ? "SHA512" : "SHA3-256", NULL);
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
        char buf[64];

        memset(buf, 'x', sizeof(buf));
        EVP_MD_free(md);
        EVP_CIPHER_free(c);
    }
}

static void show(const char *what, struct names *names, int ret)
{
    int i;

    churn();
    printf("# %s: %d,", what, ret);
    for (i = 0; i < names->n; i++)
        printf(" %s", names->list[i]);
    printf("\n");
    check(names->n > 0, what);
}

int main(void)
{
    struct names names;
    int r;

    {
        EVP_MD *m = EVP_MD_fetch(NULL, "SHA256", NULL);

        names.n = 0;
        r = EVP_MD_names_do_all(m, collect, &names);
        EVP_MD_free(m);
        show("EVP_MD_names_do_all", &names, r);
    }
    {
        EVP_CIPHER *m = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);

        names.n = 0;
        r = EVP_CIPHER_names_do_all(m, collect, &names);
        EVP_CIPHER_free(m);
        show("EVP_CIPHER_names_do_all", &names, r);
    }
    {
        EVP_MAC *m = EVP_MAC_fetch(NULL, "HMAC", NULL);

        names.n = 0;
        r = EVP_MAC_names_do_all(m, collect, &names);
        EVP_MAC_free(m);
        show("EVP_MAC_names_do_all", &names, r);
    }
    {
        EVP_KDF *m = EVP_KDF_fetch(NULL, "PBKDF2", NULL);

        names.n = 0;
        r = EVP_KDF_names_do_all(m, collect, &names);
        EVP_KDF_free(m);
        show("EVP_KDF_names_do_all", &names, r);
    }
    {
        EVP_RAND *m = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);

        names.n = 0;
        r = EVP_RAND_names_do_all(m, collect, &names);
        EVP_RAND_free(m);
        show("EVP_RAND_names_do_all", &names, r);
    }
    {
        EVP_KEYMGMT *m = EVP_KEYMGMT_fetch(NULL, "HMAC", NULL);

        names.n = 0;
        r = EVP_KEYMGMT_names_do_all(m, collect, &names);
        EVP_KEYMGMT_free(m);
        show("EVP_KEYMGMT_names_do_all", &names, r);
    }
    {
        EVP_SIGNATURE *m = EVP_SIGNATURE_fetch(NULL, "HMAC", NULL);

        names.n = 0;
        r = EVP_SIGNATURE_names_do_all(m, collect, &names);
        EVP_SIGNATURE_free(m);
        show("EVP_SIGNATURE_names_do_all", &names, r);
    }
    {
        EVP_SKEYMGMT *m = EVP_SKEYMGMT_fetch(NULL, "GENERIC-SECRET", NULL);

        names.n = 0;
        r = EVP_SKEYMGMT_names_do_all(m, collect, &names);
        EVP_SKEYMGMT_free(m);
        show("EVP_SKEYMGMT_names_do_all", &names, r);
    }
    {
        EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
            (const unsigned char *)"key", 3);

        names.n = 0;
        r = EVP_PKEY_type_names_do_all(k, collect, &names);
        EVP_PKEY_free(k);
        show("EVP_PKEY_type_names_do_all", &names, r);
    }
    printf("1..%d\n", number);
    return failures != 0;
}
