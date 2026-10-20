/*
 * Conformance test for a small secure heap holding many private keys (CRYPTO_secure_malloc(3)),
 * in TAP format: keys still generate, and a new thread's private random generator, whose
 * entropy comes from the secure heap, still instantiates.
 *
 * rustyssl copies a key object whole into the heap, more than OpenSSL's private components,
 * and stops placing keys there once the heap is half full, so that the library's own secure
 * allocations still find room (docs/adr/0005-secure-heap.md).
 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEYS 40

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void *random_bytes(void *arg)
{
    unsigned char out[32];

    *(int *)arg = RAND_priv_bytes(out, sizeof(out)) == 1 && RAND_bytes(out, sizeof(out)) == 1;
    return NULL;
}

int main(void)
{
    EVP_PKEY *keys[KEYS];
    pthread_t t;
    int made = 0, ok = 0;

    check(CRYPTO_secure_malloc_init(4096, 16) == 1, "a 4 KiB secure heap");
    for (int i = 0; i < KEYS; i++) {
        keys[i] = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        made += keys[i] != NULL;
    }
    check(made == KEYS, "40 Ed25519 keys generate");
    check(CRYPTO_secure_used() > 0, "some of them are in the heap");
    check(pthread_create(&t, NULL, random_bytes, &ok) == 0 && pthread_join(t, NULL) == 0 && ok,
          "a new thread's random generators instantiate");
    for (int i = 0; i < KEYS; i++)
        EVP_PKEY_free(keys[i]);
    printf("1..%d\n", number);
    return failures != 0;
}
