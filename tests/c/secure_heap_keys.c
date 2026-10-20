/*
 * Conformance test for what goes to the secure heap (CRYPTO_secure_malloc_init(3)): secure
 * BIGNUMs and private keys, made, copied, imported, decoded and freed, against operations
 * whose state doesn't go there (ciphers, MACs, KDFs, the random generator, public keys). In
 * TAP format.
 *
 * It checks only whether CRYPTO_secure_used() grows, stays, or shrinks: how many bytes is a
 * matter of each library's structures. rustyssl copies a key object whole into the heap, where
 * OpenSSL places only its private components (docs/adr/0005-secure-heap.md).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

static int failures = 0;
static int number = 0;
static size_t mark;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void start(void)
{
    mark = CRYPTO_secure_used();
}

static int grew(void)
{
    return CRYPTO_secure_used() > mark;
}

static int same(void)
{
    return CRYPTO_secure_used() == mark;
}

static int shrank(void)
{
    return CRYPTO_secure_used() < mark;
}

static void bignums(void)
{
    BIGNUM *a = BN_secure_new(), *b = BN_new();
    char what[80];

    start();
    check(a != NULL && BN_get_flags(a, BN_FLG_SECURE) != 0, "BN_secure_new: flagged secure");
    BN_set_word(a, 5);
    check(grew(), "BN_secure_new: its digits are in the heap");
    start();
    BN_lshift(a, a, 1000);
    check(grew(), "BN_secure_new: growing it stays in the heap");
    start();
    BN_free(a);
    check(shrank(), "BN_secure_new: freeing it returns its digits");

    start();
    BN_lshift(b, BN_value_one(), 1000);
    check(same(), "BN_new: its digits aren't in the heap");
    BN_free(b);

    /* The flag set before the number has digits: they're allocated in the heap. */
    b = BN_new();
    BN_set_flags(b, BN_FLG_SECURE);
    start();
    BN_lshift(b, BN_value_one(), 1000);
    snprintf(what, sizeof(what), "BN_FLG_SECURE set on BN_new: its digits are in the heap");
    check(grew(), what);
    start();
    BN_free(b);
    check(shrank(), "and freeing it returns them");
}

/* A key of `alg` (with its group or size), copied, then both freed. `dup`: whether a copy
 * goes to the heap on both libraries (OpenSSL keeps an EC or SLH-DSA key's copy elsewhere);
 * `returns`: whether freeing the key returns heap memory on both (OpenSSL's SLH-DSA keeps
 * it). */
static void keygen(const char *alg, const char *group, unsigned int bits, int dup, int returns)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *k = NULL, *d = NULL;
    char what[96];

    if (ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0) {
        if (group != NULL) {
            OSSL_PARAM p[] = {
                OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, strlen(group)),
                OSSL_PARAM_END
            };
            EVP_PKEY_CTX_set_params(ctx, p);
        } else if (bits != 0) {
            OSSL_PARAM p[] = { OSSL_PARAM_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits), OSSL_PARAM_END };
            EVP_PKEY_CTX_set_params(ctx, p);
        }
        start();
        EVP_PKEY_keygen(ctx, &k);
    }
    EVP_PKEY_CTX_free(ctx);
    snprintf(what, sizeof(what), "%s %s: a generated private key is in the heap", alg,
             group != NULL ? group : "");
    check(k != NULL && grew(), what);
    if (dup) {
        start();
        d = EVP_PKEY_dup(k);
        snprintf(what, sizeof(what), "%s: its copy is in the heap too", alg);
        check(d != NULL && grew(), what);
        start();
        EVP_PKEY_free(d);
        snprintf(what, sizeof(what), "%s: freeing the copy returns its memory", alg);
        check(shrank(), what);
    }
    start();
    EVP_PKEY_free(k);
    if (returns) {
        snprintf(what, sizeof(what), "%s: freeing the key returns its memory", alg);
        check(shrank(), what);
    }
}

static void not_secret(void)
{
    unsigned char key[32] = {1}, iv[16] = {2}, out[32];
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *m = EVP_MAC_CTX_new(mac);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *k = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM md[] = { OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 6), OSSL_PARAM_END };
    OSSL_PARAM kp[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 6),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof(key)),
        OSSL_PARAM_END
    };

    start();
    EVP_EncryptInit_ex2(c, EVP_aes_256_gcm(), key, iv, NULL);
    check(same(), "a cipher's key schedule isn't in the heap");
    start();
    EVP_MAC_init(m, key, sizeof(key), md);
    check(same(), "a MAC's key isn't in the heap");
    start();
    EVP_KDF_derive(k, out, sizeof(out), kp);
    check(same(), "a KDF's key isn't in the heap");
    start();
    RAND_priv_bytes(out, sizeof(out));
    check(same(), "the private random generator's state isn't in the heap");
    EVP_CIPHER_CTX_free(c);
    EVP_MAC_CTX_free(m);
    EVP_MAC_free(mac);
    EVP_KDF_CTX_free(k);
    EVP_KDF_free(kdf);
}

static void legacy(void)
{
    DH *dh = DH_new_by_nid(NID_ffdhe2048);
    RSA *r = RSA_new();
    BIGNUM *e = BN_new();
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const BIGNUM *priv = NULL;

    start();
    check(DH_generate_key(dh) == 1 && grew(), "DH_generate_key: the private key is in the heap");
    DH_get0_key(dh, NULL, &priv);
    check(priv != NULL && BN_get_flags(priv, BN_FLG_SECURE) != 0,
          "DH_generate_key: the private key is a secure number");
    start();
    DH_free(dh);
    check(shrank(), "DH_free returns it");

    BN_set_word(e, 65537);
    start();
    check(RSA_generate_key_ex(r, 2048, e, NULL) == 1 && grew(),
          "RSA_generate_key_ex: the private key is in the heap");
    start();
    RSA_free(r);
    check(shrank(), "RSA_free returns it");
    BN_free(e);

    start();
    check(EC_KEY_generate_key(ec) == 1 && grew(), "EC_KEY_generate_key: the private key is in the heap");
    start();
    EC_KEY_free(ec);
    check(shrank(), "EC_KEY_free returns it");
}

static void loaded(void)
{
    unsigned char raw[32] = {9, 8, 7}, *der = NULL, *pub = NULL;
    const unsigned char *p;
    EVP_PKEY *ec = EVP_EC_gen("P-256"), *k;
    int derlen = i2d_PrivateKey(ec, &der), publen = i2d_PUBKEY(ec, &pub);
    BIO *b = BIO_new(BIO_s_mem());

    start();
    k = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, raw, sizeof(raw));
    check(k != NULL && same(), "a raw public key isn't in the heap");
    EVP_PKEY_free(k);

    start();
    k = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, raw, sizeof(raw));
    check(k != NULL && grew(), "a MAC key is in the heap");
    start();
    EVP_PKEY_free(k);
    check(shrank(), "and freeing it returns it");

    p = der;
    start();
    k = d2i_AutoPrivateKey(NULL, &p, derlen);
    check(k != NULL && grew(), "a decoded private key is in the heap");
    start();
    EVP_PKEY_free(k);
    check(shrank(), "and freeing it returns it");

    p = pub;
    start();
    k = d2i_PUBKEY(NULL, &p, publen);
    check(k != NULL && same(), "a decoded public key isn't in the heap");
    EVP_PKEY_free(k);

    PEM_write_bio_PrivateKey(b, ec, NULL, NULL, 0, NULL, NULL);
    start();
    k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    check(k != NULL && grew(), "a private key read from PEM is in the heap");
    start();
    EVP_PKEY_free(k);
    check(shrank(), "and freeing it returns it");

    BIO_free(b);
    OPENSSL_free(der);
    OPENSSL_free(pub);
    EVP_PKEY_free(ec);
}

int main(void)
{
    check(CRYPTO_secure_malloc_init(1 << 20, 16) == 1, "a 1 MiB secure heap");
    check(CRYPTO_secure_used() == 0, "nothing in it yet");
    bignums();
    keygen("RSA", NULL, 2048, 1, 1);
    keygen("EC", "P-256", 0, 0, 1);
    keygen("X25519", NULL, 0, 1, 1);
    keygen("X448", NULL, 0, 1, 1);
    keygen("ED25519", NULL, 0, 1, 1);
    keygen("ED448", NULL, 0, 1, 1);
    keygen("DH", "ffdhe2048", 0, 1, 1);
    keygen("ML-KEM-768", NULL, 0, 1, 1);
    keygen("ML-DSA-65", NULL, 0, 1, 1);
    keygen("SLH-DSA-SHA2-128s", NULL, 0, 0, 0);
    not_secret();
    legacy();
    loaded();
    printf("1..%d\n", number);
    return failures != 0;
}
