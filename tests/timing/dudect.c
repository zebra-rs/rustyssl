/*
 * Constant-time checks (TEST_PLAN.md, constant-time verification), dudect's way: each target
 * runs one operation on inputs of two classes, a fixed one and random ones (or, for the
 * Marvin-style RSA check, valid and invalid paddings), drawn in random order, and times each
 * run. Welch's t-test compares the classes' times, on all of them and on the runs under each of
 * a hundred percentiles (dudect's cropping), plus a second-order test on the centered squares.
 * The largest |t| is the target's verdict: dudect calls over 10 "definitely not constant time".
 *
 *   dudect <target> <measurements>
 *
 * prints `<target> t=<max |t|> n=<measurements>` (and the cropping that gave it). Driven by
 * `cargo xtask test-timing`, which runs it on the reference and on rustyssl. The inputs of
 * both classes are made before any is timed, so making them isn't measured.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#define _POSIX_C_SOURCE 200809L

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif

/* The time stamp: the cycle counter where there's one to read, else the finest clock. */
static inline uint64_t now(void)
{
#if defined(__x86_64__)
    uint32_t lo, hi;

    __asm__ volatile("lfence\n\trdtsc\n\tlfence" : "=a"(lo), "=d"(hi)::"memory");
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__) && !defined(__APPLE__)
    uint64_t v;

    __asm__ volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(v)::"memory");
    return v;
#elif defined(__APPLE__)
    return mach_absolute_time();
#else
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
#endif
}

/* Welch's t-test, accumulated (Welford). */
struct ttest {
    double mean[2], m2[2], n[2];
};

static void t_push(struct ttest *t, double x, int c)
{
    double d;

    t->n[c] += 1;
    d = x - t->mean[c];
    t->mean[c] += d / t->n[c];
    t->m2[c] += d * (x - t->mean[c]);
}

static double t_value(const struct ttest *t)
{
    double v0, v1, den;

    if (t->n[0] < 2 || t->n[1] < 2)
        return 0;
    v0 = t->m2[0] / (t->n[0] - 1);
    v1 = t->m2[1] / (t->n[1] - 1);
    den = sqrt(v0 / t->n[0] + v1 / t->n[1]);
    return den == 0 ? 0 : (t->mean[0] - t->mean[1]) / den;
}

#define PERCENTILES 100
#define BATCH 10000

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

    return x < y ? -1 : x > y;
}

/* A target: its state, made once, its inputs, made per batch, and the timed operation. */
struct target {
    const char *name;
    int (*setup)(void);
    /* Makes input i of class c (0 fixed, 1 random) into its slot. */
    void (*prepare)(size_t i, int c);
    /* Runs the operation on input i. */
    void (*run)(size_t i);
    /* How many runs one measurement times (fast operations repeat to beat the clock's step). */
    int reps;
    /* Inputs made per batch (0: BATCH); fewer for inputs that hold a connection each. */
    size_t batch;
};

#define MAXIN 1536
static unsigned char in[BATCH][MAXIN];
static size_t inlen[BATCH];
static volatile unsigned char sink;

static void random_bytes(unsigned char *p, size_t n)
{
    if (RAND_bytes(p, (int)n) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        exit(2);
    }
}

/* ---- AES-128-GCM: the key (a fixed one, or random ones), a fixed message. ---- */
static EVP_CIPHER *gcm;
static EVP_CIPHER_CTX *cctx;
static unsigned char msg64[64], iv12[12], out[1024];

static int aes_setup(void)
{
    gcm = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    cctx = EVP_CIPHER_CTX_new();
    memset(msg64, 0x5a, sizeof(msg64));
    return gcm != NULL && cctx != NULL;
}

/* The fixed class's key: random, made once (an all-zero key would be a degenerate case). */
static unsigned char fixed32[32];
static int have_fixed32;

static void key_prepare(size_t i, int c)
{
    inlen[i] = 32;
    if (!have_fixed32) {
        random_bytes(fixed32, 32);
        have_fixed32 = 1;
    }
    if (c == 0)
        memcpy(in[i], fixed32, 32);
    else
        random_bytes(in[i], 32);
}

static void aes_run(size_t i)
{
    int n = 0;

    EVP_EncryptInit_ex(cctx, gcm, NULL, in[i], iv12);
    EVP_EncryptUpdate(cctx, out, &n, msg64, sizeof(msg64));
    EVP_EncryptFinal_ex(cctx, out + n, &n);
    sink ^= out[0];
}

/* ---- GHASH: GCM's tag check. ---- */
static unsigned char key16[16], ct64[64], tag16[16];

static int ghash_setup(void)
{
    int n = 0;

    if (!aes_setup())
        return 0;
    random_bytes(key16, 16);
    EVP_EncryptInit_ex(cctx, gcm, NULL, key16, iv12);
    EVP_EncryptUpdate(cctx, ct64, &n, msg64, sizeof(msg64));
    EVP_EncryptFinal_ex(cctx, ct64 + n, &n);
    return EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, 16, tag16) == 1;
}

/* Both classes fail: a tag wrong in its last octet only (what an early-exit comparison takes
 * longest on), or a random one; whether a tag is right is public anyway. */
static void tag_prepare(size_t i, int c)
{
    inlen[i] = 16;
    if (c == 0) {
        memcpy(in[i], tag16, 16);
        in[i][15] ^= 1;
    } else {
        random_bytes(in[i], 16);
    }
}

static void ghash_run(size_t i)
{
    int n = 0;

    EVP_DecryptInit_ex(cctx, gcm, NULL, key16, iv12);
    EVP_DecryptUpdate(cctx, out, &n, ct64, sizeof(ct64));
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, 16, in[i]);
    sink ^= (unsigned char)EVP_DecryptFinal_ex(cctx, out + n, &n);
}

/* ---- Poly1305: the key, over a fixed message. ---- */
static EVP_MAC *poly;

static int poly_setup(void)
{
    poly = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    memset(msg64, 0x5a, sizeof(msg64));
    return poly != NULL;
}

static void poly_run(size_t i)
{
    EVP_MAC_CTX *m = EVP_MAC_CTX_new(poly);
    size_t n = 0;

    EVP_MAC_init(m, in[i], 32, NULL);
    EVP_MAC_update(m, msg64, sizeof(msg64));
    EVP_MAC_final(m, out, &n, sizeof(out));
    EVP_MAC_CTX_free(m);
    sink ^= out[0];
}

/* ---- X25519: the private key, with a fixed peer. ---- */
static EVP_PKEY *peer;
static EVP_PKEY *keys[BATCH];

static int x25519_setup(void)
{
    unsigned char pub[32];

    random_bytes(pub, 32);
    pub[31] &= 0x7f;
    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, 32);
    return peer != NULL;
}

static void x25519_prepare(size_t i, int c)
{
    unsigned char priv[32];

    if (c == 0)
        memset(priv, 0x11, 32);
    else
        random_bytes(priv, 32);
    EVP_PKEY_free(keys[i]);
    keys[i] = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
}

static void x25519_run(size_t i)
{
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new(keys[i], NULL);
    size_t n = sizeof(out);

    EVP_PKEY_derive_init(d);
    EVP_PKEY_derive_set_peer(d, peer);
    EVP_PKEY_derive(d, out, &n);
    EVP_PKEY_CTX_free(d);
    sink ^= out[0];
}

/* ---- ECDSA P-256 signing: the private key (fixed, or one of a pool of random ones). ---- */
#define POOL 64
static EVP_PKEY *pool[POOL], *fixed_key;
static EVP_PKEY *picked[BATCH];
static unsigned char digest32[32];

static int ecdsa_setup(void)
{
    int i;

    for (i = 0; i < POOL; i++)
        if ((pool[i] = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")) == NULL)
            return 0;
    fixed_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    memset(digest32, 0x33, sizeof(digest32));
    return fixed_key != NULL;
}

static void ecdsa_prepare(size_t i, int c)
{
    unsigned char r;

    random_bytes(&r, 1);
    picked[i] = c == 0 ? fixed_key : pool[r % POOL];
}

static void ecdsa_run(size_t i)
{
    EVP_PKEY_CTX *s = EVP_PKEY_CTX_new(picked[i], NULL);
    size_t n = sizeof(out);

    EVP_PKEY_sign_init(s);
    EVP_PKEY_sign(s, out, &n, digest32, sizeof(digest32));
    EVP_PKEY_CTX_free(s);
    sink ^= out[0];
}

/* ---- RSA-2048 PKCS #1 v1.5 decryption, implicit rejection on (Marvin's classes): a valid
 * ciphertext, or ciphertexts of random paddings (almost all invalid). ---- */
static EVP_PKEY *rsa;
static size_t rsalen;

static int rsa_setup(void)
{
    rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    rsalen = 256;
    return rsa != NULL;
}

/* The raw RSA encryption of `em` (the key's length) into `ct`. */
static void rsa_raw(const unsigned char *em, unsigned char *ct)
{
    EVP_PKEY_CTX *e = EVP_PKEY_CTX_new(rsa, NULL);
    size_t n = rsalen;

    EVP_PKEY_encrypt_init(e);
    EVP_PKEY_CTX_set_rsa_padding(e, RSA_NO_PADDING);
    EVP_PKEY_encrypt(e, ct, &n, em, rsalen);
    EVP_PKEY_CTX_free(e);
}

static void rsa_prepare(size_t i, int c)
{
    static unsigned char valid[256];
    static int made;
    unsigned char em[256];

    inlen[i] = rsalen;
    if (!made) {
        EVP_PKEY_CTX *e = EVP_PKEY_CTX_new(rsa, NULL);
        size_t n = rsalen;

        EVP_PKEY_encrypt_init(e);
        EVP_PKEY_CTX_set_rsa_padding(e, RSA_PKCS1_PADDING);
        EVP_PKEY_encrypt(e, valid, &n, (const unsigned char *)"a 48-octet TLS premaster secret, more or less!!", 48);
        EVP_PKEY_CTX_free(e);
        made = 1;
    }
    if (c == 0) {
        memcpy(in[i], valid, rsalen);
        return;
    }
    /* 00 || random: below the modulus, its padding wrong but for chance. */
    random_bytes(em, rsalen);
    em[0] = 0;
    rsa_raw(em, in[i]);
}

static void rsa_run(size_t i)
{
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new(rsa, NULL);
    size_t n = sizeof(out);

    EVP_PKEY_decrypt_init(d);
    EVP_PKEY_CTX_set_rsa_padding(d, RSA_PKCS1_PADDING);
    EVP_PKEY_decrypt(d, out, &n, in[i], inlen[i]);
    EVP_PKEY_CTX_free(d);
    sink ^= out[0];
    ERR_clear_error();
}

/* ---- RSA-2048 raw (no padding) decryption: a fixed ciphertext, or random ones. ---- */
static void rsaraw_prepare(size_t i, int c)
{
    unsigned char em[256];

    inlen[i] = rsalen;
    if (c == 0)
        memset(em, 0, rsalen), em[rsalen - 1] = 7;
    else
        random_bytes(em, rsalen), em[0] = 0;
    rsa_raw(em, in[i]);
}

static void rsaraw_run(size_t i)
{
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new(rsa, NULL);
    size_t n = sizeof(out);

    EVP_PKEY_decrypt_init(d);
    EVP_PKEY_CTX_set_rsa_padding(d, RSA_NO_PADDING);
    EVP_PKEY_decrypt(d, out, &n, in[i], inlen[i]);
    EVP_PKEY_CTX_free(d);
    sink ^= out[0];
}

/* ---- BN_mod_exp_mont_consttime: the exponent, with a fixed base and 2048-bit modulus. ---- */
static BIGNUM *bn_base, *bn_mod, *bn_r, *bn_e[BATCH];
static BN_CTX *bnctx;

static int bn_setup(void)
{
    bnctx = BN_CTX_new();
    bn_base = BN_new();
    bn_mod = BN_new();
    bn_r = BN_new();
    BN_rand(bn_mod, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    BN_rand_range(bn_base, bn_mod);
    return bnctx != NULL;
}

static void bn_prepare(size_t i, int c)
{
    if (bn_e[i] == NULL)
        bn_e[i] = BN_new();
    if (c == 0)
        BN_set_word(bn_e[i], 1), BN_lshift(bn_e[i], bn_e[i], 2047);
    else
        BN_rand(bn_e[i], 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_set_flags(bn_e[i], BN_FLG_CONSTTIME);
}

static void bn_run(size_t i)
{
    BN_mod_exp_mont_consttime(bn_r, bn_base, bn_e[i], bn_mod, bnctx, NULL);
    sink ^= (unsigned char)BN_is_zero(bn_r);
}

/* ---- HMAC verification's comparison (CRYPTO_memcmp). ---- */
static unsigned char expect32[32];

static int memcmp_setup(void)
{
    random_bytes(expect32, 32);
    return 1;
}

/* As GHASH's tags: differing in the last octet only, or random. */
static void memcmp_prepare(size_t i, int c)
{
    inlen[i] = 32;
    if (c == 0) {
        memcpy(in[i], expect32, 32);
        in[i][31] ^= 1;
    } else {
        random_bytes(in[i], 32);
    }
}

static void memcmp_run(size_t i)
{
    sink ^= (unsigned char)CRYPTO_memcmp(in[i], expect32, 32);
}

/* ---- ML-KEM-768 decapsulation: a valid ciphertext, or random ones (implicit rejection). ---- */
static EVP_PKEY *mlkem;
static unsigned char mlkem_ct[1088];

static int mlkem_setup(void)
{
    EVP_PKEY_CTX *e;
    size_t n = sizeof(mlkem_ct), sl = sizeof(out);

    mlkem = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    if (mlkem == NULL)
        return 0;
    e = EVP_PKEY_CTX_new(mlkem, NULL);
    EVP_PKEY_encapsulate_init(e, NULL);
    EVP_PKEY_encapsulate(e, mlkem_ct, &n, out, &sl);
    EVP_PKEY_CTX_free(e);
    return n == sizeof(mlkem_ct);
}

static void mlkem_prepare(size_t i, int c)
{
    inlen[i] = sizeof(mlkem_ct);
    if (c == 0)
        memcpy(in[i], mlkem_ct, sizeof(mlkem_ct));
    else
        random_bytes(in[i], sizeof(mlkem_ct));
}

static void mlkem_run(size_t i)
{
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new(mlkem, NULL);
    size_t n = sizeof(out);

    EVP_PKEY_decapsulate_init(d, NULL);
    EVP_PKEY_decapsulate(d, out, &n, in[i], inlen[i]);
    EVP_PKEY_CTX_free(d);
    sink ^= out[0];
}

/*
 * ---- Lucky13: a TLS 1.2 server reading a MAC-then-encrypt CBC record (AES-128-CBC with
 * HMAC-SHA1, no encrypt-then-MAC) that fails. The client's 512-octet record is altered
 * through its next-to-last ciphertext block so the last plaintext octet, the padding length,
 * is 0 (class 0) or 255 (class 1): a server whose MAC check's work depends on the padding
 * takes longer on one. Each input is its own connection, resumed from one session so the
 * handshakes stay cheap, and made (record and all) before anything is timed. ----
 */
#define TLS_BATCH 500
static SSL_CTX *tls_cctx, *tls_sctx;
static SSL_SESSION *tls_sess;
static SSL *tls_srv[TLS_BATCH];

static int tls_pump(SSL *c, SSL *s)
{
    int k;

    for (k = 0; k < 32; k++) {
        /* Each end's error before the other runs: the other's write changes the BIO's flags. */
        int rc = SSL_do_handshake(c), ec = rc == 1 ? SSL_ERROR_NONE : SSL_get_error(c, rc);
        int rs = SSL_do_handshake(s), es = rs == 1 ? SSL_ERROR_NONE : SSL_get_error(s, rs);

        if (rc == 1 && rs == 1)
            return 1;
        if ((ec != SSL_ERROR_NONE && ec != SSL_ERROR_WANT_READ)
            || (es != SSL_ERROR_NONE && es != SSL_ERROR_WANT_READ))
            return 0;
    }
    return 0;
}

/* A connected pair over memory BIOs: the client writes to the server's read BIO and back. */
static int tls_pair(SSL **c, SSL **s)
{
    BIO *c2s = BIO_new(BIO_s_mem()), *s2c = BIO_new(BIO_s_mem());

    *c = SSL_new(tls_cctx);
    *s = SSL_new(tls_sctx);
    if (*c == NULL || *s == NULL || c2s == NULL || s2c == NULL)
        return 0;
    /* Empty is "try again", not the end. */
    BIO_set_mem_eof_return(c2s, -1);
    BIO_set_mem_eof_return(s2c, -1);
    BIO_up_ref(c2s);
    BIO_up_ref(s2c);
    SSL_set_bio(*c, s2c, c2s);
    SSL_set_bio(*s, c2s, s2c);
    SSL_set_connect_state(*c);
    SSL_set_accept_state(*s);
    if (tls_sess != NULL)
        SSL_set_session(*c, tls_sess);
    return tls_pump(*c, *s);
}

static int tls_setup(void)
{
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509 *cert = X509_new();
    SSL *c, *s;
    int ok;

    if (key == NULL || cert == NULL)
        return 0;
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 86400);
    X509_set_pubkey(cert, key);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
                               (const unsigned char *)"dudect", -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(cert));
    X509_sign(cert, key, EVP_sha256());
    tls_cctx = SSL_CTX_new(TLS_client_method());
    tls_sctx = SSL_CTX_new(TLS_server_method());
    if (tls_cctx == NULL || tls_sctx == NULL)
        return 0;
    SSL_CTX_set_max_proto_version(tls_cctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(tls_cctx, "ECDHE-ECDSA-AES128-SHA");
    SSL_CTX_set_options(tls_cctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
    SSL_CTX_set_cipher_list(tls_sctx, "ECDHE-ECDSA-AES128-SHA");
    SSL_CTX_set_options(tls_sctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
    SSL_CTX_use_certificate(tls_sctx, cert);
    SSL_CTX_use_PrivateKey(tls_sctx, key);
    X509_free(cert);
    EVP_PKEY_free(key);
    /* One full handshake for the session the others resume. */
    ok = tls_pair(&c, &s);
    if (ok)
        tls_sess = SSL_get1_session(c);
    SSL_free(c);
    SSL_free(s);
    return ok && tls_sess != NULL;
}

static void tls_prepare(size_t i, int c)
{
    static unsigned char msg[512];
    unsigned char rec[1024];
    SSL *cl, *sv;
    BIO *rb;
    int n;
    size_t pad, body;

    SSL_free(tls_srv[i]);
    tls_srv[i] = NULL;
    if (!tls_pair(&cl, &sv) || SSL_write(cl, msg, (int)sizeof(msg)) != (int)sizeof(msg)) {
        fprintf(stderr, "tls-cbc-record: no connection\n");
        exit(2);
    }
    /* The client's record went to the server's read BIO: take it out, alter it, put it back. */
    rb = SSL_get_rbio(sv);
    n = BIO_read(rb, rec, (int)sizeof(rec));
    /* header 5, explicit IV 16, then the message, the MAC (20) and the padding */
    body = n > 5 + 16 ? (size_t)n - 5 - 16 : 0;
    if (body < sizeof(msg) + 20 + 1 || body % 16 != 0 || n < 5 + 16 + 32) {
        fprintf(stderr, "tls-cbc-record: unexpected record of %d octets\n", n);
        exit(2);
    }
    pad = body - sizeof(msg) - 20 - 1;
    /* The last plaintext octet is `pad`; XOR into the block before it makes it 0 or 255. */
    rec[n - 16 - 1] ^= (unsigned char)(pad ^ (c == 0 ? 0 : 255));
    BIO_write(rb, rec, n);
    SSL_free(cl);
    tls_srv[i] = sv;
}

static void tls_run(size_t i)
{
    sink ^= (unsigned char)SSL_read(tls_srv[i], out, (int)sizeof(out));
}

static const struct target targets[] = {
    { "aes-gcm", aes_setup, key_prepare, aes_run, 8, 0 },
    { "ghash", ghash_setup, tag_prepare, ghash_run, 8, 0 },
    { "poly1305", poly_setup, key_prepare, poly_run, 8, 0 },
    { "x25519", x25519_setup, x25519_prepare, x25519_run, 1, 0 },
    { "ecdsa-sign", ecdsa_setup, ecdsa_prepare, ecdsa_run, 1, 0 },
    { "rsa-pkcs1-decrypt", rsa_setup, rsa_prepare, rsa_run, 1, 0 },
    { "rsa-raw-decrypt", rsa_setup, rsaraw_prepare, rsaraw_run, 1, 0 },
    { "bn-modexp-consttime", bn_setup, bn_prepare, bn_run, 1, 0 },
    { "memcmp", memcmp_setup, memcmp_prepare, memcmp_run, 1024, 0 },
    { "ml-kem-decap", mlkem_setup, mlkem_prepare, mlkem_run, 1, 0 },
    { "tls-cbc-record", tls_setup, tls_prepare, tls_run, 1, TLS_BATCH },
};

int main(int argc, char **argv)
{
    const struct target *t = NULL;
    long total;
    size_t i, k, done = 0;
    static uint64_t times[BATCH], sorted[BATCH];
    static unsigned char cls[BATCH];
    static struct ttest tests[PERCENTILES + 2];
    double cut[PERCENTILES], best = 0;
    int have_cuts = 0, best_at = -1;

    if (argc != 3) {
        fprintf(stderr, "usage: dudect <target> <measurements>\n");
        return 2;
    }
    for (i = 0; i < sizeof(targets) / sizeof(targets[0]); i++)
        if (strcmp(targets[i].name, argv[1]) == 0)
            t = &targets[i];
    total = strtol(argv[2], NULL, 10);
    if (t == NULL || total <= 0) {
        fprintf(stderr, "unknown target or count\n");
        return 2;
    }
    if (!t->setup()) {
        fprintf(stderr, "%s: setup failed\n", t->name);
        ERR_print_errors_fp(stderr);
        return 2;
    }
    while (done < (size_t)total) {
        size_t cap = t->batch != 0 ? t->batch : BATCH;
        size_t n = (size_t)total - done < cap ? (size_t)total - done : cap;

        for (i = 0; i < n; i++) {
            unsigned char r;

            random_bytes(&r, 1);
            cls[i] = r & 1;
            t->prepare(i, cls[i]);
        }
        for (i = 0; i < n; i++) {
            uint64_t a, b;
            int rep;

            a = now();
            for (rep = 0; rep < t->reps; rep++)
                t->run(i);
            b = now();
            times[i] = b - a;
        }
        /* The first batch sets the percentiles' cut points (dudect's crops). */
        if (!have_cuts) {
            memcpy(sorted, times, n * sizeof(times[0]));
            qsort(sorted, n, sizeof(sorted[0]), cmp_u64);
            for (k = 0; k < PERCENTILES; k++) {
                double q = 1 - pow(0.5, 10.0 * (double)(k + 1) / PERCENTILES);
                size_t at = (size_t)(q * (double)n);

                cut[k] = (double)sorted[at < n ? at : n - 1];
            }
            have_cuts = 1;
            done += n;
            continue; /* warm-up, as dudect discards its first batch */
        }
        for (i = 0; i < n; i++) {
            double x = (double)times[i];

            t_push(&tests[0], x, cls[i]);
            for (k = 0; k < PERCENTILES; k++)
                if (x < cut[k])
                    t_push(&tests[k + 1], x, cls[i]);
        }
        /* Second order: centered squares against the first test's means. */
        for (i = 0; i < n; i++) {
            double d = (double)times[i] - tests[0].mean[cls[i]];

            t_push(&tests[PERCENTILES + 1], d * d, cls[i]);
        }
        done += n;
    }
    for (k = 0; k < PERCENTILES + 2; k++) {
        double v = fabs(t_value(&tests[k]));

        /* dudect skips tests with too few runs to say anything. */
        if (tests[k].n[0] + tests[k].n[1] < 10000)
            continue;
        if (v > best) {
            best = v;
            best_at = (int)k;
        }
    }
    printf("%s t=%.2f n=%ld test=%s\n", t->name, best, total,
           best_at == 0 ? "all" : best_at == PERCENTILES + 1 ? "second-order" : "cropped");
    (void)sink;
    return 0;
}
