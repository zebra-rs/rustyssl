/*
 * Conformance test for the AEAD helpers of modes.h (GCM, CCM, OCB, XTS), in TAP format, over
 * block functions of the test's own (AES underneath) and bulk CTR, CCM, and OCB functions that
 * log every call, so the calls each helper makes must be OpenSSL's:
 *   - GCM: 12-octet and other IVs, AAD and data in pieces, through the block and the CTR
 *     function (a message past 3 KiB, which OpenSSL hashes and streams in 3 KiB strides), the
 *     tag checked and read, AAD after data, a second finish and a tag after one (OpenSSL hashes
 *     what's buffered again), and init over a used context;
 *   - CCM over the context as OpenSSL's modes_local.h lays it out (it has no constructor):
 *     each tag and length field size, AAD, both functions, a length mismatch (which leaves the
 *     nonce block half reset), and the tag lengths;
 *   - OCB with and without a stream function, copies of contexts, and the tag lengths;
 *   - XTS over its context as modes_local.h lays it out, with stealing both ways.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/modes.h>

/* The contexts without constructors, as OpenSSL's modes_local.h lays them out. */
struct ccm128_context {
    union {
        uint64_t u[2];
        unsigned char c[16];
    } nonce, cmac;
    uint64_t blocks;
    block128_f block;
    void *key;
};

struct xts128_context {
    void *key1, *key2;
    block128_f block1, block2;
};

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void hex(const char *label, const void *p, size_t n)
{
    const unsigned char *b = p;
    size_t i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

static unsigned char data[4000];
static AES_KEY enc_key, dec_key, enc_key2;
static int logging = 0;
static int blocks_called = 0;

static void enc_block(const unsigned char in[16], unsigned char out[16], const void *key)
{
    blocks_called++;
    if (logging)
        hex("E", in, 16);
    AES_encrypt(in, out, key);
}

static void dec_block(const unsigned char in[16], unsigned char out[16], const void *key)
{
    blocks_called++;
    if (logging)
        hex("D", in, 16);
    AES_decrypt(in, out, key);
}

static void inc32(unsigned char c[16])
{
    unsigned int v = ((unsigned int)c[12] << 24 | (unsigned int)c[13] << 16
                      | (unsigned int)c[14] << 8 | c[15]) + 1;

    c[12] = (unsigned char)(v >> 24);
    c[13] = (unsigned char)(v >> 16);
    c[14] = (unsigned char)(v >> 8);
    c[15] = (unsigned char)v;
}

static void ctr_fn(const unsigned char *in, unsigned char *out, size_t blocks, const void *key,
                   const unsigned char ivec[16])
{
    unsigned char counter[16], k[16];
    size_t i, n;

    printf("  ctr %zu\n", blocks);
    if (logging)
        hex("iv", ivec, 16);
    memcpy(counter, ivec, 16);
    for (i = 0; i < blocks; i++) {
        AES_encrypt(counter, k, key);
        for (n = 0; n < 16; n++)
            out[16 * i + n] = in[16 * i + n] ^ k[n];
        inc32(counter);
    }
}

/* CCM's bulk function: CTR with the 64-bit counter, the plaintext into the CBC-MAC. */
static void ccm_fn(const unsigned char *in, unsigned char *out, size_t blocks, const void *key,
                   const unsigned char ivec[16], unsigned char cmac[16], int enc)
{
    unsigned char counter[16], k[16];
    size_t i, n;

    printf("  ccm %zu %d\n", blocks, enc);
    hex("iv", ivec, 16);
    hex("cmac", cmac, 16);
    memcpy(counter, ivec, 16);
    for (i = 0; i < blocks; i++) {
        AES_encrypt(counter, k, key);
        for (n = 0; n < 16; n++) {
            unsigned char x = in[16 * i + n], y = x ^ k[n];

            out[16 * i + n] = y;
            cmac[n] ^= enc ? x : y;
        }
        AES_encrypt(cmac, cmac, key);
        for (n = 15; n >= 8; n--)
            if (++counter[n] != 0)
                break;
    }
}

static void ccm_enc_fn(const unsigned char *in, unsigned char *out, size_t blocks,
                       const void *key, const unsigned char ivec[16], unsigned char cmac[16])
{
    ccm_fn(in, out, blocks, key, ivec, cmac, 1);
}

static void ccm_dec_fn(const unsigned char *in, unsigned char *out, size_t blocks,
                       const void *key, const unsigned char ivec[16], unsigned char cmac[16])
{
    ccm_fn(in, out, blocks, key, ivec, cmac, 0);
}

static unsigned int ntz(size_t n)
{
    unsigned int c = 0;

    while (!(n & 1)) {
        n >>= 1;
        c++;
    }
    return c;
}

/* OCB's bulk function, either way: decrypting under the decryption key. */
static void ocb_fn(const unsigned char *in, unsigned char *out, size_t blocks, const void *key,
                   size_t start, unsigned char offset[16], const unsigned char L[][16],
                   unsigned char checksum[16])
{
    int dec = key == &dec_key;
    size_t i, n;

    printf("  ocb %zu from %zu %s\n", blocks, start, dec ? "dec" : "enc");
    hex("offset", offset, 16);
    for (i = 0; i < blocks; i++) {
        unsigned char t[16];
        const unsigned char *l = L[ntz(start + i)];

        for (n = 0; n < 16; n++) {
            offset[n] ^= l[n];
            t[n] = in[16 * i + n] ^ offset[n];
        }
        if (dec)
            AES_decrypt(t, t, key);
        else
            AES_encrypt(t, t, key);
        for (n = 0; n < 16; n++) {
            out[16 * i + n] = t[n] ^ offset[n];
            checksum[n] ^= dec ? out[16 * i + n] : in[16 * i + n];
        }
    }
}

static void gcm(void)
{
    static const size_t ivlens[] = { 12, 1, 16, 60 };
    static const size_t pieces[] = { 1, 7, 16, 17, 100 };
    GCM128_CONTEXT *g = CRYPTO_gcm128_new(&enc_key, enc_block);
    unsigned char out[4000], back[4000], tag[16];
    size_t i, j, at;
    int r, use_ctr;

    check(g != NULL, "CRYPTO_gcm128_new");
    for (i = 0; i < sizeof(ivlens) / sizeof(ivlens[0]); i++) {
        for (j = 0; j < sizeof(pieces) / sizeof(pieces[0]); j++) {
            for (use_ctr = 0; use_ctr < 2; use_ctr++) {
                char label[64];
                int ok = 1;

                CRYPTO_gcm128_setiv(g, data + 3000, ivlens[i]);
                for (at = 0; at < 30; at += pieces[j])
                    ok = ok && CRYPTO_gcm128_aad(g, data + 2000 + at, at + pieces[j] > 30 ? 30 - at : pieces[j]) == 0;
                for (at = 0; at < 150; at += pieces[j]) {
                    size_t n = at + pieces[j] > 150 ? 150 - at : pieces[j];

                    ok = ok && (use_ctr ? CRYPTO_gcm128_encrypt_ctr32(g, data + at, out + at, n, ctr_fn)
                                        : CRYPTO_gcm128_encrypt(g, data + at, out + at, n)) == 0;
                }
                CRYPTO_gcm128_tag(g, tag, 16);
                snprintf(label, sizeof(label), "gcm iv %zu pieces %zu ctr %d", ivlens[i], pieces[j], use_ctr);
                hex(label, out, 150);
                hex("tag", tag, 16);
                CRYPTO_gcm128_setiv(g, data + 3000, ivlens[i]);
                ok = ok && CRYPTO_gcm128_aad(g, data + 2000, 30) == 0;
                for (at = 0; at < 150; at += pieces[j]) {
                    size_t n = at + pieces[j] > 150 ? 150 - at : pieces[j];

                    ok = ok && (use_ctr ? CRYPTO_gcm128_decrypt_ctr32(g, out + at, back + at, n, ctr_fn)
                                        : CRYPTO_gcm128_decrypt(g, out + at, back + at, n)) == 0;
                }
                ok = ok && memcmp(back, data, 150) == 0 && CRYPTO_gcm128_finish(g, tag, 16) == 0;
                check(ok, label);
            }
        }
    }

    /* The call pattern, logged: a message past 3 KiB through the CTR function. */
    logging = 1;
    blocks_called = 0;
    CRYPTO_gcm128_setiv(g, data + 3000, 12);
    CRYPTO_gcm128_aad(g, data, 5);
    r = CRYPTO_gcm128_encrypt_ctr32(g, data, out, 3 + 3072 + 160 + 5, ctr_fn);
    logging = 0;
    CRYPTO_gcm128_tag(g, tag, 16);
    printf("  long ctr32 %d, %d block calls\n", r, blocks_called);
    hex("tag", tag, 16);

    /* States: AAD after data, the tag lengths, finish twice, and the tag after a finish. */
    CRYPTO_gcm128_setiv(g, data + 3000, 12);
    CRYPTO_gcm128_aad(g, data, 20);
    CRYPTO_gcm128_encrypt(g, data, out, 5);
    printf("  aad after data %d\n", CRYPTO_gcm128_aad(g, data, 1));
    printf("  encrypt nothing %d\n", CRYPTO_gcm128_encrypt(g, data, out, 0));
    memset(tag, 0, sizeof(tag));
    printf("  finish wrong %d, no tag %d, 17 %d, 0 %d\n", CRYPTO_gcm128_finish(g, tag, 16),
           CRYPTO_gcm128_finish(g, NULL, 16), CRYPTO_gcm128_finish(g, tag, 17),
           CRYPTO_gcm128_finish(g, tag, 0));
    CRYPTO_gcm128_tag(g, tag, 16);
    hex("tag after finishes", tag, 16);
    CRYPTO_gcm128_setiv(g, data + 3000, 12);
    CRYPTO_gcm128_aad(g, data, 7);
    CRYPTO_gcm128_tag(g, tag, 10);
    hex("aad only", tag, 16);
    CRYPTO_gcm128_tag(g, tag, 16);
    hex("again", tag, 16);
    CRYPTO_gcm128_setiv(g, data + 3000, 12);
    CRYPTO_gcm128_aad(g, data, 7);
    printf("  aad then empty data %d\n", CRYPTO_gcm128_decrypt(g, data, out, 0));
    CRYPTO_gcm128_tag(g, tag, 16);
    hex("tag", tag, 16);
    CRYPTO_gcm128_setiv(g, data + 3000, 0);
    CRYPTO_gcm128_tag(g, tag, 16);
    hex("empty IV", tag, 16);

    /* Init over the used context, with another key. */
    CRYPTO_gcm128_init(g, &enc_key2, enc_block);
    CRYPTO_gcm128_setiv(g, data + 3000, 12);
    CRYPTO_gcm128_encrypt(g, data, out, 16);
    CRYPTO_gcm128_tag(g, tag, 16);
    hex("reinit", out, 16);
    hex("tag", tag, 16);
    CRYPTO_gcm128_release(g);
    CRYPTO_gcm128_release(NULL);
}

static void ccm(void)
{
    static const unsigned int ms[] = { 4, 8, 16 };
    static const unsigned int ls[] = { 2, 3, 8 };
    struct ccm128_context c;
    unsigned char out[200], back[200], tag[16], tag2[16];
    size_t i, j, n;
    int r, stream;

    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            for (stream = 0; stream < 2; stream++) {
                size_t lens[] = { 0, 5, 16, 37 };

                for (n = 0; n < 4; n++) {
                    char label[64];
                    int ok;

                    memset(&c, 0xa5, sizeof(c));
                    CRYPTO_ccm128_init(&c, ms[i], ls[j], &enc_key, enc_block);
                    r = CRYPTO_ccm128_setiv(&c, data + 100, 15 - ls[j], lens[n]);
                    if (n % 2 == 0)
                        CRYPTO_ccm128_aad(&c, data + 200, 20 + 300 * n);
                    r = r * 10 + (stream ? CRYPTO_ccm128_encrypt_ccm64(&c, data, out, lens[n], ccm_enc_fn)
                                         : CRYPTO_ccm128_encrypt(&c, data, out, lens[n]));
                    printf("  ccm M %u L %u len %zu stream %d: %d %zu\n", ms[i], ls[j], lens[n], stream, r,
                           CRYPTO_ccm128_tag(&c, tag, ms[i]));
                    hex("out", out, lens[n]);
                    hex("tag", tag, ms[i]);
                    hex("nonce", c.nonce.c, 16);
                    printf("  blocks %llu\n", (unsigned long long)c.blocks);
                    CRYPTO_ccm128_init(&c, ms[i], ls[j], &enc_key, enc_block);
                    CRYPTO_ccm128_setiv(&c, data + 100, 15 - ls[j], lens[n]);
                    if (n % 2 == 0)
                        CRYPTO_ccm128_aad(&c, data + 200, 20 + 300 * n);
                    ok = (stream ? CRYPTO_ccm128_decrypt_ccm64(&c, out, back, lens[n], ccm_dec_fn)
                                 : CRYPTO_ccm128_decrypt(&c, out, back, lens[n])) == 0;
                    ok = ok && CRYPTO_ccm128_tag(&c, tag2, ms[i]) == ms[i]
                         && memcmp(tag, tag2, ms[i]) == 0 && memcmp(back, data, lens[n]) == 0;
                    snprintf(label, sizeof(label), "ccm %u %u %zu %d", ms[i], ls[j], lens[n], stream);
                    check(ok, label);
                }
            }
        }
    }

    /* Logged block calls; a length mismatch; a nonce too short; tag lengths. */
    logging = 1;
    CRYPTO_ccm128_init(&c, 8, 2, &enc_key, enc_block);
    CRYPTO_ccm128_setiv(&c, data + 100, 13, 20);
    CRYPTO_ccm128_aad(&c, data, 3);
    r = CRYPTO_ccm128_encrypt(&c, data, out, 20);
    logging = 0;
    printf("  logged %d\n", r);
    CRYPTO_ccm128_setiv(&c, data + 100, 13, 20);
    r = CRYPTO_ccm128_encrypt(&c, data, out, 21);
    printf("  mismatch %d\n", r);
    hex("nonce", c.nonce.c, 16);
    hex("cmac", c.cmac.c, 16);
    r = CRYPTO_ccm128_decrypt(&c, data, out, 21);
    printf("  again %d\n", r);
    hex("nonce", c.nonce.c, 16);
    printf("  short nonce %d\n", CRYPTO_ccm128_setiv(&c, data, 12, 5));
    printf("  tag lengths %zu %zu %zu\n", CRYPTO_ccm128_tag(&c, tag, 8), CRYPTO_ccm128_tag(&c, tag, 7),
           CRYPTO_ccm128_tag(&c, tag, 16));
    CRYPTO_ccm128_init(&c, 3, 0, &enc_key, enc_block);
    hex("odd M, L 0", c.nonce.c, 16);
}

static void ocb(void)
{
    static const size_t ivlens[] = { 1, 12, 15 };
    static const size_t taglens[] = { 1, 8, 16 };
    OCB128_CONTEXT *o, *s, *copy;
    unsigned char out[700], back[700], tag[16];
    size_t i, at;
    int stream;

    o = CRYPTO_ocb128_new(&enc_key, &dec_key, enc_block, dec_block, NULL);
    s = CRYPTO_ocb128_new(&enc_key, &dec_key, enc_block, dec_block, ocb_fn);
    copy = CRYPTO_ocb128_new(&enc_key, &dec_key, enc_block, dec_block, NULL);
    check(o != NULL && s != NULL && copy != NULL, "CRYPTO_ocb128_new");
    for (stream = 0; stream < 2; stream++) {
        OCB128_CONTEXT *c = stream ? s : o;

        for (i = 0; i < 3; i++) {
            char label[64];
            int ok;

            ok = CRYPTO_ocb128_setiv(c, data + 50, ivlens[i], taglens[i]) == 1
                 && CRYPTO_ocb128_aad(c, data + 600, 32) == 1 && CRYPTO_ocb128_aad(c, data + 632, 5) == 1;
            /* 2 blocks, 35 at once (the stream sees the table grow), then 8 octets: only the
             * last call may have a partial block. */
            ok = ok && CRYPTO_ocb128_encrypt(c, data, out, 32) == 1
                 && CRYPTO_ocb128_encrypt(c, data + 32, out + 32, 560) == 1
                 && CRYPTO_ocb128_encrypt(c, data + 592, out + 592, 8) == 1;
            ok = ok && CRYPTO_ocb128_tag(c, tag, taglens[i]) == 1;
            snprintf(label, sizeof(label), "ocb iv %zu tag %zu stream %d", ivlens[i], taglens[i], stream);
            hex(label, out, 600);
            hex("tag", tag, taglens[i]);
            ok = ok && CRYPTO_ocb128_setiv(c, data + 50, ivlens[i], taglens[i]) == 1
                 && CRYPTO_ocb128_aad(c, data + 600, 37) == 1;
            for (at = 0; at < 592; at += 16)
                ok = ok && CRYPTO_ocb128_decrypt(c, out + at, back + at, 16) == 1;
            ok = ok && CRYPTO_ocb128_decrypt(c, out + 592, back + 592, 8) == 1;
            ok = ok && memcmp(back, data, 600) == 0 && CRYPTO_ocb128_finish(c, tag, taglens[i]) == 0;
            check(ok, label);
        }
    }
    printf("  setiv bad %d %d %d %d\n", CRYPTO_ocb128_setiv(o, data, 0, 16),
           CRYPTO_ocb128_setiv(o, data, 16, 16), CRYPTO_ocb128_setiv(o, data, 12, 0),
           CRYPTO_ocb128_setiv(o, data, 12, 17));
    printf("  tag bad %d %d, finish bad %d\n", CRYPTO_ocb128_tag(o, tag, 0), CRYPTO_ocb128_tag(o, tag, 17),
           CRYPTO_ocb128_finish(o, tag, 17));
    memset(tag, 0, 16);
    printf("  finish wrong %d\n", CRYPTO_ocb128_finish(o, tag, 16));

    /* A copy mid-message carries on as the original does. */
    CRYPTO_ocb128_setiv(o, data + 50, 12, 16);
    CRYPTO_ocb128_aad(o, data, 16);
    CRYPTO_ocb128_encrypt(o, data, out, 48);
    check(CRYPTO_ocb128_copy_ctx(copy, o, NULL, NULL) == 1, "CRYPTO_ocb128_copy_ctx");
    CRYPTO_ocb128_encrypt(o, data + 48, out + 48, 20);
    CRYPTO_ocb128_encrypt(copy, data + 48, back + 48, 20);
    CRYPTO_ocb128_tag(o, tag, 16);
    check(memcmp(out + 48, back + 48, 20) == 0 && CRYPTO_ocb128_finish(copy, tag, 16) == 0,
          "the copy carries on");
    /* Init over a used context. */
    check(CRYPTO_ocb128_init(copy, &enc_key2, &dec_key, enc_block, dec_block, NULL) == 1,
          "CRYPTO_ocb128_init");
    CRYPTO_ocb128_setiv(copy, data + 50, 12, 16);
    CRYPTO_ocb128_tag(copy, tag, 16);
    hex("other key", tag, 16);
    CRYPTO_ocb128_cleanup(o);
    CRYPTO_ocb128_cleanup(s);
    CRYPTO_ocb128_cleanup(copy);
    CRYPTO_ocb128_cleanup(NULL);
    OPENSSL_free(o);
    OPENSSL_free(s);
    OPENSSL_free(copy);
}

static void xts(void)
{
    static const size_t lens[] = { 15, 16, 17, 31, 32, 33, 64, 70 };
    struct xts128_context x = { &enc_key, &enc_key2, enc_block, enc_block };
    struct xts128_context y = { &dec_key, &enc_key2, dec_block, enc_block };
    unsigned char out[80], back[80];
    size_t i;

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        char label[32];
        int r1, r2;

        memset(out, 0xee, sizeof(out));
        memset(back, 0xee, sizeof(back));
        logging = lens[i] == 33;
        r1 = CRYPTO_xts128_encrypt(&x, data + 900, data, out, lens[i], 1);
        r2 = CRYPTO_xts128_encrypt(&y, data + 900, out, back, lens[i], 0);
        logging = 0;
        snprintf(label, sizeof(label), "xts %zu: %d %d", lens[i], r1, r2);
        hex(label, out, lens[i] + 1);
        check(r1 == (lens[i] < 16 ? -1 : 0) && (r1 != 0 || memcmp(back, data, lens[i]) == 0), label);
    }
}

int main(void)
{
    size_t i;
    unsigned char k[16];

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    for (i = 0; i < 16; i++)
        k[i] = (unsigned char)(i * 13 + 1);
    AES_set_encrypt_key(k, 128, &enc_key);
    AES_set_decrypt_key(k, 128, &dec_key);
    k[0] ^= 1;
    AES_set_encrypt_key(k, 128, &enc_key2);
    gcm();
    ccm();
    ocb();
    xts();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
