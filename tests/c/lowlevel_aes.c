/*
 * Conformance test for the deprecated AES functions (AES_encrypt(3)) and the block-mode
 * helpers in modes.h, in TAP format:
 *   - AES_set_encrypt_key and AES_set_decrypt_key for each size and the refused ones, with the
 *     AES_KEY they leave (its words are the platform's: OpenSSL's x86_64 assembly keeps the
 *     round keys as octets, its C code as big-endian words), and the block functions;
 *   - CBC with partial last blocks (written whole on encryption, read whole on decryption),
 *     CFB-128, CFB-8, CFB-1, and OFB in pieces with the position carried between calls, and a
 *     negative position; IGE and bi-IGE; the RFC 3394 key wraps;
 *   - the CRYPTO_*128 helpers over block, CBC, and CTR functions of the test's own that log
 *     every call, so the calls each makes (their order, lengths, IVs, and data) must be
 *     OpenSSL's: CBC, CTR (with the 32-bit counter's carry), OFB, the CFBs, ciphertext stealing
 *     both ways and in each form, and the key wraps with and without padding.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/modes.h>

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

static unsigned char data[200];
static unsigned char keybytes[32];
static AES_KEY enc_key, dec_key;

/* Block, CBC, and CTR functions over the AES functions that log each call. */
static int logging = 0;

static void log_block(const char *what, const unsigned char *in)
{
    if (logging)
        hex(what, in, 16);
}

static void enc_block(const unsigned char in[16], unsigned char out[16], const void *key)
{
    log_block("E", in);
    AES_encrypt(in, out, key);
}

static void dec_block(const unsigned char in[16], unsigned char out[16], const void *key)
{
    log_block("D", in);
    AES_decrypt(in, out, key);
}

static void cbc_fn(const unsigned char *in, unsigned char *out, size_t len, const void *key,
                   unsigned char ivec[16], int enc)
{
    if (logging) {
        printf("  cbc %zu %d\n", len, enc);
        hex("iv", ivec, 16);
        hex("in", in, len);
    }
    AES_cbc_encrypt(in, out, len, enc ? &enc_key : &dec_key, ivec, enc);
    (void)key;
}

static void ctr_fn(const unsigned char *in, unsigned char *out, size_t blocks, const void *key,
                   const unsigned char ivec[16])
{
    unsigned char counter[16], k[16];
    size_t i, n;

    if (logging) {
        printf("  ctr %zu\n", blocks);
        hex("iv", ivec, 16);
    }
    memcpy(counter, ivec, 16);
    for (i = 0; i < blocks; i++) {
        unsigned int c;

        AES_encrypt(counter, k, key);
        for (n = 0; n < 16; n++)
            out[16 * i + n] = in[16 * i + n] ^ k[n];
        /* The 32-bit counter only. */
        c = ((unsigned int)counter[12] << 24 | (unsigned int)counter[13] << 16
             | (unsigned int)counter[14] << 8 | counter[15]) + 1;
        counter[12] = (unsigned char)(c >> 24);
        counter[13] = (unsigned char)(c >> 16);
        counter[14] = (unsigned char)(c >> 8);
        counter[15] = (unsigned char)c;
    }
}

static void keys(void)
{
    static const int bits[] = { 128, 192, 256, 0, 64, 129, 512 };
    AES_KEY k;
    unsigned char out[16], back[16];
    size_t i;
    int ok = 1;

    printf("  options %s size %zu\n", AES_options(), sizeof(AES_KEY));
    for (i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
        int r;

        memset(&k, 0xa5, sizeof(k));
        r = AES_set_encrypt_key(keybytes, bits[i], &k);
        printf("  set_encrypt_key %d: %d\n", bits[i], r);
        hex("key", &k, sizeof(k));
        if (r == 0) {
            AES_encrypt(data, out, &k);
            hex("encrypt", out, 16);
        }
        memset(&k, 0xa5, sizeof(k));
        r = AES_set_decrypt_key(keybytes, bits[i], &k);
        printf("  set_decrypt_key %d: %d\n", bits[i], r);
        hex("key", &k, sizeof(k));
        if (r == 0) {
            AES_decrypt(out, back, &k);
            ok = ok && memcmp(back, data, 16) == 0;
        }
    }
    check(ok, "decryption inverts encryption");
    check(AES_set_encrypt_key(NULL, 128, &k) == -1 && AES_set_encrypt_key(keybytes, 128, NULL) == -1
          && AES_set_decrypt_key(NULL, 128, &k) == -1 && AES_set_decrypt_key(keybytes, 128, NULL) == -1,
          "null keys are refused");

    /* In place, and the ECB function both ways (any other enc decrypts). */
    memcpy(out, data, 16);
    AES_encrypt(out, out, &enc_key);
    hex("in place", out, 16);
    AES_ecb_encrypt(out, back, &dec_key, AES_DECRYPT);
    check(memcmp(back, data, 16) == 0, "AES_ecb_encrypt decrypts");
    AES_ecb_encrypt(data, back, &enc_key, AES_ENCRYPT);
    check(memcmp(back, out, 16) == 0, "AES_ecb_encrypt encrypts");
    AES_ecb_encrypt(out, back, &dec_key, 7);
    check(memcmp(back, data, 16) == 0, "AES_ecb_encrypt with another enc decrypts");
}

static void aes_modes(void)
{
    static const size_t lens[] = { 0, 1, 15, 16, 20, 32, 47, 48 };
    unsigned char iv[64], out[80], back[80];
    size_t i;
    int num, r;

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        char label[32];

        memset(out, 0xee, sizeof(out));
        memcpy(iv, data + 100, 16);
        AES_cbc_encrypt(data, out, lens[i], &enc_key, iv, AES_ENCRYPT);
        snprintf(label, sizeof(label), "cbc %zu", lens[i]);
        hex(label, out, 64);
        hex("iv", iv, 16);
        memset(back, 0xee, sizeof(back));
        memcpy(iv, data + 100, 16);
        AES_cbc_encrypt(out, back, lens[i], &dec_key, iv, AES_DECRYPT);
        hex("back", back, 64);
        hex("iv", iv, 16);
    }
    /* In place. */
    memcpy(out, data, 48);
    memcpy(iv, data + 100, 16);
    AES_cbc_encrypt(out, out, 48, &enc_key, iv, AES_ENCRYPT);
    memcpy(iv, data + 100, 16);
    AES_cbc_encrypt(out, out, 48, &dec_key, iv, AES_DECRYPT);
    check(memcmp(out, data, 48) == 0, "CBC in place");

    /* The stream modes in pieces: 7, then 20, then 1, then 22. */
    {
        static const size_t pieces[] = { 7, 20, 1, 22 };
        size_t at;
        int mode;

        for (mode = 0; mode < 5; mode++) {
            static const char *const names[] = { "cfb128", "cfb128 dec", "ofb128", "cfb8", "cfb1" };

            memcpy(iv, data + 100, 16);
            num = 0;
            memset(out, 0xee, sizeof(out));
            at = 0;
            for (i = 0; i < 4; i++) {
                switch (mode) {
                case 0:
                    AES_cfb128_encrypt(data + at, out + at, pieces[i], &enc_key, iv, &num, AES_ENCRYPT);
                    break;
                case 1:
                    AES_cfb128_encrypt(data + at, out + at, pieces[i], &enc_key, iv, &num, AES_DECRYPT);
                    break;
                case 2:
                    AES_ofb128_encrypt(data + at, out + at, pieces[i], &enc_key, iv, &num);
                    break;
                case 3:
                    AES_cfb8_encrypt(data + at, out + at, pieces[i], &enc_key, iv, &num, AES_ENCRYPT);
                    break;
                default:
                    /* In bits: 7 octets of bits, then 20 bits. */
                    AES_cfb1_encrypt(data + at, out + at, pieces[i] * 8, &enc_key, iv, &num, AES_ENCRYPT);
                    break;
                }
                at += pieces[i];
                printf("  %s num %d\n", names[mode], num);
            }
            hex(names[mode], out, 52);
            hex("iv", iv, 16);
        }
        /* CFB-1 by a bit count that isn't whole octets keeps the other bits. */
        memcpy(iv, data + 100, 16);
        memset(out, 0xee, 4);
        AES_cfb1_encrypt(data, out, 13, &enc_key, iv, &num, AES_ENCRYPT);
        hex("cfb1 13 bits", out, 4);
        num = -3;
        memcpy(out, data, 4);
        AES_ofb128_encrypt(data, out, 4, &enc_key, iv, &num);
        check(num == -1 && memcmp(out, data, 4) == 0, "OFB with a negative position does nothing");
        num = -3;
        AES_cfb128_encrypt(data, out, 4, &enc_key, iv, &num, AES_ENCRYPT);
        check(num == -1, "CFB with a negative position does nothing");
    }

    /* IGE and bi-IGE. */
    memcpy(iv, data + 100, 32);
    memset(out, 0xee, sizeof(out));
    AES_ige_encrypt(data, out, 48, &enc_key, iv, AES_ENCRYPT);
    hex("ige", out, 48);
    hex("iv", iv, 32);
    memcpy(iv, data + 100, 32);
    AES_ige_encrypt(out, back, 48, &dec_key, iv, AES_DECRYPT);
    check(memcmp(back, data, 48) == 0, "IGE inverts");
    memcpy(back, data, 48);
    memcpy(iv, data + 100, 32);
    AES_ige_encrypt(back, back, 48, &enc_key, iv, AES_ENCRYPT);
    check(memcmp(back, out, 48) == 0, "IGE in place");
    AES_ige_encrypt(data, out, 0, &enc_key, iv, AES_ENCRYPT);
    AES_bi_ige_encrypt(data, out, 48, &enc_key, &dec_key, data + 100, AES_ENCRYPT);
    hex("bi-ige", out, 48);
    AES_bi_ige_encrypt(out, back, 48, &dec_key, &enc_key, data + 100, AES_DECRYPT);
    check(memcmp(back, data, 48) == 0, "bi-IGE inverts");

    /* RFC 3394 through the AES functions. */
    memset(out, 0xee, sizeof(out));
    r = AES_wrap_key(&enc_key, NULL, out, data, 24);
    printf("  wrap %d\n", r);
    hex("wrapped", out, 40);
    memset(back, 0xee, sizeof(back));
    r = AES_unwrap_key(&dec_key, NULL, back, out, 32);
    printf("  unwrap %d\n", r);
    check(r == 24 && memcmp(back, data, 24) == 0, "AES_unwrap_key");
    r = AES_wrap_key(&enc_key, data + 50, out, data, 16);
    printf("  wrap with an IV %d\n", r);
    hex("wrapped", out, 24);
    r = AES_unwrap_key(&dec_key, NULL, back, out, 24);
    printf("  unwrap with the default IV %d\n", r);
    hex("zeroed", back, 16);
    printf("  bad lengths %d %d %d %d\n", AES_wrap_key(&enc_key, NULL, out, data, 8),
           AES_wrap_key(&enc_key, NULL, out, data, 20), AES_unwrap_key(&dec_key, NULL, back, out, 16),
           AES_unwrap_key(&dec_key, NULL, back, out, 25));
}

static void helpers(void)
{
    unsigned char iv[16], ecount[16], out[96], back[96];
    unsigned int unum;
    size_t i, r;
    int num;

    logging = 1;
    printf("  CRYPTO_cbc128_encrypt 20\n");
    memcpy(iv, data + 100, 16);
    memset(out, 0xee, sizeof(out));
    CRYPTO_cbc128_encrypt(data, out, 20, &enc_key, iv, enc_block);
    hex("out", out, 32);
    printf("  CRYPTO_cbc128_decrypt 20\n");
    memcpy(iv, data + 100, 16);
    memset(back, 0xee, sizeof(back));
    CRYPTO_cbc128_decrypt(out, back, 20, &dec_key, iv, dec_block);
    hex("back", back, 32);
    hex("iv", iv, 16);

    printf("  CRYPTO_ctr128_encrypt 5, 30\n");
    memcpy(iv, data + 100, 16);
    iv[15] = 0xff;
    iv[14] = 0xff;
    memset(ecount, 0, 16);
    unum = 0;
    CRYPTO_ctr128_encrypt(data, out, 5, &enc_key, iv, ecount, &unum, enc_block);
    CRYPTO_ctr128_encrypt(data + 5, out + 5, 30, &enc_key, iv, ecount, &unum, enc_block);
    hex("out", out, 35);
    hex("iv", iv, 16);
    hex("ecount", ecount, 16);
    printf("  num %u\n", unum);

    printf("  CRYPTO_ctr128_encrypt_ctr32 5, 70, 3\n");
    memcpy(iv, data + 100, 16);
    iv[12] = iv[13] = iv[14] = 0xff;
    iv[15] = 0xfe;
    memset(ecount, 0, 16);
    unum = 0;
    CRYPTO_ctr128_encrypt_ctr32(data, back, 5, &enc_key, iv, ecount, &unum, ctr_fn);
    CRYPTO_ctr128_encrypt_ctr32(data + 5, back + 5, 70, &enc_key, iv, ecount, &unum, ctr_fn);
    CRYPTO_ctr128_encrypt_ctr32(data + 75, back + 75, 3, &enc_key, iv, ecount, &unum, ctr_fn);
    hex("out", back, 78);
    hex("iv", iv, 16);
    hex("ecount", ecount, 16);
    printf("  num %u\n", unum);

    printf("  CRYPTO_ofb128_encrypt 3, 17\n");
    memcpy(iv, data + 100, 16);
    num = 0;
    CRYPTO_ofb128_encrypt(data, out, 3, &enc_key, iv, &num, enc_block);
    CRYPTO_ofb128_encrypt(data + 3, out + 3, 17, &enc_key, iv, &num, enc_block);
    hex("out", out, 20);
    printf("  num %d\n", num);
    printf("  CRYPTO_cfb128_encrypt 3, 17 decrypting\n");
    memcpy(iv, data + 100, 16);
    num = 0;
    CRYPTO_cfb128_encrypt(data, out, 3, &enc_key, iv, &num, 0, enc_block);
    CRYPTO_cfb128_encrypt(data + 3, out + 3, 17, &enc_key, iv, &num, 0, enc_block);
    hex("out", out, 20);
    hex("iv", iv, 16);
    printf("  CRYPTO_cfb128_8_encrypt 3\n");
    memcpy(iv, data + 100, 16);
    CRYPTO_cfb128_8_encrypt(data, out, 3, &enc_key, iv, &num, 1, enc_block);
    hex("out", out, 3);
    printf("  CRYPTO_cfb128_1_encrypt 3 bits\n");
    memcpy(iv, data + 100, 16);
    out[0] = 0x55;
    CRYPTO_cfb128_1_encrypt(data, out, 3, &enc_key, iv, &num, 1, enc_block);
    hex("out", out, 1);
    logging = 0;

    /* Ciphertext stealing: each length, each form, logged for two of them. */
    for (i = 0; i <= 50; i++) {
        unsigned char a[64], b[64], c[64], d[64], ia[16], ib[16];
        size_t ra, rb, rc, rd;
        char label[48];

        logging = i == 20 || i == 32;
        if (logging)
            printf("  cts %zu\n", i);
        memset(a, 0xee, sizeof(a));
        memset(b, 0xee, sizeof(b));
        memcpy(ia, data + 100, 16);
        memcpy(ib, data + 100, 16);
        ra = CRYPTO_cts128_encrypt_block(data, a, i, &enc_key, ia, enc_block);
        rb = CRYPTO_cts128_encrypt(data, b, i, &enc_key, ib, cbc_fn);
        memset(c, 0xee, sizeof(c));
        memset(d, 0xee, sizeof(d));
        memcpy(ia, data + 100, 16);
        memcpy(ib, data + 100, 16);
        rc = CRYPTO_cts128_decrypt_block(a, c, i, &dec_key, ia, dec_block);
        rd = CRYPTO_cts128_decrypt(b, d, i, &dec_key, ib, cbc_fn);
        snprintf(label, sizeof(label), "cts %zu: %zu %zu %zu %zu", i, ra, rb, rc, rd);
        hex(label, a, i + 2);
        hex("iv", ib, 16);
        check(memcmp(a, b, sizeof(a)) == 0 && memcmp(c, d, sizeof(c)) == 0
              && (rc == 0 || memcmp(c, data, i) == 0), label);
        if (logging)
            printf("  nistcts %zu\n", i);
        memset(a, 0xee, sizeof(a));
        memset(b, 0xee, sizeof(b));
        memcpy(ia, data + 100, 16);
        memcpy(ib, data + 100, 16);
        ra = CRYPTO_nistcts128_encrypt_block(data, a, i, &enc_key, ia, enc_block);
        rb = CRYPTO_nistcts128_encrypt(data, b, i, &enc_key, ib, cbc_fn);
        memset(c, 0xee, sizeof(c));
        memset(d, 0xee, sizeof(d));
        memcpy(ia, data + 100, 16);
        memcpy(ib, data + 100, 16);
        rc = CRYPTO_nistcts128_decrypt_block(a, c, i, &dec_key, ia, dec_block);
        rd = CRYPTO_nistcts128_decrypt(b, d, i, &dec_key, ib, cbc_fn);
        snprintf(label, sizeof(label), "nistcts %zu: %zu %zu %zu %zu", i, ra, rb, rc, rd);
        hex(label, a, i + 2);
        hex("iv", ib, 16);
        check(memcmp(a, b, sizeof(a)) == 0 && memcmp(c, d, sizeof(c)) == 0
              && (rc == 0 || memcmp(c, data, i) == 0), label);
    }
    logging = 0;

    /* The key wraps, padded and not, with and without an IV, and tampered. */
    {
        static const size_t plens[] = { 0, 1, 7, 8, 9, 16, 20, 24 };
        static const unsigned char icv[4] = { 1, 2, 3, 4 };

        logging = 1;
        printf("  CRYPTO_128_wrap 16\n");
        r = CRYPTO_128_wrap(&enc_key, NULL, out, data, 16, enc_block);
        printf("  -> %zu\n", r);
        logging = 0;
        for (i = 0; i < sizeof(plens) / sizeof(plens[0]); i++) {
            char label[48];
            size_t w, u;

            memset(out, 0xee, sizeof(out));
            memset(back, 0xee, sizeof(back));
            w = CRYPTO_128_wrap_pad(&enc_key, i % 2 ? icv : NULL, out, data, plens[i], enc_block);
            u = w ? CRYPTO_128_unwrap_pad(&dec_key, i % 2 ? icv : NULL, back, out, w, dec_block) : 0;
            snprintf(label, sizeof(label), "wrap_pad %zu: %zu %zu", plens[i], w, u);
            hex(label, out, w + 2);
            check(u == plens[i] && memcmp(back, data, u) == 0, label);
            if (w != 0) {
                out[w - 1] ^= 1;
                memset(back, 0xee, sizeof(back));
                u = CRYPTO_128_unwrap_pad(&dec_key, i % 2 ? icv : NULL, back, out, w, dec_block);
                printf("  tampered %zu\n", u);
                hex("zeroed", back, w - 8);
            }
            w = CRYPTO_128_wrap(&enc_key, i % 2 ? data + 60 : NULL, out, data, plens[i], enc_block);
            u = w ? CRYPTO_128_unwrap(&dec_key, i % 2 ? data + 60 : NULL, back, out, w, dec_block) : 0;
            printf("  wrap %zu: %zu %zu\n", plens[i], w, u);
            if (w != 0) {
                u = CRYPTO_128_unwrap(&dec_key, i % 2 ? NULL : data + 60, back, out, w, dec_block);
                printf("  other IV %zu\n", u);
                hex("zeroed", back, w - 8);
            }
        }
        printf("  unwrap_pad bad lengths %zu %zu %zu\n",
               CRYPTO_128_unwrap_pad(&dec_key, NULL, back, out, 8, dec_block),
               CRYPTO_128_unwrap_pad(&dec_key, NULL, back, out, 20, dec_block),
               CRYPTO_128_unwrap(&dec_key, NULL, back, out, 7, dec_block));
    }
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    for (i = 0; i < sizeof(keybytes); i++)
        keybytes[i] = (unsigned char)(i * 13 + 1);
    AES_set_encrypt_key(keybytes, 128, &enc_key);
    AES_set_decrypt_key(keybytes, 128, &dec_key);
    keys();
    aes_modes();
    helpers();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
