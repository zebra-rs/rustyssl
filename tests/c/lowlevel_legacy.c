/*
 * Conformance test for the deprecated Blowfish, CAST, RC2, and RC4 functions (BF_set_key(3),
 * RC4_set_key(3), ...), in TAP format:
 *   - the key structs each key setter leaves (Blowfish's P-array and S-box ends, CAST's round
 *     keys and short-key flag, RC2's words for each effective bit count, RC4's permutation),
 *     with keys of every length OpenSSL caps or treats specially;
 *   - the block functions on words (RC2's taking unsigned longs with high bits set);
 *   - ECB, CBC (partial last blocks written whole and read whole), CFB-64 and OFB-64 in pieces
 *     with the position carried (its high bits ignored), and in place;
 *   - RC4 in pieces and in place, and the options strings (RC4's is the platform's).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <openssl/rc2.h>
#include <openssl/rc4.h>

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

static unsigned char data[400];
static BF_KEY bf;
static CAST_KEY cast;
static RC2_KEY rc2;

/* The 64-bit block modes, through one cipher's functions. */
struct cipher {
    const char *name;
    void (*ecb)(const unsigned char *in, unsigned char *out, int enc);
    void (*cbc)(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int enc);
    void (*cfb)(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int *num, int enc);
    void (*ofb)(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int *num);
};

static void bf_ecb(const unsigned char *in, unsigned char *out, int enc) { BF_ecb_encrypt(in, out, &bf, enc); }
static void bf_cbc(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int enc) { BF_cbc_encrypt(in, out, len, &bf, iv, enc); }
static void bf_cfb(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int *num, int enc) { BF_cfb64_encrypt(in, out, len, &bf, iv, num, enc); }
static void bf_ofb(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int *num) { BF_ofb64_encrypt(in, out, len, &bf, iv, num); }
static void cast_ecb(const unsigned char *in, unsigned char *out, int enc) { CAST_ecb_encrypt(in, out, &cast, enc); }
static void cast_cbc(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int enc) { CAST_cbc_encrypt(in, out, len, &cast, iv, enc); }
static void cast_cfb(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int *num, int enc) { CAST_cfb64_encrypt(in, out, len, &cast, iv, num, enc); }
static void cast_ofb(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int *num) { CAST_ofb64_encrypt(in, out, len, &cast, iv, num); }
static void rc2_ecb(const unsigned char *in, unsigned char *out, int enc) { RC2_ecb_encrypt(in, out, &rc2, enc); }
static void rc2_cbc(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int enc) { RC2_cbc_encrypt(in, out, len, &rc2, iv, enc); }
static void rc2_cfb(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int *num, int enc) { RC2_cfb64_encrypt(in, out, len, &rc2, iv, num, enc); }
static void rc2_ofb(const unsigned char *in, unsigned char *out, long len, unsigned char *iv, int *num) { RC2_ofb64_encrypt(in, out, len, &rc2, iv, num); }

static const struct cipher ciphers[] = {
    { "bf", bf_ecb, bf_cbc, bf_cfb, bf_ofb },
    { "cast", cast_ecb, cast_cbc, cast_cfb, cast_ofb },
    { "rc2", rc2_ecb, rc2_cbc, rc2_cfb, rc2_ofb },
};

static void keys(void)
{
    static const int bflens[] = { 0, -1, 1, 7, 72, 80 };
    static const int castlens[] = { 0, 5, 10, 11, 16, 20 };
    static const int rc2lens[] = { 1, 8, 128, 200 };
    static const int rc2bits[] = { 0, 1, 63, 64, 128, 1024, 2000, -5 };
    size_t i, j;

    printf("  options %s %s\n", BF_options(), RC4_options());
    for (i = 0; i < sizeof(bflens) / sizeof(bflens[0]); i++) {
        char label[32];

        BF_set_key(&bf, bflens[i], data);
        snprintf(label, sizeof(label), "bf %d P", bflens[i]);
        hex(label, bf.P, sizeof(bf.P));
        hex("S ends", bf.S, 32);
        hex("", bf.S + 1024 - 8, 32);
    }
    for (i = 0; i < sizeof(castlens) / sizeof(castlens[0]); i++) {
        char label[32];

        memset(&cast, 0xa5, sizeof(cast));
        CAST_set_key(&cast, castlens[i], data);
        snprintf(label, sizeof(label), "cast %d", castlens[i]);
        hex(label, &cast, sizeof(cast));
    }
    for (i = 0; i < sizeof(rc2lens) / sizeof(rc2lens[0]); i++) {
        for (j = 0; j < sizeof(rc2bits) / sizeof(rc2bits[0]); j++) {
            char label[32];

            memset(&rc2, 0xa5, sizeof(rc2));
            RC2_set_key(&rc2, rc2lens[i], data, rc2bits[j]);
            snprintf(label, sizeof(label), "rc2 %d %d", rc2lens[i], rc2bits[j]);
            hex(label, &rc2, sizeof(rc2));
        }
    }
    BF_set_key(&bf, 16, data);
    CAST_set_key(&cast, 16, data);
    RC2_set_key(&rc2, 16, data, 128);
}

static void words(void)
{
    BF_LONG b[2] = { 0x01234567, 0x89abcdef };
    CAST_LONG c[2] = { 0x01234567, 0x89abcdef };
    unsigned long r[2] = { 0x01234567UL, 0x89abcdefUL };

    BF_encrypt(b, &bf);
    printf("  BF_encrypt %08x %08x\n", (unsigned)b[0], (unsigned)b[1]);
    BF_decrypt(b, &bf);
    check(b[0] == 0x01234567 && b[1] == 0x89abcdef, "BF_decrypt");
    CAST_encrypt(c, &cast);
    printf("  CAST_encrypt %08x %08x\n", (unsigned)c[0], (unsigned)c[1]);
    CAST_decrypt(c, &cast);
    check(c[0] == 0x01234567 && c[1] == 0x89abcdef, "CAST_decrypt");
    if (sizeof(long) > 4) {
        /* the high bits are ignored */
        r[0] |= (unsigned long)0xabcd << 16 << 16;
        r[1] |= (unsigned long)0x1234 << 16 << 16;
    }
    RC2_encrypt(r, &rc2);
    printf("  RC2_encrypt %08lx %08lx\n", r[0], r[1]);
    RC2_decrypt(r, &rc2);
    printf("  RC2_decrypt %08lx %08lx\n", r[0], r[1]);
}

static void modes(void)
{
    static const long lens[] = { 0, 1, 8, 9, 23 };
    unsigned char out[48], back[48], iv[8];
    size_t c, i;
    int num;

    for (c = 0; c < 3; c++) {
        const struct cipher *k = &ciphers[c];
        char label[48];

        k->ecb(data, out, 1);
        snprintf(label, sizeof(label), "%s ecb", k->name);
        hex(label, out, 8);
        k->ecb(out, back, 0);
        check(memcmp(back, data, 8) == 0, label);
        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            memset(out, 0xee, sizeof(out));
            memset(back, 0xee, sizeof(back));
            memcpy(iv, data + 100, 8);
            k->cbc(data, out, lens[i], iv, 1);
            snprintf(label, sizeof(label), "%s cbc %ld", k->name, lens[i]);
            hex(label, out, 32);
            hex("iv", iv, 8);
            memcpy(iv, data + 100, 8);
            k->cbc(out, back, lens[i], iv, 0);
            hex("back", back, 32);
            hex("iv", iv, 8);
            check(memcmp(back, data, (size_t)lens[i]) == 0, label);
        }
        {
            static const long pieces[] = { 3, 9, 1, 20, 0, 7 };
            long at = 0;
            size_t p;

            memset(out, 0xee, sizeof(out));
            memcpy(iv, data + 100, 8);
            num = 8;
            for (p = 0; p < sizeof(pieces) / sizeof(pieces[0]); p++) {
                k->cfb(data + at, out + at, pieces[p], iv, &num, 1);
                at += pieces[p];
                printf("  %s cfb num %d\n", k->name, num);
            }
            snprintf(label, sizeof(label), "%s cfb64", k->name);
            hex(label, out, 40);
            hex("iv", iv, 8);
            memcpy(iv, data + 100, 8);
            num = 0;
            k->cfb(out, back, 40, iv, &num, 0);
            check(memcmp(back, data, 40) == 0, label);
            at = 0;
            memset(out, 0xee, sizeof(out));
            memcpy(iv, data + 100, 8);
            num = -7;
            for (p = 0; p < sizeof(pieces) / sizeof(pieces[0]); p++) {
                k->ofb(data + at, out + at, pieces[p], iv, &num);
                at += pieces[p];
                printf("  %s ofb num %d\n", k->name, num);
            }
            snprintf(label, sizeof(label), "%s ofb64", k->name);
            hex(label, out, 40);
            hex("iv", iv, 8);
        }
        /* In place. */
        memcpy(out, data, 24);
        memcpy(iv, data + 100, 8);
        k->cbc(out, out, 24, iv, 1);
        memcpy(iv, data + 100, 8);
        k->cbc(out, out, 24, iv, 0);
        snprintf(label, sizeof(label), "%s cbc in place", k->name);
        check(memcmp(out, data, 24) == 0, label);
    }
}

static void rc4(void)
{
    static const int lens[] = { 1, 5, 16, 256, 300 };
    RC4_KEY k;
    unsigned char out[64], again[64];
    size_t i;

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        char label[32];

        memset(&k, 0xa5, sizeof(k));
        RC4_set_key(&k, lens[i], data);
        snprintf(label, sizeof(label), "rc4 %d", lens[i]);
        printf("  %s x %u y %u\n", label, (unsigned)k.x, (unsigned)k.y);
        hex("data", k.data, 32);
        RC4(&k, 37, data, out);
        hex("stream", out, 37);
        printf("  x %u y %u\n", (unsigned)k.x, (unsigned)k.y);
    }
    RC4_set_key(&k, 16, data);
    RC4(&k, 5, data, out);
    RC4(&k, 0, data, out + 5);
    RC4(&k, 30, data + 5, out + 5);
    RC4_set_key(&k, 16, data);
    memcpy(again, data, 35);
    RC4(&k, 35, again, again);
    check(memcmp(out, again, 35) == 0, "RC4 in pieces and in place");
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    keys();
    words();
    modes();
    rc4();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
