/*
 * Conformance test for the deprecated IDEA, SEED, and Camellia functions (IDEA_encrypt(3),
 * SEED_encrypt(3), Camellia_set_key(3), ...), in TAP format:
 *   - the key structs each key setter leaves: IDEA's encryption and decryption schedules
 *     (and a decryption schedule made from words a key setter never leaves, through IDEA's
 *     inverse), SEED's round keys, and Camellia's words and grand rounds for each size (its
 *     words are the platform's: OpenSSL's x86_64 assembly swaps each pair), with the sizes
 *     and pointers Camellia_set_key refuses, and a key with fewer grand rounds;
 *   - IDEA_encrypt on words (their high bits ignored) and with schedule words past 16 bits;
 *   - the published vectors (RFC 4269 for SEED, RFC 3713 for Camellia);
 *   - ECB, CBC (partial last blocks written whole and read whole), and in pieces with the
 *     position carried: IDEA's CFB-64 and OFB-64 (a negative position refused), SEED's and
 *     Camellia's CFB-128 and OFB-128, and Camellia's CFB-1, CFB-8, and CTR; and in place.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/camellia.h>
#include <openssl/idea.h>
#include <openssl/seed.h>

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

static int unhex(const char *s, unsigned char *out)
{
    int n = 0;
    unsigned int v;

    while (s[0] != '\0' && sscanf(s, "%2x", &v) == 1) {
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return n;
}

static unsigned char data[400];
static IDEA_KEY_SCHEDULE idea_ek, idea_dk;
static SEED_KEY_SCHEDULE seed;
static CAMELLIA_KEY cmll;

static void idea(void)
{
    static const long lens[] = { 0, 1, 8, 9, 23 };
    static const long pieces[] = { 3, 9, 1, 20, 0, 7 };
    static const IDEA_INT odd[] = { 0, 1, 2, 0xffff, 0x10000, 0x10001, 0x10002, 0x20002,
        0x7fffffff, 0xffffffff };
    unsigned long w[2] = { 0x01234567UL, 0x89abcdefUL };
    unsigned char out[48], back[48], iv[8];
    IDEA_KEY_SCHEDULE k;
    size_t i, p;
    long at;
    int num;

    printf("  options %s\n", IDEA_options());
    memset(&idea_ek, 0xa5, sizeof(idea_ek));
    IDEA_set_encrypt_key(data, &idea_ek);
    hex("idea ek", &idea_ek, sizeof(idea_ek));
    memset(&idea_dk, 0xa5, sizeof(idea_dk));
    IDEA_set_decrypt_key(&idea_ek, &idea_dk);
    hex("idea dk", &idea_dk, sizeof(idea_dk));

    /* A decryption schedule from words no key setter leaves: each through the inverse. */
    for (i = 0; i < 54; i++)
        (&k.data[0][0])[i] = odd[i % (sizeof(odd) / sizeof(odd[0]))];
    {
        IDEA_KEY_SCHEDULE d;

        /* its last two words are left as they are */
        memset(&d, 0xa5, sizeof(d));
        IDEA_set_decrypt_key(&k, &d);
        hex("idea dk of odd words", &d, sizeof(d));
        /* and encryption with them */
        IDEA_encrypt(w, &k);
        printf("  IDEA_encrypt odd %08lx %08lx\n", w[0], w[1]);
        w[0] = 0x01234567UL;
        w[1] = 0x89abcdefUL;
    }

    if (sizeof(long) > 4) {
        /* the high bits are ignored */
        w[0] |= (unsigned long)0xabcd << 16 << 16;
        w[1] |= (unsigned long)0x1234 << 16 << 16;
    }
    IDEA_encrypt(w, &idea_ek);
    printf("  IDEA_encrypt %08lx %08lx\n", w[0], w[1]);
    IDEA_encrypt(w, &idea_dk);
    check(w[0] == 0x01234567UL && w[1] == 0x89abcdefUL, "IDEA_encrypt with the decryption key");

    IDEA_ecb_encrypt(data, out, &idea_ek);
    hex("idea ecb", out, 8);
    IDEA_ecb_encrypt(out, back, &idea_dk);
    check(memcmp(back, data, 8) == 0, "idea ecb");

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        char label[48];

        memset(out, 0xee, sizeof(out));
        memset(back, 0xee, sizeof(back));
        memcpy(iv, data + 100, 8);
        IDEA_cbc_encrypt(data, out, lens[i], &idea_ek, iv, IDEA_ENCRYPT);
        snprintf(label, sizeof(label), "idea cbc %ld", lens[i]);
        hex(label, out, 32);
        hex("iv", iv, 8);
        memcpy(iv, data + 100, 8);
        IDEA_cbc_encrypt(out, back, lens[i], &idea_dk, iv, IDEA_DECRYPT);
        hex("back", back, 32);
        hex("iv", iv, 8);
        check(memcmp(back, data, (size_t)lens[i]) == 0, label);
    }

    memset(out, 0xee, sizeof(out));
    memcpy(iv, data + 100, 8);
    num = 8;
    for (at = 0, p = 0; p < sizeof(pieces) / sizeof(pieces[0]); p++) {
        IDEA_cfb64_encrypt(data + at, out + at, pieces[p], &idea_ek, iv, &num, IDEA_ENCRYPT);
        at += pieces[p];
        printf("  idea cfb num %d\n", num);
    }
    hex("idea cfb64", out, 40);
    hex("iv", iv, 8);
    memcpy(iv, data + 100, 8);
    num = 0;
    IDEA_cfb64_encrypt(out, back, 40, &idea_ek, iv, &num, IDEA_DECRYPT);
    check(memcmp(back, data, 40) == 0, "idea cfb64");

    memset(out, 0xee, sizeof(out));
    memcpy(iv, data + 100, 8);
    num = 13;
    for (at = 0, p = 0; p < sizeof(pieces) / sizeof(pieces[0]); p++) {
        IDEA_ofb64_encrypt(data + at, out + at, pieces[p], &idea_ek, iv, &num);
        at += pieces[p];
        printf("  idea ofb num %d\n", num);
    }
    hex("idea ofb64", out, 40);
    hex("iv", iv, 8);

    /* A negative position is refused, and becomes -1. */
    memset(out, 0xee, sizeof(out));
    memcpy(iv, data + 100, 8);
    num = -5;
    IDEA_cfb64_encrypt(data, out, 10, &idea_ek, iv, &num, IDEA_ENCRYPT);
    check(num == -1 && out[0] == 0xee && memcmp(iv, data + 100, 8) == 0, "idea cfb64 refuses a negative num");
    num = -100;
    IDEA_ofb64_encrypt(data, out, 10, &idea_ek, iv, &num);
    check(num == -1 && out[0] == 0xee && memcmp(iv, data + 100, 8) == 0, "idea ofb64 refuses a negative num");

    memcpy(out, data, 24);
    memcpy(iv, data + 100, 8);
    IDEA_cbc_encrypt(out, out, 24, &idea_ek, iv, IDEA_ENCRYPT);
    memcpy(iv, data + 100, 8);
    IDEA_cbc_encrypt(out, out, 24, &idea_dk, iv, IDEA_DECRYPT);
    check(memcmp(out, data, 24) == 0, "idea cbc in place");
}

/* The 128-bit modes, through one cipher's functions. */
struct cipher128 {
    const char *name;
    void (*ecb)(const unsigned char *in, unsigned char *out, int enc);
    void (*cbc)(const unsigned char *in, unsigned char *out, size_t len, unsigned char *iv, int enc);
    void (*cfb)(const unsigned char *in, unsigned char *out, size_t len, unsigned char *iv, int *num, int enc);
    void (*ofb)(const unsigned char *in, unsigned char *out, size_t len, unsigned char *iv, int *num);
};

static void seed_ecb(const unsigned char *in, unsigned char *out, int enc) { SEED_ecb_encrypt(in, out, &seed, enc); }
static void seed_cbc(const unsigned char *in, unsigned char *out, size_t len, unsigned char *iv, int enc) { SEED_cbc_encrypt(in, out, len, &seed, iv, enc); }
static void seed_cfb(const unsigned char *in, unsigned char *out, size_t len, unsigned char *iv, int *num, int enc) { SEED_cfb128_encrypt(in, out, len, &seed, iv, num, enc); }
static void seed_ofb(const unsigned char *in, unsigned char *out, size_t len, unsigned char *iv, int *num) { SEED_ofb128_encrypt(in, out, len, &seed, iv, num); }
static void cmll_ecb(const unsigned char *in, unsigned char *out, int enc) { Camellia_ecb_encrypt(in, out, &cmll, enc); }
static void cmll_cbc(const unsigned char *in, unsigned char *out, size_t len, unsigned char *iv, int enc) { Camellia_cbc_encrypt(in, out, len, &cmll, iv, enc); }
static void cmll_cfb(const unsigned char *in, unsigned char *out, size_t len, unsigned char *iv, int *num, int enc) { Camellia_cfb128_encrypt(in, out, len, &cmll, iv, num, enc); }
static void cmll_ofb(const unsigned char *in, unsigned char *out, size_t len, unsigned char *iv, int *num) { Camellia_ofb128_encrypt(in, out, len, &cmll, iv, num); }

static void modes128(const struct cipher128 *k)
{
    static const size_t lens[] = { 0, 1, 16, 17, 40 };
    static const size_t pieces[] = { 3, 17, 1, 30, 0, 9 };
    unsigned char out[96], back[96], iv[16];
    char label[48];
    size_t i, p, at;
    int num;

    k->ecb(data, out, 1);
    snprintf(label, sizeof(label), "%s ecb", k->name);
    hex(label, out, 16);
    k->ecb(out, back, 0);
    check(memcmp(back, data, 16) == 0, label);
    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        memset(out, 0xee, sizeof(out));
        memset(back, 0xee, sizeof(back));
        memcpy(iv, data + 100, 16);
        k->cbc(data, out, lens[i], iv, 1);
        snprintf(label, sizeof(label), "%s cbc %zu", k->name, lens[i]);
        hex(label, out, 64);
        hex("iv", iv, 16);
        memcpy(iv, data + 100, 16);
        k->cbc(out, back, lens[i], iv, 0);
        hex("back", back, 64);
        hex("iv", iv, 16);
        check(memcmp(back, data, lens[i]) == 0, label);
    }

    memset(out, 0xee, sizeof(out));
    memcpy(iv, data + 100, 16);
    num = 5;
    for (at = 0, p = 0; p < sizeof(pieces) / sizeof(pieces[0]); p++) {
        k->cfb(data + at, out + at, pieces[p], iv, &num, 1);
        at += pieces[p];
        printf("  %s cfb num %d\n", k->name, num);
    }
    snprintf(label, sizeof(label), "%s cfb128", k->name);
    hex(label, out, 60);
    hex("iv", iv, 16);
    memcpy(iv, data + 100, 16);
    num = 5;
    k->cfb(out, back, 60, iv, &num, 0);
    check(memcmp(back, data, 60) == 0, label);

    memset(out, 0xee, sizeof(out));
    memcpy(iv, data + 100, 16);
    num = 0;
    for (at = 0, p = 0; p < sizeof(pieces) / sizeof(pieces[0]); p++) {
        k->ofb(data + at, out + at, pieces[p], iv, &num);
        at += pieces[p];
        printf("  %s ofb num %d\n", k->name, num);
    }
    snprintf(label, sizeof(label), "%s ofb128", k->name);
    hex(label, out, 60);
    hex("iv", iv, 16);

    /* A negative position is refused, and becomes -1. */
    memset(out, 0xee, sizeof(out));
    memcpy(iv, data + 100, 16);
    num = -3;
    k->cfb(data, out, 10, iv, &num, 1);
    snprintf(label, sizeof(label), "%s cfb128 refuses a negative num", k->name);
    check(num == -1 && out[0] == 0xee, label);
    num = -3;
    k->ofb(data, out, 10, iv, &num);
    snprintf(label, sizeof(label), "%s ofb128 refuses a negative num", k->name);
    check(num == -1 && out[0] == 0xee, label);

    memcpy(out, data, 40);
    memcpy(iv, data + 100, 16);
    k->cbc(out, out, 40, iv, 1);
    memcpy(iv, data + 100, 16);
    k->cbc(out, out, 40, iv, 0);
    snprintf(label, sizeof(label), "%s cbc in place", k->name);
    check(memcmp(out, data, 40) == 0, label);
}

static void seed_tests(void)
{
    static const struct cipher128 c = { "seed", seed_ecb, seed_cbc, seed_cfb, seed_ofb };
    /* RFC 4269, appendix B */
    static const char *const vectors[][3] = {
        { "00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "5ebac6e0054e166819aff1cc6d346cdb" },
        { "000102030405060708090a0b0c0d0e0f", "00000000000000000000000000000000", "c11f22f20140505084483597e4370f43" },
        { "4706480851e61be85d74bfb3fd956185", "83a2f8a288641fb9a4e9a5cc2f131c7d", "ee54d13ebcae706d226bc3142cd40d4a" },
        { "28dbc3bc49ffd87dcfa509b11d422be7", "b41e6be2eba84a148e2eed84593c5ec7", "9b9b7bfcd1813cb95d0b3618f40f5122" },
    };
    unsigned char key[16], pt[16], ct[16], out[16];
    size_t i;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        char label[32];

        unhex(vectors[i][0], key);
        unhex(vectors[i][1], pt);
        unhex(vectors[i][2], ct);
        SEED_set_key(key, &seed);
        SEED_encrypt(pt, out, &seed);
        snprintf(label, sizeof(label), "SEED vector %zu", i + 1);
        check(memcmp(out, ct, 16) == 0, label);
        SEED_decrypt(ct, out, &seed);
        check(memcmp(out, pt, 16) == 0, label);
    }
    memset(&seed, 0xa5, sizeof(seed));
    SEED_set_key(data, &seed);
    hex("seed ks", &seed, sizeof(seed));
    /* in place */
    memcpy(out, data, 16);
    SEED_encrypt(out, out, &seed);
    SEED_decrypt(out, out, &seed);
    check(memcmp(out, data, 16) == 0, "SEED in place");
    modes128(&c);
}

static void camellia_tests(void)
{
    static const struct cipher128 c = { "camellia", cmll_ecb, cmll_cbc, cmll_cfb, cmll_ofb };
    /* RFC 3713, appendix A */
    static const char *const vectors[][2] = {
        { "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43" },
        { "0123456789abcdeffedcba98765432100011223344556677", "b4993401b3e996f84ee5cee7d79b09b9" },
        { "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff", "9acc237dff16d76c20ef7c919e3a7509" },
    };
    static const int bits[] = { 128, 192, 256, 0, 64, 129, 255, 512, -128 };
    unsigned char key[32], pt[16], ct[16], out[96], back[96], iv[16], ecount[16];
    unsigned int unum;
    size_t i;
    int num;

    unhex("0123456789abcdeffedcba9876543210", pt);
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        char label[32];
        int n = unhex(vectors[i][0], key);

        unhex(vectors[i][1], ct);
        check(Camellia_set_key(key, n * 8, &cmll) == 0, "Camellia_set_key");
        Camellia_encrypt(pt, out, &cmll);
        snprintf(label, sizeof(label), "Camellia vector %zu", i + 1);
        check(memcmp(out, ct, 16) == 0, label);
        Camellia_decrypt(ct, out, &cmll);
        check(memcmp(out, pt, 16) == 0, label);
    }
    for (i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
        char label[32];
        int r;

        memset(&cmll, 0xa5, sizeof(cmll));
        r = Camellia_set_key(data, bits[i], &cmll);
        snprintf(label, sizeof(label), "camellia %d", bits[i]);
        printf("  %s -> %d grand rounds %d\n", label, r, cmll.grand_rounds);
        hex("words", &cmll.u.rd_key, sizeof(cmll.u.rd_key));
    }
    /* Fewer grand rounds than a key setter leaves run fewer rounds over the same table. */
    for (i = 1; i <= 2; i++) {
        Camellia_set_key(data, 256, &cmll);
        cmll.grand_rounds = (int)i;
        Camellia_encrypt(data, out, &cmll);
        hex(i == 1 ? "one grand round" : "two grand rounds", out, 16);
        Camellia_decrypt(out, back, &cmll);
        check(memcmp(back, data, 16) == 0, "Camellia with fewer grand rounds");
    }
    check(Camellia_set_key(NULL, 128, &cmll) == -1, "Camellia_set_key with no key");
    check(Camellia_set_key(data, 128, NULL) == -1, "Camellia_set_key with nowhere to put it");
    check(Camellia_set_key(data, 100, NULL) == -1, "Camellia_set_key checks the pointers first");

    Camellia_set_key(data, 192, &cmll);
    modes128(&c);

    /* CFB-1 and CFB-8; num isn't used. */
    memset(out, 0xee, sizeof(out));
    memcpy(iv, data + 100, 16);
    num = 77;
    Camellia_cfb1_encrypt(data, out, 13, &cmll, iv, &num, CAMELLIA_ENCRYPT);
    Camellia_cfb1_encrypt(data + 2, out + 2, 30, &cmll, iv, &num, CAMELLIA_ENCRYPT);
    printf("  cfb1 num %d\n", num);
    hex("camellia cfb1", out, 8);
    hex("iv", iv, 16);
    memset(out, 0xee, sizeof(out));
    memcpy(iv, data + 100, 16);
    Camellia_cfb8_encrypt(data, out, 21, &cmll, iv, &num, CAMELLIA_ENCRYPT);
    hex("camellia cfb8", out, 24);
    hex("iv", iv, 16);
    memcpy(iv, data + 100, 16);
    Camellia_cfb8_encrypt(out, back, 21, &cmll, iv, &num, CAMELLIA_DECRYPT);
    check(memcmp(back, data, 21) == 0, "camellia cfb8");

    /* CTR in pieces, the counter carried past an octet's end. */
    memset(out, 0xee, sizeof(out));
    memcpy(iv, data + 100, 16);
    memset(iv + 12, 0xff, 4);
    iv[11] = 0xff;
    memset(ecount, 0, sizeof(ecount));
    unum = 0;
    Camellia_ctr128_encrypt(data, out, 5, &cmll, iv, ecount, &unum);
    printf("  ctr num %u\n", unum);
    Camellia_ctr128_encrypt(data + 5, out + 5, 40, &cmll, iv, ecount, &unum);
    printf("  ctr num %u\n", unum);
    Camellia_ctr128_encrypt(data + 45, out + 45, 0, &cmll, iv, ecount, &unum);
    Camellia_ctr128_encrypt(data + 45, out + 45, 19, &cmll, iv, ecount, &unum);
    printf("  ctr num %u\n", unum);
    hex("camellia ctr", out, 64);
    hex("iv", iv, 16);
    hex("ecount", ecount, 16);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    idea();
    seed_tests();
    camellia_tests();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
