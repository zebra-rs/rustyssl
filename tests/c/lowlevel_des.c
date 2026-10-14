/*
 * Conformance test for the deprecated DES functions (DES_set_key(3), DES_ecb_encrypt(3), ...),
 * in TAP format:
 *   - the key functions: parity for every octet, the parity check, the weak keys, the three
 *     ways to set a key (with what each leaves in a schedule full of junk), DES_random_key;
 *   - the block functions with the permutations and without, single and triple;
 *   - CBC (which leaves the IV), NCBC, XCBC, PCBC, and triple-DES CBC over lengths around the
 *     block, partial last blocks included, and in place;
 *   - CFB and OFB by bit widths from 1 to 64 (and widths they ignore), and their 64-bit forms
 *     in pieces with the position carried (its high bits ignored);
 *   - the CBC and quadratic checksums (with and without somewhere to write), the string to
 *     key functions, and crypt(3) with good and bad salts.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/des.h>

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
static DES_cblock k1 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
static DES_cblock k2 = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
static DES_cblock k3 = { 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67 };
static DES_key_schedule s1, s2, s3;

static void keys(void)
{
    DES_cblock k;
    DES_key_schedule s;
    unsigned char par[256];
    int i, r, weak = 0, odd = 0;

    printf("  options %s\n", DES_options());
    for (i = 0; i < 256; i++) {
        memset(k, i, 8);
        DES_set_odd_parity(&k);
        par[i] = k[0];
        odd += DES_check_key_parity((const_DES_cblock *)&k);
    }
    hex("odd parity", par, 256);
    printf("  %d keys with odd parity\n", odd);
    for (i = 0; i < 256; i++) {
        memset(k, i, 8);
        weak += DES_is_weak_key((const_DES_cblock *)&k);
    }
    printf("  %d uniform keys weak\n", weak);
    {
        static DES_cblock semi = { 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe };
        DES_cblock near = { 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xff };

        check(DES_is_weak_key(&semi) == 1 && DES_is_weak_key((const_DES_cblock *)&near) == 0,
              "semi-weak keys, parity bits compared");
    }

    /* The three ways to set a key, over a schedule full of junk. */
    {
        static DES_cblock tries[] = {
            { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
            { 0x00, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
            { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        };

        for (i = 0; i < 4; i++) {
            char label[48];

            memset(&s, 0xa5, sizeof(s));
            r = DES_set_key_checked(&tries[i], &s);
            snprintf(label, sizeof(label), "checked %d -> %d", i, r);
            hex(label, &s, sizeof(s));
            memset(&s, 0xa5, sizeof(s));
            r = DES_set_key(&tries[i], &s);
            snprintf(label, sizeof(label), "set_key %d -> %d", i, r);
            hex(label, &s, sizeof(s));
            memset(&s, 0xa5, sizeof(s));
            r = DES_key_sched(&tries[i], &s);
            printf("  key_sched %d -> %d\n", i, r);
            memset(&s, 0xa5, sizeof(s));
            DES_set_key_unchecked(&tries[i], &s);
            hex("unchecked", &s, sizeof(s));
        }
    }
    for (i = 0; i < 20; i++) {
        r = DES_random_key(&k);
        if (r != 1 || !DES_check_key_parity((const_DES_cblock *)&k) || DES_is_weak_key((const_DES_cblock *)&k))
            break;
    }
    check(i == 20, "DES_random_key gives keys with odd parity, not weak");
}

static void blocks(void)
{
    DES_LONG d[2];
    DES_cblock out, back;

    d[0] = 0x01234567;
    d[1] = 0x89abcdef;
    DES_encrypt1(d, &s1, DES_ENCRYPT);
    printf("  encrypt1 %08x %08x\n", (unsigned)d[0], (unsigned)d[1]);
    DES_encrypt1(d, &s1, DES_DECRYPT);
    printf("  decrypt1 %08x %08x\n", (unsigned)d[0], (unsigned)d[1]);
    DES_encrypt2(d, &s1, DES_ENCRYPT);
    printf("  encrypt2 %08x %08x\n", (unsigned)d[0], (unsigned)d[1]);
    DES_encrypt2(d, &s1, 5);
    printf("  encrypt2 with enc 5 %08x %08x\n", (unsigned)d[0], (unsigned)d[1]);
    DES_encrypt3(d, &s1, &s2, &s3);
    printf("  encrypt3 %08x %08x\n", (unsigned)d[0], (unsigned)d[1]);
    DES_decrypt3(d, &s1, &s2, &s3);
    printf("  decrypt3 %08x %08x\n", (unsigned)d[0], (unsigned)d[1]);
    DES_ecb_encrypt((const_DES_cblock *)data, &out, &s1, DES_ENCRYPT);
    hex("ecb", out, 8);
    DES_ecb_encrypt((const_DES_cblock *)&out, &back, &s1, DES_DECRYPT);
    check(memcmp(back, data, 8) == 0, "ecb inverts");
    DES_ecb3_encrypt((const_DES_cblock *)data, &out, &s1, &s2, &s3, DES_ENCRYPT);
    hex("ecb3", out, 8);
    DES_ecb3_encrypt((const_DES_cblock *)&out, &out, &s1, &s2, &s3, DES_DECRYPT);
    check(memcmp(out, data, 8) == 0, "ecb3 inverts in place");
}

static void cbcs(void)
{
    static const long lens[] = { 0, 1, 7, 8, 9, 16, 23 };
    unsigned char out[40], back[40];
    DES_cblock iv, inw = { 1, 2, 3, 4, 5, 6, 7, 8 }, outw = { 9, 10, 11, 12, 13, 14, 15, 16 };
    size_t i;
    int mode;

    for (mode = 0; mode < 5; mode++) {
        static const char *const names[] = { "cbc", "ncbc", "xcbc", "pcbc", "ede3_cbc" };

        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            char label[48];
            int enc;

            for (enc = 1; enc >= 0; enc--) {
                unsigned char *dst = enc ? out : back;
                const unsigned char *src = enc ? data : out;

                memset(dst, 0xee, 40);
                memcpy(iv, data + 100, 8);
                switch (mode) {
                case 0:
                    DES_cbc_encrypt(src, dst, lens[i], &s1, &iv, enc);
                    break;
                case 1:
                    DES_ncbc_encrypt(src, dst, lens[i], &s1, &iv, enc);
                    break;
                case 2:
                    DES_xcbc_encrypt(src, dst, lens[i], &s1, &iv, (const_DES_cblock *)&inw,
                                     (const_DES_cblock *)&outw, enc);
                    break;
                case 3:
                    DES_pcbc_encrypt(src, dst, lens[i], &s1, &iv, enc);
                    break;
                default:
                    DES_ede3_cbc_encrypt(src, dst, lens[i], &s1, &s2, &s3, &iv, enc);
                    break;
                }
                snprintf(label, sizeof(label), "%s %ld %s", names[mode], lens[i], enc ? "enc" : "dec");
                hex(label, dst, 32);
                hex("iv", iv, 8);
            }
            snprintf(label, sizeof(label), "%s %ld inverts", names[mode], lens[i]);
            check(memcmp(back, data, (size_t)lens[i]) == 0, label);
        }
    }
    /* In place. */
    memcpy(out, data, 24);
    memcpy(iv, data + 100, 8);
    DES_ede3_cbc_encrypt(out, out, 24, &s1, &s2, &s3, &iv, DES_ENCRYPT);
    memcpy(iv, data + 100, 8);
    DES_ede3_cbc_encrypt(out, out, 24, &s1, &s2, &s3, &iv, DES_DECRYPT);
    check(memcmp(out, data, 24) == 0, "triple-DES CBC in place");
}

static void feedback(void)
{
    static const int widths[] = { 1, 7, 8, 12, 32, 40, 63, 64, 0, -1, 65 };
    unsigned char out[80], back[80];
    DES_cblock iv;
    size_t i;
    int n;

    for (i = 0; i < sizeof(widths) / sizeof(widths[0]); i++) {
        char label[48];

        memset(out, 0xee, sizeof(out));
        memcpy(iv, data + 100, 8);
        DES_cfb_encrypt(data, out, widths[i], 30, &s1, &iv, DES_ENCRYPT);
        snprintf(label, sizeof(label), "cfb %d", widths[i]);
        hex(label, out, 32);
        hex("iv", iv, 8);
        memset(back, 0xee, sizeof(back));
        memcpy(iv, data + 100, 8);
        DES_cfb_encrypt(out, back, widths[i], 30, &s1, &iv, DES_DECRYPT);
        hex("back", back, 32);
        if (widths[i] > 0) {
            /* triple DES's CFB loops forever for a width of 0 or less in OpenSSL */
            memset(out, 0xee, sizeof(out));
            memcpy(iv, data + 100, 8);
            DES_ede3_cfb_encrypt(data, out, widths[i], 30, &s1, &s2, &s3, &iv, DES_ENCRYPT);
            snprintf(label, sizeof(label), "ede3_cfb %d", widths[i]);
            hex(label, out, 32);
            memcpy(iv, data + 100, 8);
            DES_ede3_cfb_encrypt(out, back, widths[i], 30, &s1, &s2, &s3, &iv, DES_DECRYPT);
            hex("back", back, 32);
        }
        if (widths[i] > 0) {
            /* OFB's length counts steps, and a width of 0 or less is undefined in OpenSSL */
            memset(out, 0xee, sizeof(out));
            memcpy(iv, data + 100, 8);
            DES_ofb_encrypt(data, out, widths[i], 5, &s1, &iv);
            snprintf(label, sizeof(label), "ofb %d", widths[i]);
            hex(label, out, 48);
            hex("iv", iv, 8);
        }
    }

    for (i = 0; i < 4; i++) {
        static const char *const names[] = { "cfb64", "ede3_cfb64", "ofb64", "ede3_ofb64" };
        static const long pieces[] = { 3, 9, 1, 20, 0, 7 };
        size_t p;
        long at = 0;

        memset(out, 0xee, sizeof(out));
        memcpy(iv, data + 100, 8);
        n = 8; /* only its low three bits count */
        for (p = 0; p < sizeof(pieces) / sizeof(pieces[0]); p++) {
            switch (i) {
            case 0:
                DES_cfb64_encrypt(data + at, out + at, pieces[p], &s1, &iv, &n, DES_ENCRYPT);
                break;
            case 1:
                DES_ede3_cfb64_encrypt(data + at, out + at, pieces[p], &s1, &s2, &s3, &iv, &n, DES_ENCRYPT);
                break;
            case 2:
                DES_ofb64_encrypt(data + at, out + at, pieces[p], &s1, &iv, &n);
                break;
            default:
                DES_ede3_ofb64_encrypt(data + at, out + at, pieces[p], &s1, &s2, &s3, &iv, &n);
                break;
            }
            at += pieces[p];
            printf("  %s num %d\n", names[i], n);
        }
        hex(names[i], out, 40);
        hex("iv", iv, 8);
        if (i < 2) {
            memcpy(iv, data + 100, 8);
            n = 0;
            if (i == 0)
                DES_cfb64_encrypt(out, back, 40, &s1, &iv, &n, DES_DECRYPT);
            else
                DES_ede3_cfb64_encrypt(out, back, 40, &s1, &s2, &s3, &iv, &n, DES_DECRYPT);
            check(memcmp(back, data, 40) == 0, names[i]);
        }
    }
}

static void sums(void)
{
    static const long lens[] = { 0, 1, 8, 9, 31 };
    DES_cblock out, quad[5], seed = { 1, 2, 3, 4, 5, 6, 7, 8 };
    size_t i;

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        DES_LONG r;
        int c;

        memset(out, 0xee, 8);
        r = DES_cbc_cksum(data, &out, lens[i], &s1, (const_DES_cblock *)(data + 100));
        printf("  cbc_cksum %ld %08x\n", lens[i], (unsigned)r);
        hex("out", out, 8);
        for (c = 0; c <= 5; c++) {
            memset(quad, 0xee, sizeof(quad));
            r = DES_quad_cksum(data, quad, lens[i], c, &seed);
            printf("  quad_cksum %ld %d %08x\n", lens[i], c, (unsigned)r);
            hex("out", quad, sizeof(quad));
        }
    }
    printf("  without output %08x %08x\n",
           (unsigned)DES_cbc_cksum(data, NULL, 20, &s1, (const_DES_cblock *)(data + 100)),
           (unsigned)DES_quad_cksum(data, NULL, 20, 3, &seed));
}

static void strings(void)
{
    static const char *const strs[] = { "", "a", "password", "0123456789abcdefg",
                                        "a much longer pass phrase, of forty octets" };
    DES_cblock a, b;
    size_t i;

    for (i = 0; i < sizeof(strs) / sizeof(strs[0]); i++) {
        char label[64];

        DES_string_to_key(strs[i], &a);
        snprintf(label, sizeof(label), "string_to_key \"%s\"", strs[i]);
        hex(label, a, 8);
        DES_string_to_2keys(strs[i], &a, &b);
        hex("2keys", a, 8);
        hex("     ", b, 8);
    }
}

static void crypts(void)
{
    static const char *const salts[] = { "ab", "./", "zz", "a", "", "\200a", "a\x7f", "A9x" };
    static const char *const pws[] = { "", "password", "longer than eight", "\xc3\xa9t\xc3\xa9" };
    char buf[20];
    size_t i, j;
    char *a, *b;

    for (i = 0; i < sizeof(salts) / sizeof(salts[0]); i++) {
        for (j = 0; j < sizeof(pws) / sizeof(pws[0]); j++) {
            char *r;

            memset(buf, '#', sizeof(buf));
            buf[sizeof(buf) - 1] = '\0';
            r = DES_fcrypt(pws[j], salts[i], buf);
            printf("  fcrypt %zu %zu: %s\n", i, j, r == NULL ? "NULL" : r == buf ? "buf" : "other");
            hex("buf", buf, sizeof(buf));
        }
    }
    a = DES_crypt("password", "ab");
    printf("  crypt %s\n", a != NULL ? a : "NULL");
    b = DES_crypt("other", "xy");
    check(a == b, "DES_crypt has one static buffer");
    printf("  crypt %s\n", b);
    check(DES_crypt("password", "") == NULL, "DES_crypt with an empty salt");
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    DES_set_key_unchecked(&k1, &s1);
    DES_set_key_unchecked(&k2, &s2);
    DES_set_key_unchecked(&k3, &s3);
    keys();
    blocks();
    cbcs();
    feedback();
    sums();
    strings();
    crypts();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
