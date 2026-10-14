/*
 * Conformance test for PKCS #12 password strings and key derivation (PKCS12_key_gen_uni(3),
 * OPENSSL_asc2uni and the other conversions of pkcs12.h), in TAP format: passwords to the
 * big-endian UTF-16 PKCS #12 hashes and back (surrogate pairs, the terminating zero unit, input
 * that isn't UTF-8 or UTF-16 taken octet by octet, odd and negative lengths), and the key
 * derivation from UTF-16, ASCII, and UTF-8 passwords, against a known answer.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 *
 * Lengths the reference reads out of bounds with (a NULL string with a length) are left out
 * (docs/DEVIATIONS.md).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void hex(const char *what, const unsigned char *p, int n)
{
    int i;

    printf("  %s (%d):", what, n);
    for (i = 0; i < n; i++)
        printf(" %02x", p[i]);
    printf("\n");
}

static void errors(void)
{
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/* The PKCS12KDF test of evppbe_pkcs12.txt: "smeg", SHA-1, id 1, one iteration. */
static const unsigned char smeg[] = { 0x00, 0x73, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x67, 0x00, 0x00 };
static const unsigned char salt[] = { 0x0a, 0x58, 0xcf, 0x64, 0x53, 0x0d, 0x82, 0x3f };
static const unsigned char key[] = {
    0x8a, 0xaa, 0xe6, 0x29, 0x7b, 0x6c, 0xb0, 0x46, 0x42, 0xab, 0x5b, 0x07,
    0x78, 0x51, 0x28, 0x4e, 0xb7, 0x12, 0x8f, 0x1a, 0x2a, 0x7f, 0xbc, 0xa3
};

static void to_uni(void)
{
    unsigned char *uni = NULL, *r;
    int len = -7;
    /* U+00E9, U+1F600. */
    const char *utf8 = "a\xc3\xa9\xf0\x9f\x98\x80";

    r = OPENSSL_asc2uni("smeg", -1, &uni, &len);
    check(r != NULL && r == uni && len == 10 && memcmp(r, smeg, 10) == 0, "asc2uni: a C string");
    OPENSSL_free(r);
    r = OPENSSL_asc2uni("a\xe9z", 2, NULL, NULL);
    check(r != NULL, "asc2uni: a length, no outputs");
    if (r != NULL)
        hex("asc2uni", r, 6);
    OPENSSL_free(r);
    r = OPENSSL_asc2uni("x", 0, NULL, &len);
    check(r != NULL && len == 2 && r[0] == 0 && r[1] == 0, "asc2uni: empty");
    OPENSSL_free(r);
    check(OPENSSL_asc2uni("x", -2, NULL, NULL) == NULL, "asc2uni: below -1");

    uni = NULL;
    r = OPENSSL_utf82uni(utf8, -1, &uni, &len);
    check(r != NULL && r == uni && len == 10, "utf82uni: past the BMP");
    if (r != NULL)
        hex("utf82uni", r, len);
    OPENSSL_free(r);
    r = OPENSSL_utf82uni("\xe9z", -1, NULL, &len);
    check(r != NULL && len == 6, "utf82uni: not UTF-8, octet by octet");
    if (r != NULL)
        hex("utf82uni", r, len);
    OPENSSL_free(r);
    r = OPENSSL_utf82uni("\xed\xa0\x80", -1, NULL, &len);
    check(r != NULL && len == 8, "utf82uni: an encoded surrogate, octet by octet");
    OPENSSL_free(r);
    r = OPENSSL_utf82uni("abc", -5, NULL, &len);
    check(r != NULL && len == 2 && r[0] == 0 && r[1] == 0, "utf82uni: below -1 is empty");
    OPENSSL_free(r);
}

static void from_uni(void)
{
    static const unsigned char pair[] = { 0x00, 0x61, 0xd8, 0x3d, 0xde, 0x00, 0x00, 0x00 };
    static const unsigned char open_[] = { 0x00, 0x61, 0x00, 0xe9 };
    static const unsigned char lone[] = { 0xd8, 0x3d, 0x00, 0x62, 0x00, 0x00 };
    static const unsigned char low[] = { 0xdc, 0x00, 0x00, 0x62 };
    char *s;

    s = OPENSSL_uni2asc(smeg, 10);
    check(s != NULL && strcmp(s, "smeg") == 0, "uni2asc: terminated");
    OPENSSL_free(s);
    s = OPENSSL_uni2asc(open_, 4);
    check(s != NULL && strlen(s) == 2, "uni2asc: a zero added");
    if (s != NULL)
        hex("uni2asc", (unsigned char *)s, 3);
    OPENSSL_free(s);
    s = OPENSSL_uni2asc(smeg, 0);
    check(s != NULL && s[0] == 0, "uni2asc: empty");
    OPENSSL_free(s);
    check(OPENSSL_uni2asc(smeg, 7) == NULL, "uni2asc: odd");
    check(OPENSSL_uni2asc(smeg, -2) == NULL, "uni2asc: negative");

    s = OPENSSL_uni2utf8(pair, 8);
    check(s != NULL && strcmp(s, "a\xf0\x9f\x98\x80") == 0, "uni2utf8: a surrogate pair");
    OPENSSL_free(s);
    s = OPENSSL_uni2utf8(open_, 4);
    check(s != NULL && strcmp(s, "a\xc3\xa9") == 0, "uni2utf8: a zero added");
    OPENSSL_free(s);
    s = OPENSSL_uni2utf8(lone, 6);
    check(s != NULL, "uni2utf8: a lone high surrogate, as uni2asc");
    if (s != NULL)
        hex("uni2utf8", (unsigned char *)s, 3);
    OPENSSL_free(s);
    s = OPENSSL_uni2utf8(low, 4);
    check(s != NULL, "uni2utf8: a low surrogate first, as uni2asc");
    if (s != NULL)
        hex("uni2utf8", (unsigned char *)s, 3);
    OPENSSL_free(s);
    s = OPENSSL_uni2utf8(smeg, 0);
    check(s != NULL && s[0] == 0, "uni2utf8: empty");
    OPENSSL_free(s);
    check(OPENSSL_uni2utf8(smeg, 5) == NULL, "uni2utf8: odd");
    check(OPENSSL_uni2utf8(smeg, -1) == NULL, "uni2utf8: negative");
}

static void key_gen(void)
{
    EVP_MD *sha1 = EVP_MD_fetch(NULL, "SHA1", NULL);
    const EVP_MD *sha256 = EVP_sha256();
    unsigned char out[24], other[24], s[8], u[10];
    unsigned char empty[2] = { 0, 0 };

    memcpy(s, salt, 8);
    memcpy(u, smeg, 10);
    memset(out, 0, sizeof(out));
    check(PKCS12_key_gen_uni(u, 10, s, 8, 1, 1, 24, out, sha1) == 1
              && memcmp(out, key, 24) == 0,
          "key_gen_uni: the known answer");
    memset(out, 0, sizeof(out));
    check(PKCS12_key_gen_asc("smeg", -1, s, 8, 1, 1, 24, out, sha1) == 1
              && memcmp(out, key, 24) == 0,
          "key_gen_asc: the same from ASCII");
    memset(out, 0, sizeof(out));
    check(PKCS12_key_gen_utf8("smegx", 4, s, 8, 1, 1, 24, out, sha1) == 1
              && memcmp(out, key, 24) == 0,
          "key_gen_utf8: the same from UTF-8");
    memset(out, 0, sizeof(out));
    check(PKCS12_key_gen_uni_ex(u, 10, s, 8, 1, 1, 24, out, sha1, NULL, "provider=default") == 1
              && memcmp(out, key, 24) == 0,
          "key_gen_uni_ex: a property query");
    memset(out, 0, sizeof(out));
    check(PKCS12_key_gen_asc_ex("smeg", 4, s, 8, 1, 1, 24, out, sha1, NULL, NULL) == 1
              && memcmp(out, key, 24) == 0,
          "key_gen_asc_ex");
    memset(out, 0, sizeof(out));
    check(PKCS12_key_gen_utf8_ex("smeg", -1, s, 8, 1, 1, 24, out, sha1, NULL, NULL) == 1
              && memcmp(out, key, 24) == 0,
          "key_gen_utf8_ex");

    /* Other purposes, digests, and iteration counts. */
    check(PKCS12_key_gen_uni(u, 10, s, 8, 2, 1000, 24, out, sha256) == 1, "IV, SHA-256, 1000");
    hex("iv", out, 24);
    check(PKCS12_key_gen_utf8("\xc3\xa9t\xc3\xa9", -1, s, 8, 3, 5, 20, out, sha256) == 1,
          "a MAC key from UTF-8");
    hex("mac", out, 20);

    /* No password: none at all, not even the zero unit. */
    check(PKCS12_key_gen_asc(NULL, 5, s, 8, 1, 1, 24, out, sha1) == 1, "asc: no password");
    check(PKCS12_key_gen_utf8(NULL, -1, s, 8, 1, 1, 24, other, sha1) == 1
              && memcmp(out, other, 24) == 0,
          "utf8: the same");
    check(PKCS12_key_gen_uni(NULL, 0, s, 8, 1, 1, 24, other, sha1) == 1
              && memcmp(out, other, 24) == 0,
          "uni: the same");
    hex("none", out, 24);
    check(PKCS12_key_gen_uni(empty, 2, s, 8, 1, 1, 24, other, sha1) == 1
              && memcmp(out, other, 24) != 0,
          "an empty password differs");
    check(PKCS12_key_gen_utf8("abc", -5, s, 8, 1, 1, 24, out, sha1) == 1
              && memcmp(out, other, 24) == 0,
          "utf8: a length below -1 is the empty password");
    check(PKCS12_key_gen_uni(u, 10, NULL, 0, 1, 1, 24, out, sha1) == 1, "no salt");
    hex("no salt", out, 24);

    /* Failures. */
    check(PKCS12_key_gen_asc("abc", -5, s, 8, 1, 1, 24, out, sha1) == 0, "asc: below -1");
    errors();
    check(PKCS12_key_gen_uni(u, 10, s, 8, 1, 1, 0, out, sha1) == 0, "no octets");
    check(PKCS12_key_gen_uni(u, 10, s, 8, 1, 1, -1, out, sha1) == 0, "a negative count");
    errors();
    check(PKCS12_key_gen_uni_ex(u, 10, s, 8, 1, 1, 24, out, sha1, NULL, "provider=nowhere") == 0,
          "no PKCS12KDF");
    ERR_clear_error();
    EVP_MD_free(sha1);
}

int main(void)
{
    to_uni();
    from_uni();
    key_gen();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
