/*
 * Conformance test for the string and hex helpers in crypto.h (OPENSSL_strdup(3),
 * OPENSSL_hexstr2buf(3), OPENSSL_strcasecmp(3), OPENSSL_strtoul), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). Results that
 * depend on whether char is signed are printed as comments, which the harness compares.
 */
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int same(const char *a, const char *b)
{
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

static unsigned long reason(void)
{
    return ERR_GET_REASON(ERR_get_error());
}

static void duplicating(void)
{
    char *s = OPENSSL_strdup("hello");
    char *n = OPENSSL_strndup("hello", 3), *whole = OPENSSL_strndup("hi", 10);
    unsigned char bytes[4] = { 1, 0, 2, 3 };
    unsigned char *m = OPENSSL_memdup(bytes, sizeof(bytes));

    check(same(s, "hello") && same(n, "hel") && same(whole, "hi"),
          "OPENSSL_strdup and OPENSSL_strndup");
    check(m != NULL && memcmp(m, bytes, 4) == 0, "OPENSSL_memdup");
    check(OPENSSL_strdup(NULL) == NULL && OPENSSL_strndup(NULL, 3) == NULL
          && OPENSSL_memdup(NULL, 3) == NULL, "null in, null out");
    ERR_clear_error();
    check(CRYPTO_memdup(bytes, (size_t)INT_MAX, "big.c", 1) == NULL && ERR_peek_error() == 0,
          "CRYPTO_memdup: INT_MAX bytes or more fail without an error");
    OPENSSL_free(s);
    OPENSSL_free(n);
    OPENSSL_free(whole);
    OPENSSL_free(m);
}

static void copying(void)
{
    char buf[8];

    check(OPENSSL_strnlen("hello", 3) == 3 && OPENSSL_strnlen("hi", 10) == 2
          && OPENSSL_strnlen("x", 0) == 0, "OPENSSL_strnlen");
    memset(buf, '#', sizeof(buf));
    check(OPENSSL_strlcpy(buf, "hello world", sizeof(buf)) == 11 && same(buf, "hello w"),
          "OPENSSL_strlcpy: truncates, returns the source length");
    memset(buf, '#', sizeof(buf));
    check(OPENSSL_strlcpy(buf, "hi", 0) == 2 && buf[0] == '#', "OPENSSL_strlcpy: size 0");
    check(OPENSSL_strlcpy(buf, "hi", 1) == 2 && buf[0] == '\0', "OPENSSL_strlcpy: size 1");
    strcpy(buf, "ab");
    check(OPENSSL_strlcat(buf, "cdefghij", sizeof(buf)) == 10 && same(buf, "abcdefg"),
          "OPENSSL_strlcat: truncates, returns the length it tried to make");
    memcpy(buf, "abcd", 4);
    check(OPENSSL_strlcat(buf, "xy", 3) == 5 && memcmp(buf, "abcd", 4) == 0,
          "OPENSSL_strlcat: a destination without a NUL within size");
}

static void comparing(void)
{
    check(OPENSSL_strcasecmp("Hello", "hELLO") == 0 && OPENSSL_strcasecmp("a", "B") < 0
          && OPENSSL_strcasecmp("b", "A") > 0 && OPENSSL_strcasecmp("ab", "a") > 0,
          "OPENSSL_strcasecmp");
    check(OPENSSL_strncasecmp("HELLO there", "hello world", 6) == 0
          && OPENSSL_strncasecmp("abc", "abd", 3) < 0 && OPENSSL_strncasecmp("abc", "ABD", 0) == 0
          && OPENSSL_strncasecmp("ab", "AB", 10) == 0, "OPENSSL_strncasecmp");
    printf("# strcasecmp: %d %d %d %d\n", OPENSSL_strcasecmp("a", "z"),
           OPENSSL_strcasecmp("\xe9", "a"), OPENSSL_strcasecmp("\xc9", "\xe9"),
           OPENSSL_strncasecmp("x\x80", "X\x01", 5));
}

static void converting(void)
{
    unsigned long n = 7;
    char *end = NULL;
    const char *text = "123abc";

    check(OPENSSL_strtoul("42", NULL, 10, &n) == 1 && n == 42, "OPENSSL_strtoul");
    check(OPENSSL_strtoul("0x1f", NULL, 0, &n) == 1 && n == 31
          && OPENSSL_strtoul("1f", NULL, 16, &n) == 1 && n == 31
          && OPENSSL_strtoul("017", NULL, 0, &n) == 1 && n == 15,
          "OPENSSL_strtoul: bases");
    check(OPENSSL_strtoul(text, &end, 10, &n) == 1 && n == 123 && end == text + 3,
          "OPENSSL_strtoul: with endptr, trailing text is fine");
    check(OPENSSL_strtoul(text, NULL, 10, &n) == 0, "OPENSSL_strtoul: without, it isn't");
    check(OPENSSL_strtoul("-5", &end, 10, &n) == 0 && OPENSSL_strtoul("", &end, 10, &n) == 0
          && OPENSSL_strtoul("abc", &end, 10, &n) == 0,
          "OPENSSL_strtoul: negative, empty, or no digits");
    n = 0;
    printf("# OPENSSL_strtoul(\" -5\") = %d, %lu\n", OPENSSL_strtoul(" -5", NULL, 10, &n), n);
    errno = 0;
    check(OPENSSL_strtoul("99999999999999999999999", NULL, 10, &n) == 0 && errno == ERANGE,
          "OPENSSL_strtoul: out of range, with errno");
    errno = 5;
    check(OPENSSL_strtoul("1", NULL, 10, &n) == 1 && errno == 0, "OPENSSL_strtoul: clears errno");
    end = NULL;
    check(OPENSSL_strtoul(text, &end, 10, NULL) == 0 && end == text,
          "OPENSSL_strtoul: no result pointer; endptr is the string");
    end = (char *)text;
    check(OPENSSL_strtoul(NULL, &end, 10, &n) == 0 && end == NULL,
          "OPENSSL_strtoul: null string, endptr set to it");
}

static void hex(void)
{
    unsigned char buf[8];
    size_t len = 99;
    long out = -1;
    unsigned char *p;
    char str[32];
    char *h;
    int all = 1;

    for (int c = 0; c < 256; c++) {
        int expected = c >= '0' && c <= '9' ? c - '0'
                     : c >= 'a' && c <= 'f' ? c - 'a' + 10
                     : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

        all = all && OPENSSL_hexchar2int((unsigned char)c) == expected;
    }
    check(all, "OPENSSL_hexchar2int: every byte");

    p = OPENSSL_hexstr2buf("0A:1b:Ff", &out);
    check(p != NULL && out == 3 && p[0] == 0x0a && p[1] == 0x1b && p[2] == 0xff,
          "OPENSSL_hexstr2buf: colons between bytes");
    OPENSSL_free(p);
    p = OPENSSL_hexstr2buf("0a1bff", &out);
    check(p != NULL && out == 3, "OPENSSL_hexstr2buf: no separators");
    OPENSSL_free(p);
    p = OPENSSL_hexstr2buf("::0a", &out);
    check(p != NULL && out == 1, "OPENSSL_hexstr2buf: separators anywhere");
    OPENSSL_free(p);
    ERR_clear_error();
    out = 5;
    check(OPENSSL_hexstr2buf("abc", &out) == NULL && reason() == CRYPTO_R_ODD_NUMBER_OF_DIGITS
          && out == 0, "OPENSSL_hexstr2buf: an odd number of digits");
    check(OPENSSL_hexstr2buf("zz", NULL) == NULL && reason() == CRYPTO_R_ILLEGAL_HEX_DIGIT,
          "OPENSSL_hexstr2buf: an illegal digit");
    out = 5;
    check(OPENSSL_hexstr2buf("a", &out) == NULL && reason() == CRYPTO_R_HEX_STRING_TOO_SHORT
          && out == 5 && OPENSSL_hexstr2buf("", NULL) == NULL
          && reason() == CRYPTO_R_HEX_STRING_TOO_SHORT,
          "OPENSSL_hexstr2buf: too short");

    check(OPENSSL_hexstr2buf_ex(buf, sizeof(buf), &len, "01-02-03", '-') == 1 && len == 3
          && buf[2] == 3, "OPENSSL_hexstr2buf_ex: a separator of choice");
    check(OPENSSL_hexstr2buf_ex(NULL, 0, &len, "0102030405", '\0') == 1 && len == 5,
          "OPENSSL_hexstr2buf_ex: counting only");
    check(OPENSSL_hexstr2buf_ex(buf, 2, &len, "010203", '\0') == 0
          && reason() == CRYPTO_R_TOO_SMALL_BUFFER, "OPENSSL_hexstr2buf_ex: too small");
    check(OPENSSL_hexstr2buf_ex(buf, sizeof(buf), &len, "01:02", '\0') == 0
          && reason() == CRYPTO_R_ILLEGAL_HEX_DIGIT,
          "OPENSSL_hexstr2buf_ex: no separator means none is allowed");

    buf[0] = 0x0a;
    buf[1] = 0xbc;
    buf[2] = 0xff;
    h = OPENSSL_buf2hexstr(buf, 3);
    check(same(h, "0A:BC:FF"), "OPENSSL_buf2hexstr: uppercase, with colons");
    OPENSSL_free(h);
    h = OPENSSL_buf2hexstr(buf, 0);
    check(same(h, ""), "OPENSSL_buf2hexstr: empty");
    OPENSSL_free(h);
    check(OPENSSL_buf2hexstr(buf, -1) == NULL && reason() == CRYPTO_R_TOO_MANY_BYTES,
          "OPENSSL_buf2hexstr: a negative length");
    check(OPENSSL_buf2hexstr_ex(str, sizeof(str), &len, buf, 3, '\0') == 1 && same(str, "0ABCFF")
          && len == 7, "OPENSSL_buf2hexstr_ex: no separator; the length counts the NUL");
    check(OPENSSL_buf2hexstr_ex(str, sizeof(str), &len, buf, 3, '-') == 1
          && same(str, "0A-BC-FF") && len == 9, "OPENSSL_buf2hexstr_ex: a separator");
    check(OPENSSL_buf2hexstr_ex(NULL, 0, &len, buf, 2, ':') == 1 && len == 6,
          "OPENSSL_buf2hexstr_ex: the length only");
    check(OPENSSL_buf2hexstr_ex(str, 5, &len, buf, 2, ':') == 0
          && reason() == CRYPTO_R_TOO_SMALL_BUFFER && len == 6,
          "OPENSSL_buf2hexstr_ex: too small");
    check(OPENSSL_buf2hexstr_ex(str, sizeof(str), &len, buf, 0, ':') == 1 && same(str, "")
          && len == 1, "OPENSSL_buf2hexstr_ex: empty");
    check(OPENSSL_buf2hexstr_ex(str, sizeof(str), &len, buf, SIZE_MAX / 2, ':') == 0
          && reason() == CRYPTO_R_TOO_MANY_BYTES, "OPENSSL_buf2hexstr_ex: too many bytes");
}

int main(void)
{
    duplicating();
    copying();
    comparing();
    converting();
    hex();
    printf("1..%d\n", number);
    return failures != 0;
}
