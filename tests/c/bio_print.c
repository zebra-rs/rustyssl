/*
 * Conformance test for OpenSSL's printf (BIO_printf(3): BIO_printf, BIO_vprintf, BIO_snprintf,
 * BIO_vsnprintf) and for ERR_set_error and ERR_vset_error with a format, in TAP format.
 *
 * OpenSSL formats with its own code, not the C library's, and its output differs from C's in
 * many details. The expected strings are the reference's output.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/bnerr.h>
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

/*
 * BIO_vsnprintf and BIO_vprintf through wrappers without a format attribute, so that formats
 * the compiler would reject (OpenSSL's quirks among them) can be tested.
 */
static int sn(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = BIO_vsnprintf(buf, n, format, args);
    va_end(args);
    return ret;
}

static int pr(BIO *bio, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = BIO_vprintf(bio, format, args);
    va_end(args);
    return ret;
}

static void set_error(int lib, int reason, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    ERR_vset_error(lib, reason, format, args);
    va_end(args);
}

static char buf[128];

/* Formats into a 64-byte buffer filled with '#', and checks the return and the text. */
static int is(int ret, int expected_ret, const char *expected)
{
    if (ret != expected_ret) {
        printf("# returned %d, expected %d (text \"%s\")\n", ret, expected_ret, buf);
        return 0;
    }
    if (expected != NULL && strcmp(buf, expected) != 0) {
        printf("# got \"%s\", expected \"%s\"\n", buf, expected);
        return 0;
    }
    return 1;
}

static void reset(void)
{
    memset(buf, '#', sizeof(buf));
}

/* The memory BIO's contents as a string, then empties it. */
static const char *contents(BIO *bio)
{
    static char text[4096];
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);

    if (len < 0 || (size_t)len >= sizeof(text))
        len = 0;
    memcpy(text, data, (size_t)len);
    text[len] = '\0';
    (void)BIO_reset(bio);
    return text;
}

static void integers(void)
{
    reset();
    check(is(BIO_snprintf(buf, 64, "%d %i %s %c %%", 42, -3, "abc", 'x'), 13, "42 -3 abc x %"),
          "BIO_snprintf formats ints, strings, chars, and %%");
    reset();
    check(is(BIO_snprintf(buf, 64, "[%5d|%-5d|%05d|%+d|% d|%.3d]", 42, -7, -7, 5, 5, 5), 29,
             "[   42|-7   |-0007|+5| 5|005]"),
          "widths, flags, and precisions of ints");
    reset();
    check(is(BIO_snprintf(buf, 64, "%x %X %#x %o %#o %u %#X", 255, 255, 255, 8, 8, 4000000000U, 0),
             30, "ff FF 0xff 10 010 4000000000 0"),
          "hex, octal, and unsigned; # gives 0x only to nonzero values, and a leading 0");
    reset();
    check(is(sn(buf, 64, "[%#X|%#o|%#.3o|%.0d|%.0x|%#.0o|%.d]", 255, 0, 8, 0, 0, 0, 0), 17,
             "[0XFF|0|010|||0|]"),
          "%#X gives 0X; 0 with a precision of 0 is empty, except %#o; . alone is precision 0");
    reset();
    check(is(BIO_snprintf(buf, 64, "%ld %lu %lld %zu %zd %jd", -1L, 18446744073709551615UL,
                          (long long)INT64_MIN, (size_t)7, (ssize_t)-7, (intmax_t)9), 51,
             "-1 18446744073709551615 -9223372036854775808 7 -7 9"),
          "long, long long, size_t, and intmax_t");
    reset();
    check(is(BIO_snprintf(buf, 64, "%hd %hu %hx", 70000, 70000, -1), 14, "4464 4464 ffff"),
          "h narrows to a short");
    reset();
    check(is(BIO_snprintf(buf, 64, "[%*d|%-*d|%.*d]", 4, 1, 3, 2, 3, 3), 14, "[   1|2  |003]"),
          "widths and precisions from *");
    reset();
    check(is(sn(buf, 64, "[%*d|%.*d]", -4, 1, -2, 7), 8, "[1   |7]"),
          "a negative width from * is the - flag; a negative precision is none");
    reset();
    check(is(BIO_snprintf(buf, 64, "%p %p", (void *)0, (void *)0x1234), 8, "0 0x1234"),
          "%p is hex with 0x, and null is 0");
    reset();
    check(is(sn(buf, 64, "[%08.3d|%-08d|%+05d|%-+5d]", 5, 5, -5, 5), 31,
             "[     005|5       |-0005|+5   ]"),
          "a precision drops the 0 flag, and - beats 0");
}

static void quirks(void)
{
    int n = -1;

    reset();
    check(is(sn(buf, 64, "%hhd|%hhu|%hhx|", 261, -1, 511), 9, "5|255|ff|"),
          "hh narrows to a char");
    reset();
    check(is(sn(buf, 64, "%td|%tx", (ptrdiff_t)-3, (ptrdiff_t)255), 5, "-3|ff"),
          "t reads a ptrdiff_t");
    reset();
    check(is(sn(buf, 64, "a%wbc%k%5%d", 1), 4, "ac%d"),
          "%w skips the next character; unknown conversions print nothing; %5% is %");
    reset();
    check(is(BIO_snprintf(buf, 64, "abc%n|", &n), 4, "abc|") && n == 3, "%n stores the count");
    {
        signed char hh = -1;
        short h = -1;
        long l = -1;
        long long ll = -1;
        size_t z = 0;

        reset();
        check(is(sn(buf, 64, "a%hhnbc%hnd%lne%llnf%zn", &hh, &h, &l, &ll, &z), 6, "abcdef")
              && hh == 1 && h == 3 && l == 4 && ll == 5 && z == 6,
              "%n stores into the type its length modifier names");
    }
    reset();
    n = -1;
    check(sn(buf, 4, "abcdef%n%10s", &n, "") == -1 && n == 6 && strcmp(buf, "abc") == 0,
          "%n counts what a full buffer drops");
    reset();
    check(is(sn(buf, 64, "trailing %"), 9, "trailing "), "a trailing % prints nothing");
}

static void strings(void)
{
    reset();
    check(is(BIO_snprintf(buf, 64, "[%8s][%-8s][%.2s][%6.2s]", "hello", "hello", "hello", "hello"),
             32, "[   hello][hello   ][he][    he]"),
          "string widths and precisions");
    reset();
    check(is(sn(buf, 64, "[%s|%3s|%.3s]", NULL, NULL, NULL), 19, "[<NULL>|<NULL>|<NU]"),
          "a null string is <NULL>");
    reset();
    check(is(sn(buf, 64, "[%.*s]", -1, "hello"), 7, "[hello]"),
          "a negative precision from * prints the whole string");
}

static void doubles(void)
{
    reset();
    check(is(BIO_snprintf(buf, 64, "%f %.2f %.0f %#.0f", 1.5, 2.675, 2.5, 3.0), 18,
             "1.500000 2.67 3 3."),
          "%f rounds the scaled fraction half up; # keeps the point");
    reset();
    check(is(sn(buf, 64, "[%10.3f|%-10.3f|%010.3f|%+.1f]", -1.5, -1.5, -1.5, 2.25), 34,
             "[    -1.500|-1.500|-0001.500|+2.3]"),
          "widths and flags of %f; - drops the padding");
    reset();
    check(is(BIO_snprintf(buf, 64, "%.12f", 0.5), 11, "0.500000000"),
          "%f prints at most 9 decimals");
    reset();
    check(is(BIO_snprintf(buf, 64, "%e %E %.2e", 12345.678, 0.000123, 1.0), 34,
             "1.234568e+04 1.230000E-04 1.00e+00"),
          "%e and %E");
    reset();
    check(is(BIO_snprintf(buf, 64, "%e", 10.0), 13, "10.000000e+00"), "%e leaves 10 as 10");
    reset();
    check(is(BIO_snprintf(buf, 64, "%g %g %g %g %G %g", 0.0001, 100000.0, 1e-5, 1234567.0,
                          1e-10, 0.0), 39, "0.0001 100000 1e-05 1.23457e+06 1E-10 0"),
          "%g picks %f or %e and drops trailing zeros");
    reset();
    check(is(BIO_snprintf(buf, 64, "%f|%f|%.1f", 1.0 / 0.0, -1.0 / 0.0, 0.0 / 0.0), 24,
             "?0.000000|?0.000000|?0.0"),
          "infinities and NaNs print as ?0");
    reset();
    check(is(BIO_snprintf(buf, 64, "%f", 1e20), -1, NULL),
          "%f fails at 2^64 and above");
    reset();
    check(is(BIO_snprintf(buf, 64, "%.0f", 12345678901234567890.0), 19, "2345678901234567168"),
          "%f drops the leading digit of a 20-digit integer part");
    reset();
    check(is(sn(buf, 64, "%Lf", 2.0), 8, "2.000000"), "%Lf reads a double");
}

static void truncation(void)
{
    reset();
    check(is(BIO_snprintf(buf, 4, "abcdef"), -1, "abc") && buf[4] == '#',
          "output that doesn't fit is cut short, ends in a NUL, and returns -1");
    reset();
    check(is(BIO_snprintf(buf, 4, "abc"), 3, "abc"), "output that just fits returns its length");
    reset();
    check(BIO_snprintf(buf, 0, "abc") == -1 && buf[0] == '#',
          "a zero-size buffer is untouched and returns -1");
    reset();
    check(BIO_snprintf(buf, 1, "abc") == -1 && buf[0] == '\0' && buf[1] == '#',
          "a one-byte buffer gets the NUL");
    reset();
    check(BIO_snprintf(buf, 6, "%10d", 1) == -1 && strcmp(buf, "     ") == 0,
          "padding is cut short too");
    reset();
    check(BIO_snprintf(buf, 5, "%s", "abcdef") == -1 && strcmp(buf, "abcd") == 0,
          "strings are cut short");
    reset();
    check(is(sn(buf, 64, ""), 0, ""), "an empty format gives an empty string");
}

static void printing(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    char big[3001];
    int ret;

    check(BIO_printf(mem, "%s=%d\n", "x", 5) == 4 && strcmp(contents(mem), "x=5\n") == 0,
          "BIO_printf writes to the BIO and returns the count");
    check(pr(mem, "%05.1f", 2.25) == 5 && strcmp(contents(mem), "002.3") == 0,
          "BIO_vprintf formats as BIO_printf");
    memset(big, 'y', 3000);
    big[3000] = '\0';
    ret = BIO_printf(mem, "%3000s|%s", "x", big);
    check(ret == 6001 && BIO_pending(mem) == 6001,
          "BIO_printf grows its buffer for long output");
    (void)BIO_reset(mem);
    check(BIO_printf(mem, "%f", 1e300) == -1 && BIO_pending(mem) == 0,
          "BIO_printf writes nothing when formatting fails");
    check(pr(mem, "") == 0 && BIO_pending(mem) == 0,
          "BIO_printf of nothing writes nothing");
    check(BIO_printf(NULL, "x") <= 0, "BIO_printf to a null BIO fails");
    BIO_free(mem);
}

static void errors(void)
{
    const char *data = NULL;
    int flags = 0;
    unsigned long code;
    char longer[1100];

    ERR_clear_error();
    ERR_new();
    ERR_set_debug("file.c", 12, "func");
    ERR_set_error(ERR_LIB_BN, BN_R_DIV_BY_ZERO, "value %d of %s", 7, "x");
    code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags);
    check(ERR_GET_LIB(code) == ERR_LIB_BN && ERR_GET_REASON(code) == BN_R_DIV_BY_ZERO
              && strcmp(data, "value 7 of x") == 0
              && flags == (ERR_TXT_STRING | ERR_TXT_MALLOCED),
          "ERR_set_error formats its data");

    ERR_raise_data(ERR_LIB_BN, BN_R_BIGNUM_TOO_LONG, "%.2f%%", 99.5);
    code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags);
    check(ERR_GET_REASON(code) == BN_R_BIGNUM_TOO_LONG && strcmp(data, "99.50%") == 0,
          "ERR_raise_data formats its data");

    ERR_new();
    set_error(ERR_LIB_BN, BN_R_DIV_BY_ZERO, "%s-%d", "v", 2);
    code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags);
    check(code != 0 && strcmp(data, "v-2") == 0, "ERR_vset_error formats its data");

    memset(longer, 'z', sizeof(longer) - 1);
    longer[sizeof(longer) - 1] = '\0';
    ERR_new();
    ERR_set_error(ERR_LIB_BN, BN_R_DIV_BY_ZERO, "%s", longer);
    code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags);
    check(code != 0 && strcmp(data, "") == 0 && flags == (ERR_TXT_STRING | ERR_TXT_MALLOCED),
          "data longer than ERR_MAX_DATA_SIZE - 1 is left empty");

    ERR_new();
    ERR_set_error(ERR_LIB_BN, BN_R_DIV_BY_ZERO, "%f", 1e30);
    code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags);
    check(code != 0 && strcmp(data, "") == 0, "data whose formatting fails is left empty");

    ERR_new();
    ERR_add_error_data(1, "old");
    ERR_set_error(ERR_LIB_BN, BN_R_DIV_BY_ZERO, NULL);
    code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags);
    check(code != 0 && strcmp(data, "") == 0 && (flags & ERR_TXT_STRING) == 0,
          "ERR_set_error without a format drops the data");
}

int main(void)
{
    integers();
    quirks();
    strings();
    doubles();
    truncation();
    printing();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
