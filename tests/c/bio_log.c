/*
 * Conformance test for the syslog BIO (BIO_s_log in bio.h), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both (TEST_PLAN.md, layer L4). It writes a few messages to the
 * system log (under "rustyssl-bio-log-test" after BIO_CTRL_SET); what the log keeps isn't read
 * back, only what the BIO calls return.
 */
#include <stdio.h>
#include <syslog.h>

#include <openssl/bio.h>
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

int main(void)
{
    static char name[] = "rustyssl-bio-log-test";
    BIO *b = BIO_new(BIO_s_log());
    char buf[16];

    check(b != NULL, "BIO_new(BIO_s_log())");
    printf("  type %d (BIO_TYPE_MEM %d), name %s\n", BIO_method_type(b), BIO_TYPE_MEM,
           BIO_method_name(b));
    check(BIO_ctrl(b, BIO_CTRL_SET, LOG_USER, name) == 0, "BIO_CTRL_SET reopens the log, returning 0");
    check(BIO_write(b, "DEBUG rustyssl conformance test", 31) == 31, "BIO_write: the length");
    check(BIO_write(b, "INFO a message\0with a NUL", 25) == 25, "a NUL inside: still the length");
    check(BIO_puts(b, "NOTICE rustyssl BIO_puts") == 24, "BIO_puts: the length");
    check(BIO_write(b, "", 0) == 0, "an empty write");
    printf("  BIO_printf %d\n", BIO_printf(b, "DBG %s %d", "rustyssl", 7));
    printf("  BIO_read %d, BIO_gets %d\n", BIO_read(b, buf, sizeof(buf)), BIO_gets(b, buf, sizeof(buf)));
    ERR_clear_error();
    printf("  ctrl pending %ld, flush %ld, eof %ld\n", BIO_ctrl_pending(b), (long)BIO_flush(b),
           (long)BIO_eof(b));
    check(BIO_free(b) == 1, "BIO_free closes the log");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
