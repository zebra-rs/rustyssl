/*
 * Conformance test for tracing (OSSL_trace_set_channel(3), OSSL_trace_enabled(3),
 * OSSL_trace_get_category_num(3), OSSL_trace_string) in OpenSSL's default build, which has no
 * tracing: categories still map to names, OSSL_trace_string still formats, and nothing can be
 * attached or enabled. In TAP format; the strings OSSL_trace_string writes are printed escaped
 * as comments, so they're compared too.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/trace.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int called = 0;

static size_t callback(const char *buf, size_t cnt, int category, int cmd, void *data)
{
    (void)buf;
    (void)category;
    (void)cmd;
    (void)data;
    called++;
    return cnt;
}

static void categories(void)
{
    int i, ok = 1;

    printf("# categories:");
    for (i = 0; i < OSSL_TRACE_CATEGORY_NUM; i++) {
        const char *name = OSSL_trace_get_category_name(i);

        printf(" %d=%s", i, name == NULL ? "(null)" : name);
        ok = ok && name != NULL && OSSL_trace_get_category_num(name) == i;
    }
    printf("\n");
    check(ok, "every category's name maps back to its number");
    check(OSSL_trace_get_category_name(-1) == NULL && OSSL_trace_get_category_name(OSSL_TRACE_CATEGORY_NUM) == NULL,
          "numbers outside the range have no name");
    check(OSSL_trace_get_category_num("tls") == OSSL_TRACE_CATEGORY_TLS
              && OSSL_trace_get_category_num("Tls_Cipher") == OSSL_TRACE_CATEGORY_TLS_CIPHER
              && OSSL_trace_get_category_num("x509v3_POLICY") == OSSL_TRACE_CATEGORY_X509V3_POLICY,
          "names are matched ignoring case");
    check(OSSL_trace_get_category_num(NULL) == -1 && OSSL_trace_get_category_num("") == -1
              && OSSL_trace_get_category_num("TLS ") == -1 && OSSL_trace_get_category_num("nope") == -1,
          "unknown names are -1");
}

static void disabled(void)
{
    BIO *channel = BIO_new(BIO_s_mem());
    int i, ok = 1;

    check(OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_TLS, channel) == 0
              && OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_ALL, NULL) == 0
              && OSSL_trace_set_channel(-1, channel) == 0,
          "OSSL_trace_set_channel fails, leaving the channel to the caller");
    check(BIO_puts(channel, "still mine") == 10, "which can still use it");
    BIO_free(channel);
    check(OSSL_trace_set_callback(OSSL_TRACE_CATEGORY_ALL, callback, &called) == 0
              && OSSL_trace_set_callback(OSSL_TRACE_CATEGORY_ALL, NULL, NULL) == 0,
          "OSSL_trace_set_callback fails");
    check(OSSL_trace_set_prefix(OSSL_TRACE_CATEGORY_INIT, "BEGIN") == 0
              && OSSL_trace_set_suffix(OSSL_TRACE_CATEGORY_INIT, "END") == 0
              && OSSL_trace_set_prefix(OSSL_TRACE_CATEGORY_INIT, NULL) == 0
              && OSSL_trace_set_suffix(99, NULL) == 0,
          "and so do the prefix and suffix setters");
    for (i = -1; i <= OSSL_TRACE_CATEGORY_NUM; i++)
        ok = ok && OSSL_trace_enabled(i) == 0 && OSSL_trace_begin(i) == NULL;
    check(ok, "no category is enabled, and none begins a trace");
    OSSL_trace_end(OSSL_TRACE_CATEGORY_TLS, NULL);
    check(1, "OSSL_trace_end does nothing");
    check(!OSSL_TRACE_ENABLED(TLS), "OSSL_TRACE_ENABLED is false");
    OSSL_TRACE_BEGIN(TLS) {
        called += 100 + (trc_out != NULL);
    } OSSL_TRACE_END(TLS);
    OSSL_TRACE(INIT, "never\n");
    OSSL_TRACE1(INIT, "never %d\n", 1);
    check(called == 0, "the trace macros run nothing, and no callback was called");
    check(ERR_peek_error() == 0, "nothing raised an error");
}

/* Writes what `ret = OSSL_trace_string(...)` produced as an escaped comment. */
static void show(const char *what, int ret, BIO *mem)
{
    char *data;
    long len = BIO_get_mem_data(mem, &data), i;

    printf("# %s: %d \"", what, ret);
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];

        if (c == '\n')
            printf("\\n");
        else if (c < 0x20 || c >= 0x7f || c == '"' || c == '\\')
            printf("\\x%02x", c);
        else
            putchar(c);
    }
    printf("\"\n");
    (void)BIO_reset(mem);
}

static void strings(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    unsigned char long_data[200], controls[] = "tab\there\0nul\x7f" "del\x80high\r\n";
    int ret;

    memset(long_data, 'a', sizeof(long_data));
    long_data[sizeof(long_data) - 1] = 'z';

    ret = OSSL_trace_string(mem, 1, 0, (const unsigned char *)"plain text", 10);
    check(ret == 10, "text is printed as it is");
    show("text", ret, mem);
    ret = OSSL_trace_string(mem, 0, 0, (const unsigned char *)"plain text", 10);
    check(ret == 11, "masked, a newline is added");
    show("masked", ret, mem);
    ret = OSSL_trace_string(mem, 0, 0, controls, sizeof(controls) - 1);
    check(ret == (int)sizeof(controls) - 1, "control characters but the last newline are shown as spaces");
    show("controls", ret, mem);
    ret = OSSL_trace_string(mem, 1, 0, controls, sizeof(controls) - 1);
    check(ret == 8, "as text, a NUL ends the output");
    show("controls as text", ret, mem);
    ret = OSSL_trace_string(mem, 1, 0, long_data, sizeof(long_data));
    check(ret == OSSL_TRACE_STRING_MAX, "a long string is cut to OSSL_TRACE_STRING_MAX after a note");
    show("limited", ret, mem);
    ret = OSSL_trace_string(mem, 0, 0, long_data, sizeof(long_data));
    check(ret == OSSL_TRACE_STRING_MAX + 1, "also when masked");
    show("limited and masked", ret, mem);
    ret = OSSL_trace_string(mem, 1, 1, long_data, sizeof(long_data));
    check(ret == (int)sizeof(long_data), "full prints it all");
    show("full", ret, mem);
    ret = OSSL_trace_string(mem, 0, 0, long_data, OSSL_TRACE_STRING_MAX);
    check(ret == OSSL_TRACE_STRING_MAX + 1, "exactly the limit isn't cut");
    show("at the limit", ret, mem);
    ret = OSSL_trace_string(mem, 0, 0, (const unsigned char *)"", 0);
    check(ret == 1, "masking nothing gives a newline");
    show("empty masked", ret, mem);
    ret = OSSL_trace_string(mem, 1, 0, (const unsigned char *)"", 0);
    check(ret == 0, "printing nothing as text writes nothing");
    show("empty text", ret, mem);
    ERR_clear_error();
    ret = OSSL_trace_string(mem, 1, 0, NULL, 3);
    check(ret == 3, "NULL text prints the start of BIO_printf's placeholder");
    show("null text", ret, mem);
    ret = OSSL_trace_string(NULL, 1, 0, (const unsigned char *)"x", 1);
    printf("# null BIO: %d, error %d/%d\n", ret, ERR_GET_LIB(ERR_peek_last_error()),
           ERR_GET_REASON(ERR_peek_last_error()));
    check(ret <= 0, "a NULL BIO fails as BIO_write does");
    ERR_clear_error();
    BIO_free(mem);
}

int main(void)
{
    categories();
    disabled();
    strings();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
