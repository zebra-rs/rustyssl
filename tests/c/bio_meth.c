/*
 * Conformance test for application-defined BIOs and BIO callbacks (BIO_meth_new(3),
 * BIO_get_data(3), BIO_set_callback_ex(3), BIO_get_ex_new_index(3), BIO_get_new_index), in TAP
 * format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). The callbacks log
 * what they see, and the log is compared exactly.
 */
/* BIO_set_callback and the BIO_meth_get_* functions are deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
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

static char trace[2048];

static void note(const char *fmt, long a, long b, long c)
{
    size_t n = strlen(trace);

    if (n + 64 < sizeof(trace))
        snprintf(trace + n, sizeof(trace) - n, fmt, a, b, c);
}

/* A method keeping what is written in a 64-byte store behind BIO_get_data. */
typedef struct {
    char data[64];
    int len;
} STORE;

static STORE store;
static int created, destroyed;

static int store_create(BIO *b)
{
    created++;
    BIO_set_data(b, &store);
    BIO_set_init(b, 1);
    return 1;
}

static int store_destroy(BIO *b)
{
    destroyed++;
    BIO_set_data(b, NULL);
    return 1;
}

static int store_write(BIO *b, const char *in, int len)
{
    STORE *s = BIO_get_data(b);

    note("write(%ld) ", len, 0, 0);
    if (s->len + len > (int)sizeof(s->data)) {
        BIO_set_retry_write(b);
        return -1;
    }
    memcpy(s->data + s->len, in, len);
    s->len += len;
    return len;
}

static int store_read_ex(BIO *b, char *out, size_t len, size_t *done)
{
    STORE *s = BIO_get_data(b);
    size_t n = len < (size_t)s->len ? len : (size_t)s->len;

    note("read_ex(%ld) ", (long)len, 0, 0);
    memcpy(out, s->data, n);
    memmove(s->data, s->data + n, s->len - n);
    s->len -= (int)n;
    *done = n;
    return n > 0;
}

static long store_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    STORE *s = BIO_get_data(b);

    (void)ptr;
    note("ctrl(%ld,%ld) ", cmd, num, 0);
    return cmd == BIO_CTRL_PENDING ? s->len : 0;
}

static int store_puts(BIO *b, const char *str)
{
    return store_write(b, str, (int)strlen(str));
}

static int sent_msgs(BIO *b, BIO_MSG *msg, size_t stride, size_t num, uint64_t flags,
                     size_t *done)
{
    (void)b;
    (void)msg;
    (void)stride;
    (void)flags;
    note("sendmmsg(%ld) ", (long)num, 0, 0);
    *done = num;
    return 1;
}

static int received_msgs(BIO *b, BIO_MSG *msg, size_t stride, size_t num, uint64_t flags,
                         size_t *done)
{
    (void)b;
    (void)msg;
    (void)stride;
    (void)flags;
    note("recvmmsg(%ld) ", (long)num, 0, 0);
    *done = 0;
    return 0;
}

static int store_gets(BIO *b, char *buf, int size)
{
    (void)b;
    note("gets(%ld) ", size, 0, 0);
    if (size > 0)
        buf[0] = '\0';
    return 0;
}

static long store_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp)
{
    (void)b;
    note("callback_ctrl(%ld,%ld) ", cmd, fp == NULL ? 0 : 1, 0);
    return 1;
}

static void messages(void)
{
    BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK | 201, "messages");
    BIO *b;
    BIO_MSG msg[2];
    BIO_POLL_DESCRIPTOR desc;
    size_t done = 99;
    char buf[4];

    memset(msg, 0, sizeof(msg));
    check(BIO_meth_set_sendmmsg(m, sent_msgs) == 1 && BIO_meth_set_recvmmsg(m, received_msgs) == 1
          && BIO_meth_set_gets(m, store_gets) == 1
          && BIO_meth_set_callback_ctrl(m, store_callback_ctrl) == 1
          && BIO_meth_set_ctrl(m, store_ctrl) == 1 && BIO_meth_set_create(m, store_create) == 1,
          "BIO_meth_set_sendmmsg, _recvmmsg, _gets, _callback_ctrl");
    check(BIO_meth_get_sendmmsg(m) == sent_msgs && BIO_meth_get_recvmmsg(m) == received_msgs
          && BIO_meth_get_gets(m) == store_gets
          && BIO_meth_get_callback_ctrl(m) == store_callback_ctrl, "and their getters");
    b = BIO_new(m);
    trace[0] = '\0';
    check(BIO_sendmmsg(b, msg, sizeof(msg[0]), 2, 0, &done) == 1 && done == 2,
          "BIO_sendmmsg calls the method");
    check(BIO_recvmmsg(b, msg, sizeof(msg[0]), 2, 0, &done) == 0 && done == 0,
          "BIO_recvmmsg calls the method");
    check(BIO_gets(b, buf, sizeof(buf)) == 0 && BIO_callback_ctrl(b, BIO_CTRL_SET_CALLBACK, NULL) == 1,
          "BIO_gets and BIO_callback_ctrl call the method");
    check(BIO_get_rpoll_descriptor(b, &desc) == 0 && BIO_get_wpoll_descriptor(b, &desc) == 0,
          "BIO_get_rpoll_descriptor and _wpoll_descriptor ask the method's ctrl");
    check(strcmp(trace, "sendmmsg(2) recvmmsg(2) gets(4) callback_ctrl(14,0) ctrl(91,0) ctrl(92,0) ")
          == 0, "in order");
    store.len = 0;
    BIO_free(b);
    b = BIO_new(BIO_s_mem());
    done = 99;
    check(BIO_sendmmsg(b, msg, sizeof(msg[0]), 1, 0, &done) == 0 && done == 0
          && BIO_recvmmsg(b, msg, sizeof(msg[0]), 1, 0, &done) == 0,
          "a memory BIO has no message functions");
    ERR_clear_error();
    BIO_set_shutdown(b, 0);
    check(BIO_get_shutdown(b) == 0, "BIO_set_shutdown");
    BIO_set_shutdown(b, 1);
    BIO_free(b);
    BIO_meth_free(m);
}

static void methods(void)
{
    int type = BIO_get_new_index();
    BIO_METHOD *m = BIO_meth_new(type | BIO_TYPE_SOURCE_SINK, "store");
    BIO *b;
    char buf[16];
    size_t done = 0;

    check(type == BIO_TYPE_START + 1 && BIO_get_new_index() == BIO_TYPE_START + 2,
          "BIO_get_new_index: from BIO_TYPE_START + 1");
    check(m != NULL, "BIO_meth_new");
    check(BIO_meth_set_write(m, store_write) == 1 && BIO_meth_set_read_ex(m, store_read_ex) == 1
          && BIO_meth_set_puts(m, store_puts) == 1 && BIO_meth_set_ctrl(m, store_ctrl) == 1
          && BIO_meth_set_create(m, store_create) == 1
          && BIO_meth_set_destroy(m, store_destroy) == 1, "BIO_meth_set_*");
    check(BIO_meth_get_write(m) == store_write && BIO_meth_get_read_ex(m) == store_read_ex
          && BIO_meth_get_read(m) == NULL && BIO_meth_get_write_ex(m) != NULL
          && BIO_meth_get_puts(m) == store_puts && BIO_meth_get_gets(m) == NULL
          && BIO_meth_get_ctrl(m) == store_ctrl && BIO_meth_get_create(m) == store_create
          && BIO_meth_get_destroy(m) == store_destroy && BIO_meth_get_callback_ctrl(m) == NULL,
          "BIO_meth_get_*: an _ex setter clears the other, a plain one adds a converter");

    b = BIO_new(m);
    check(b != NULL && created == 1 && BIO_get_data(b) == &store && BIO_get_init(b) == 1
          && BIO_method_type(b) == (type | BIO_TYPE_SOURCE_SINK) && same(BIO_method_name(b), "store"),
          "BIO_new runs create");
    trace[0] = '\0';
    check(BIO_write(b, "hello", 5) == 5 && BIO_puts(b, " you") == 4 && BIO_pending(b) == 9,
          "writing through the method");
    check(BIO_read(b, buf, 3) == 3 && memcmp(buf, "hel", 3) == 0
          && BIO_read_ex(b, buf, 16, &done) == 1 && done == 6, "reading through the method");
    check(same(trace, "write(5) write(4) ctrl(10,0) read_ex(3) read_ex(16) "),
          "the method's functions are called in order");
    check(BIO_gets(b, buf, 4) == -2, "BIO_gets: the method has none");
    check(ERR_GET_REASON(ERR_get_error()) == BIO_R_UNSUPPORTED_METHOD,
          "BIO_R_UNSUPPORTED_METHOD");
    check(BIO_write(b, "0123456789012345678901234567890123456789012345678901234567890123456789",
                    70) == -1 && BIO_should_retry(b) && BIO_should_write(b),
          "retry flags the method sets");
    store.len = 0;
    BIO_free(b);
    check(destroyed == 1, "BIO_free runs destroy");
    BIO_meth_free(m);
    BIO_meth_free(NULL);

    m = BIO_meth_new(BIO_TYPE_SOURCE_SINK | 200, "lazy");
    b = BIO_new(m);
    check(b != NULL && BIO_get_init(b) == 1, "without create, a new BIO is initialized");
    check(BIO_write(b, "x", 1) == -2 && BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL) == -2,
          "with no write or ctrl, those fail with -2");
    ERR_clear_error();
    BIO_free(b);
    BIO_meth_set_create(m, store_destroy);
    b = BIO_new(m);
    check(b != NULL && BIO_get_init(b) == 0 && BIO_read(b, buf, 1) == -2,
          "with create, init stays 0 until the BIO sets it");
    BIO_meth_set_read(m, (int (*)(BIO *, char *, int))store_write);
    ERR_clear_error();
    check(BIO_read(b, buf, 1) == -1 && ERR_GET_REASON(ERR_get_error()) == BIO_R_UNINITIALIZED,
          "an uninitialized BIO can't be read");
    BIO_free(b);
    BIO_meth_free(m);
    check(BIO_meth_new(1, NULL) == NULL, "BIO_meth_new: a null name fails");

    m = BIO_meth_new(BIO_TYPE_SOURCE_SINK | 202, "ex");
    check(BIO_meth_set_write(m, store_write) == 1 && BIO_meth_set_write_ex(m, NULL) == 1
          && BIO_meth_get_write(m) == NULL && BIO_meth_get_write_ex(m) == NULL,
          "BIO_meth_set_write_ex clears the plain write");
    b = BIO_new_ex(NULL, m);
    check(b != NULL && BIO_write(b, "x", 1) == -2, "BIO_new_ex; no write at all now");
    ERR_clear_error();
    BIO_free(b);
    BIO_meth_free(m);
}

static long callback_ex(BIO *b, int oper, const char *argp, size_t len, int argi, long argl,
                        int ret, size_t *processed)
{
    (void)b;
    (void)argp;
    note("[%lx %ld ", oper, (long)len, 0);
    note("%ld %ld ", argi, argl, 0);
    note("%ld %ld]", ret, processed == NULL ? -1 : (long)*processed, 0);
    if (oper == BIO_CB_WRITE && len == 4)
        return 0;
    return ret;
}

static long callback_old(BIO *b, int oper, const char *argp, int argi, long argl, long ret)
{
    (void)b;
    (void)argp;
    note("(%lx %ld ", oper, argi, 0);
    note("%ld %ld)", argl, ret, 0);
    return ret;
}

static void callbacks(void)
{
    BIO *b = BIO_new(BIO_s_mem());
    char buf[8];
    char arg[] = "arg";

    BIO_set_callback_ex(b, callback_ex);
    BIO_set_callback_arg(b, arg);
    check(BIO_get_callback_ex(b) == callback_ex && BIO_get_callback_arg(b) == arg,
          "BIO_get_callback_ex and BIO_get_callback_arg");
    trace[0] = '\0';
    BIO_write(b, "abc", 3);
    BIO_read(b, buf, 2);
    BIO_puts(b, "xy");
    BIO_gets(b, buf, 8);
    BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL);
    printf("# callback_ex: %s\n", trace);
    check(strstr(trace, "[3 3 0 0 1 -1][83 3 0 0 1 3]") != NULL,
          "the write callback before and after, with the count");
    trace[0] = '\0';
    check(BIO_write(b, "vetoed", 4) == 0 && BIO_pending(b) == 0,
          "a callback returning 0 stops the operation");
    trace[0] = '\0';
    BIO_free(b);
    check(same(trace, "[1 0 0 0 1 -1]"), "BIO_free calls the callback");

    b = BIO_new(BIO_s_mem());
    BIO_set_callback(b, callback_old);
    check(BIO_get_callback(b) == callback_old, "BIO_get_callback");
    trace[0] = '\0';
    BIO_write(b, "abcd", 4);
    BIO_read(b, buf, 3);
    BIO_ctrl(b, BIO_CTRL_PENDING, 5, NULL);
    BIO_free(b);
    printf("# old-style callback: %s\n", trace);
    check(same(trace, "(3 4 0 1)(83 4 0 4)(2 3 0 1)(82 3 0 3)(6 10 5 1)(86 10 5 1)(1 0 0 1)"),
          "the old-style callback gets the length in argi and the count in ret");
}

static int ex_new_calls, ex_free_calls;

static void ex_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent;
    (void)ptr;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;
    ex_new_calls++;
}

static void ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;
    if (ptr != NULL)
        ex_free_calls++;
}

static void ex_data(void)
{
    int idx = BIO_get_ex_new_index(0, NULL, ex_new, NULL, ex_free);
    BIO *b = BIO_new(BIO_s_mem());
    int value;

    check(idx >= 1 && ex_new_calls == 1, "BIO_get_ex_new_index; BIO_new runs the new callback");
    check(BIO_set_ex_data(b, idx, &value) == 1 && BIO_get_ex_data(b, idx) == &value
          && BIO_get_ex_data(b, idx + 5) == NULL, "BIO_set_ex_data and BIO_get_ex_data");
    BIO_free(b);
    check(ex_free_calls == 1, "BIO_free frees the ex_data");
}

int main(void)
{
    methods();
    messages();
    callbacks();
    ex_data();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures != 0;
}
