/*
 * Conformance test for the error queue (ERR_raise(3), ERR_get_error(3), ERR_set_mark(3),
 * ERR_add_error_data(3), ERR_print_errors(3), ERR_error_string(3), ERR_load_strings(3),
 * OSSL_ERR_STATE_save(3)), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). Error strings are
 * compared byte for byte; the file names and lines are this file's, from the macros.
 */
#define _POSIX_C_SOURCE 200809L
/* ERR_get_state, the _line_data variants, ERR_put_error, and the legacy loaders are deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bnerr.h>
#include <openssl/crypto.h>
#include <openssl/decodererr.h>
#include <openssl/encodererr.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/sslerr.h>

/* Exported, but declared only in OpenSSL's internal headers. */
void err_free_strings_int(void);

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

/* The number of errors on the queue, which it empties. */
static int drain(void)
{
    int n = 0;

    while (ERR_get_error() != 0)
        n++;
    return n;
}

static const unsigned long BUF_INVALID = ERR_PACK(ERR_LIB_BUF, 0, ERR_R_PASSED_INVALID_ARGUMENT);
static int raised_line;

static void raise_buf_error(void)
{
    raised_line = __LINE__ + 1;
    ERR_raise(ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT);
}

/* Raising and reading. */

static void reading(void)
{
    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = -1;
    unsigned long e;

    check(ERR_get_error() == 0 && ERR_peek_error() == 0 && ERR_peek_last_error() == 0,
          "ERR_get_error, ERR_peek_error, ERR_peek_last_error: 0 on an empty queue");
    raise_buf_error();
    ERR_raise(ERR_LIB_SYS, ENOENT);
    e = ERR_peek_last_error();
    check(ERR_peek_error() == BUF_INVALID, "ERR_raise: ERR_peek_error returns the oldest error");
    check(e == (ERR_SYSTEM_FLAG | ENOENT) && ERR_SYSTEM_ERROR(e) && ERR_GET_LIB(e) == ERR_LIB_SYS
          && ERR_GET_REASON(e) == ENOENT,
          "ERR_raise(ERR_LIB_SYS, errno): a system error, newest");

    e = ERR_peek_error_all(&file, &line, &func, &data, &flags);
    check(e == BUF_INVALID && same(file, __FILE__) && line == raised_line
          && same(func, "raise_buf_error") && same(data, "") && flags == 0,
          "ERR_peek_error_all: file, line, and function from ERR_raise; no data");
    file = func = NULL;
    line = 0;
    check(ERR_peek_error_line(&file, &line) == BUF_INVALID && same(file, __FILE__)
          && line == raised_line, "ERR_peek_error_line");
    check(ERR_peek_error_func(&func) == BUF_INVALID && same(func, "raise_buf_error"),
          "ERR_peek_error_func");
    flags = -1;
    check(ERR_peek_error_data(&data, &flags) == BUF_INVALID && same(data, "") && flags == 0,
          "ERR_peek_error_data: \"\" and 0 without data");
    flags = -1;
    check(ERR_peek_error_line_data(&file, &line, &data, &flags) == BUF_INVALID
          && line == raised_line && same(data, "") && flags == 0, "ERR_peek_error_line_data");
    check(ERR_peek_last_error_line(&file, &line) == (ERR_SYSTEM_FLAG | ENOENT)
          && same(file, __FILE__) && line > raised_line, "ERR_peek_last_error_line");
    check(ERR_peek_last_error_func(&func) == (ERR_SYSTEM_FLAG | ENOENT) && same(func, "reading"),
          "ERR_peek_last_error_func");
    check(ERR_peek_last_error_data(&data, &flags) == (ERR_SYSTEM_FLAG | ENOENT)
          && same(data, "") && flags == 0, "ERR_peek_last_error_data");
    check(ERR_peek_last_error_line_data(&file, &line, &data, &flags) == (ERR_SYSTEM_FLAG | ENOENT)
          && ERR_peek_last_error_all(&file, &line, &func, &data, &flags)
                 == (ERR_SYSTEM_FLAG | ENOENT), "ERR_peek_last_error_line_data and _all");
    check(ERR_peek_error_all(NULL, NULL, NULL, NULL, NULL) == BUF_INVALID,
          "ERR_peek_error_all: every output may be null");

    check(ERR_get_error_all(&file, &line, &func, &data, &flags) == BUF_INVALID
          && same(func, "raise_buf_error") && ERR_peek_error() == (ERR_SYSTEM_FLAG | ENOENT),
          "ERR_get_error_all: removes the oldest error");
    check(ERR_get_error_line(&file, &line) == (ERR_SYSTEM_FLAG | ENOENT) && ERR_get_error() == 0,
          "ERR_get_error_line: removes the next one");

    ERR_put_error(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO, "put.c", 7);
    check(ERR_get_error_line_data(&file, &line, &data, &flags)
              == ERR_PACK(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO)
          && same(file, "put.c") && line == 7 && same(data, "") && flags == 0,
          "ERR_put_error and ERR_get_error_line_data");

    ERR_new();
    ERR_set_debug(NULL, 0, NULL);
    ERR_set_error(ERR_LIB_BN, BN_R_DIV_BY_ZERO, NULL);
    check(ERR_peek_error_all(&file, &line, &func, NULL, NULL) == ERR_PACK(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO)
          && same(file, "") && line == 0 && same(func, ""),
          "ERR_set_debug: a null file and function read back as \"\"");
    ERR_set_debug("", 5, "");
    check(ERR_peek_error_all(&file, &line, &func, NULL, NULL) != 0 && same(file, "") && line == 5
          && same(func, ""), "ERR_set_debug: changes the newest error");
    ERR_set_error(ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT | ERR_SYSTEM_FLAG, NULL);
    check(ERR_peek_error() == BUF_INVALID,
          "ERR_set_error: replaces the newest error's code; the reason is masked");
    ERR_clear_error();
    check(ERR_peek_error() == 0, "ERR_clear_error");
}

static void vset(int lib, int reason, ...)
{
    va_list args;

    va_start(args, reason);
    ERR_vset_error(lib, reason, NULL, args);
    va_end(args);
}

static void vadd(int num, ...)
{
    va_list args;

    va_start(args, num);
    ERR_add_error_vdata(num, args);
    va_end(args);
}

/* Data attached to errors. */

static void attaching(void)
{
    static char fixed[] = "fixed text";
    const char *data = NULL;
    char *owned = OPENSSL_malloc(6);
    char longer[301];
    int flags = 0;

    ERR_new();
    vset(ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT);
    check(ERR_peek_error() == BUF_INVALID, "ERR_vset_error without a format");

    ERR_set_error_data(fixed, ERR_TXT_STRING);
    check(ERR_peek_error_data(&data, &flags) == BUF_INVALID && data == fixed
          && flags == ERR_TXT_STRING, "ERR_set_error_data: a string the caller keeps");
    ERR_add_error_data(3, "one", NULL, "three");
    check(ERR_peek_error_data(&data, &flags) != 0 && same(data, "one<NULL>three")
          && flags == (ERR_TXT_MALLOCED | ERR_TXT_STRING),
          "ERR_add_error_data: replaces data it doesn't own, null as <NULL>");
    ERR_add_error_data(1, "+four");
    vadd(2, "+", "five");
    check(ERR_peek_error_data(&data, &flags) != 0 && same(data, "one<NULL>three+four+five"),
          "ERR_add_error_data and ERR_add_error_vdata: append to data they own");
    memset(longer, 'x', 300);
    longer[300] = '\0';
    ERR_add_error_data(1, longer);
    check(ERR_peek_error_data(&data, &flags) != 0 && strlen(data) == 324
          && strncmp(data, "one<NULL>three+four+fivexxx", 27) == 0 && data[323] == 'x',
          "ERR_add_error_data: grows past its first buffer");

    if (owned != NULL)
        memcpy(owned, "owned", 6);
    ERR_set_error_data(owned, ERR_TXT_STRING | ERR_TXT_MALLOCED);
    check(ERR_peek_error_data(&data, &flags) != 0 && data == owned
          && flags == (ERR_TXT_STRING | ERR_TXT_MALLOCED),
          "ERR_set_error_data: takes over allocated data");
    ERR_set_error_data(fixed, 0);
    check(ERR_peek_error_data(&data, &flags) != 0 && data == fixed && flags == 0,
          "ERR_set_error_data: data that isn't a string");
    flags = 1;
    check(ERR_get_error_all(NULL, NULL, NULL, &data, &flags) == BUF_INVALID && data == fixed
          && flags == 0, "ERR_get_error_all: returns the data");

    ERR_add_error_txt(NULL, "orphan");
    check(ERR_peek_last_error_data(&data, &flags) == ERR_PACK(ERR_LIB_NONE, 0, 0)
          && same(data, "orphan"), "ERR_add_error_txt: on an empty queue, raises an error");
    ERR_add_error_txt(", ", "a, b");
    ERR_add_error_txt(", ", "c, ");
    check(ERR_peek_last_error_data(&data, &flags) != 0 && same(data, "orphan, a, b, c"),
          "ERR_add_error_txt: separators between pieces, a trailing one dropped");
    ERR_clear_error();
}

static void splitting(void)
{
    char *text = malloc(5001);
    const char *data, *file, *func;
    int flags, line;
    unsigned long first, second;

    if (text == NULL) {
        check(0, "malloc");
        return;
    }
    memset(text, 'y', 5000);
    text[5000] = '\0';
    raise_buf_error();
    ERR_add_error_txt("", text);
    check(ERR_count_to_mark() == 2, "ERR_add_error_txt: long text spills into a second error");
    first = ERR_get_error_all(NULL, NULL, NULL, &data, &flags);
    check(first == BUF_INVALID && strlen(data) == 3995,
          "ERR_add_error_txt: fills the first error's data up to its limit");
    second = ERR_get_error_all(&file, &line, &func, &data, &flags);
    check(second == BUF_INVALID && strlen(data) == 1005 && same(file, __FILE__)
          && line == raised_line && same(func, "raise_buf_error"),
          "ERR_add_error_txt: the second error repeats the first's code and origin");
    memset(text, 'z', 5000);
    memcpy(text + 3000, ";", 1);
    memcpy(text + 4100, ";", 1);
    raise_buf_error();
    ERR_add_error_txt(";", text);
    first = ERR_get_error_all(NULL, NULL, NULL, &data, &flags);
    check(strlen(data) == 3002 && data[0] == ';' && data[3001] == ';',
          "ERR_add_error_txt: splits after a separator, and starts with one");
    second = ERR_get_error_all(NULL, NULL, NULL, &data, &flags);
    check(first == second && strlen(data) == 1999 && ERR_get_error() == 0,
          "ERR_add_error_txt: the rest goes to the next error");
    free(text);
}

/* The ring holds ERR_NUM_ERRORS - 1 errors. */

static void ring(void)
{
    unsigned long e;

    for (int i = 1; i <= 20; i++)
        ERR_raise(ERR_LIB_BN, i);
    e = ERR_peek_error();
    check(ERR_GET_REASON(e) == 6 && ERR_GET_REASON(ERR_peek_last_error()) == 20,
          "a full queue drops the oldest errors");
    check(drain() == ERR_NUM_ERRORS - 1, "the queue holds ERR_NUM_ERRORS - 1 errors");
}

/* Marks. */

static void marks(void)
{
    check(ERR_set_mark() == 0 && ERR_count_to_mark() == 0 && ERR_pop_to_mark() == 0
          && ERR_clear_last_mark() == 0 && ERR_pop() == 0,
          "ERR_set_mark, _count_to_mark, _pop_to_mark, _clear_last_mark, ERR_pop: empty queue");
    ERR_raise(ERR_LIB_BN, 1);
    check(ERR_set_mark() == 1, "ERR_set_mark: marks the newest error");
    ERR_raise(ERR_LIB_BN, 2);
    ERR_raise(ERR_LIB_BN, 3);
    check(ERR_count_to_mark() == 2, "ERR_count_to_mark: errors after the mark");
    check(ERR_pop_to_mark() == 1 && ERR_GET_REASON(ERR_peek_last_error()) == 1
          && ERR_count_to_mark() == 1,
          "ERR_pop_to_mark: removes errors after the mark, and the mark");
    ERR_set_mark();
    ERR_set_mark();
    ERR_raise(ERR_LIB_BN, 2);
    check(ERR_clear_last_mark() == 1 && ERR_count_to_mark() == 1,
          "ERR_clear_last_mark: removes one mark, keeps the errors");
    check(ERR_pop_to_mark() == 1 && ERR_GET_REASON(ERR_peek_last_error()) == 1,
          "ERR_pop_to_mark: a second mark on the same error");
    check(ERR_pop_to_mark() == 0 && ERR_peek_error() == 0,
          "ERR_pop_to_mark: without a mark, empties the queue and returns 0");
    ERR_raise(ERR_LIB_BN, 1);
    ERR_raise(ERR_LIB_BN, 2);
    check(ERR_pop() == 1 && ERR_GET_REASON(ERR_peek_last_error()) == 1 && ERR_pop() == 1
          && ERR_pop() == 0, "ERR_pop: removes the newest error");
}

/* Strings. */

static void strings(void)
{
    char buf[256], small[20];
    char *s;

    ERR_error_string_n(BUF_INVALID, buf, sizeof(buf));
    check(same(buf, "error:03880106:memory buffer routines::passed invalid argument"),
          "ERR_error_string_n: library and common reason");
    ERR_error_string_n(ERR_PACK(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO), buf, sizeof(buf));
    check(same(buf, "error:01800067:bignum routines::div by zero"),
          "ERR_error_string_n: a library's own reason");
    ERR_error_string_n(ERR_SYSTEM_FLAG | ENOENT, buf, sizeof(buf));
    snprintf(small, sizeof(small), "%s", strerror(ENOENT));
    check(strncmp(buf, "error:80000002:system library::", 31) == 0 && same(buf + 31, strerror(ENOENT)),
          "ERR_error_string_n: system errors use strerror");
    ERR_error_string_n(ERR_PACK(ERR_LIB_SSL, 0, ERR_R_SSL_LIB), buf, sizeof(buf));
    check(same(buf, "error:0A080014:SSL routines::reason(20)"),
          "ERR_error_string_n: an unknown reason without its flags");
    ERR_error_string_n(ERR_PACK(100, 0, 5), buf, sizeof(buf));
    check(same(buf, "error:32000005:lib(100)::reason(5)"), "ERR_error_string_n: an unknown library");
    ERR_error_string_n(0, buf, sizeof(buf));
    check(same(buf, "error:00000000:lib(0)::reason(0)"), "ERR_error_string_n: 0");
    ERR_error_string_n(BUF_INVALID, small, sizeof(small));
    check(same(small, "err:3880106:7:0:801"),
          "ERR_error_string_n: the short form when the long one doesn't fit");
    memset(small, '#', sizeof(small));
    ERR_error_string_n(BUF_INVALID, small, 5);
    check(same(small, "err:") && small[5] == '#', "ERR_error_string_n: truncates to the length");
    ERR_error_string_n(BUF_INVALID, small, 1);
    check(small[0] == '\0' && small[1] == 'r', "ERR_error_string_n: length 1");
    ERR_error_string_n(BUF_INVALID, small, 0);
    check(small[0] == '\0' && small[1] == 'r', "ERR_error_string_n: length 0 writes nothing");
    s = ERR_error_string(BUF_INVALID, NULL);
    check(same(s, "error:03880106:memory buffer routines::passed invalid argument")
          && ERR_error_string(0, NULL) == s, "ERR_error_string: a static buffer");
    check(ERR_error_string(BUF_INVALID, buf) == buf
          && same(buf, "error:03880106:memory buffer routines::passed invalid argument"),
          "ERR_error_string: the caller's buffer");

    check(same(ERR_lib_error_string(BUF_INVALID), "memory buffer routines")
          && same(ERR_lib_error_string(ERR_SYSTEM_FLAG | 1), "system library")
          && same(ERR_lib_error_string(ERR_PACK(ERR_LIB_NONE, 0, 0)), "unknown library")
          && ERR_lib_error_string(ERR_PACK(100, 0, 0)) == NULL,
          "ERR_lib_error_string");
    check(same(ERR_reason_error_string(BUF_INVALID), "passed invalid argument")
          && same(ERR_reason_error_string(ERR_R_MALLOC_FAILURE), "malloc failure")
          && same(ERR_reason_error_string(ERR_PACK(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO)), "div by zero")
          && ERR_reason_error_string(ERR_SYSTEM_FLAG | ENOENT) == NULL
          && ERR_reason_error_string(ERR_PACK(ERR_LIB_BUF, 0, 99)) == NULL,
          "ERR_reason_error_string: the library's, else the common one; none for system errors");
    check(ERR_func_error_string(BUF_INVALID) == NULL, "ERR_func_error_string: always null");
    check(same(ERR_reason_error_string(ERR_PACK(ERR_LIB_PROV, 0, PROV_R_ALGORITHM_MISMATCH)),
               "algorithm mismatch"),
          "ERR_reason_error_string: the provider reasons are loaded with libcrypto's");
    check(same(ERR_lib_error_string(ERR_PACK(ERR_LIB_OSSL_ENCODER, 0, 0)), "ENCODER routines")
          && ERR_reason_error_string(ERR_PACK(ERR_LIB_OSSL_ENCODER, 0,
                                              OSSL_ENCODER_R_ENCODER_NOT_FOUND)) == NULL
          && ERR_reason_error_string(ERR_PACK(ERR_LIB_OSSL_DECODER, 0,
                                              OSSL_DECODER_R_DECODER_NOT_FOUND)) == NULL,
          "ERR_reason_error_string: the encoder and decoder reasons are never loaded");
    check(same(ERR_lib_error_string(ERR_PACK(ERR_LIB_SSL, 0, 0)), "SSL routines")
          && ERR_reason_error_string(ERR_PACK(ERR_LIB_SSL, 0, SSL_R_BAD_DATA)) == NULL,
          "ERR_reason_error_string: the SSL reasons aren't loaded with libcrypto's");
}

/* Libraries the application defines. */

/* The library's own entry is packed when the library number is known. */
static ERR_STRING_DATA app_strings[] = {
    { 0, "application library" },
    { 1, "first reason" },
    { 2, "second reason" },
    { 0, NULL },
};

static ERR_STRING_DATA app_const[] = {
    { ERR_PACK(ERR_LIB_BN, 0, 99), "a reason added to BN" },
    { 0, NULL },
};

static void applications(void)
{
    int lib = ERR_get_next_error_library();
    char buf[256];

    check(lib == ERR_LIB_USER && ERR_get_next_error_library() == ERR_LIB_USER + 1,
          "ERR_get_next_error_library: counts up from ERR_LIB_USER");
    check(ERR_load_strings(lib, app_strings) == 1 && app_strings[1].error == 1
          && ERR_reason_error_string(ERR_PACK(lib, 0, 1)) == NULL,
          "ERR_load_strings: a table that starts with 0 is empty");
    app_strings[0].error = ERR_PACK(lib, 0, 0);
    check(ERR_load_strings(lib, app_strings) == 1 && app_strings[1].error == ERR_PACK(lib, 0, 1)
          && app_strings[0].error == ERR_PACK(lib, 0, 0),
          "ERR_load_strings: packs the library into the caller's table");
    check(ERR_reason_error_string(ERR_PACK(lib, 0, 2)) == app_strings[2].string
          && ERR_lib_error_string(ERR_PACK(lib, 0, 2)) == app_strings[0].string,
          "ERR_load_strings: the strings are the caller's");
    ERR_error_string_n(ERR_PACK(lib, 0, 1), buf, sizeof(buf));
    check(same(buf, "error:40000001:application library::first reason"),
          "ERR_error_string_n: an application library");
    check(ERR_load_strings_const(app_const) == 1
          && ERR_reason_error_string(ERR_PACK(ERR_LIB_BN, 0, 99)) == app_const[0].string,
          "ERR_load_strings_const: entries already packed");
    check(ERR_unload_strings(lib, app_strings) == 1
          && ERR_reason_error_string(ERR_PACK(lib, 0, 2)) == NULL
          && ERR_lib_error_string(ERR_PACK(lib, 0, 2)) == NULL,
          "ERR_unload_strings");
    check(ERR_unload_strings(0, app_const) == 1
          && ERR_reason_error_string(ERR_PACK(ERR_LIB_BN, 0, 99)) == NULL,
          "ERR_unload_strings: entries already packed");
}

/* Printing. */

static char printed[4][512];
static int calls;

static int collect(const char *str, size_t len, void *u)
{
    if (calls < 4 && len < sizeof(printed[0]) && strlen(str) == len)
        memcpy(printed[calls], str, len + 1);
    calls++;
    return u == NULL ? 1 : 0;
}

/* What ERR_print_errors prints before the error string: the thread ID's bytes in hex. */
static void thread_prefix(char *out, size_t size)
{
    pthread_t self = pthread_self();
    const unsigned char *bytes = (const unsigned char *)&self;
    size_t used = 0;

    for (size_t i = 0; i < sizeof(self) && used + 3 < size; i++)
        used += (size_t)snprintf(out + used, size - used, "%02X", bytes[i]);
    snprintf(out + used, size - used, ":");
}

static void printing(void)
{
    char prefix[64], expected[512], line[512] = "";
    FILE *f;

    thread_prefix(prefix, sizeof(prefix));
    raise_buf_error();
    ERR_add_error_data(1, "some data");
    ERR_raise(ERR_LIB_BN, BN_R_DIV_BY_ZERO);
    ERR_set_error_data((char *)"not a string", 0);
    calls = 0;
    ERR_print_errors_cb(collect, NULL);
    snprintf(expected, sizeof(expected),
             "%serror:03880106:memory buffer routines:raise_buf_error:passed invalid argument:%s:%d:"
             "some data\n", prefix, __FILE__, raised_line);
    check(calls == 2 && same(printed[0], expected), "ERR_print_errors_cb: the format");
    check(strstr(printed[1], ":bignum routines:printing:div by zero:") != NULL
          && strlen(printed[1]) > 2 && printed[1][strlen(printed[1]) - 2] == ':',
          "ERR_print_errors_cb: data that isn't a string isn't printed");
    check(ERR_peek_error() == 0, "ERR_print_errors_cb: empties the queue");

    ERR_raise(ERR_LIB_BN, 1);
    ERR_raise(ERR_LIB_BN, 2);
    calls = 0;
    ERR_print_errors_cb(collect, printed);
    check(calls == 1 && ERR_GET_REASON(ERR_get_error()) == 2,
          "ERR_print_errors_cb: stops when the callback returns 0");

    f = tmpfile();
    raise_buf_error();
    ERR_print_errors_fp(f);
    rewind(f);
    if (fgets(line, sizeof(line), f) == NULL)
        line[0] = '\0';
    fclose(f);
    snprintf(expected, sizeof(expected),
             "%serror:03880106:memory buffer routines:raise_buf_error:passed invalid argument:%s:%d:\n",
             prefix, __FILE__, raised_line);
    check(same(line, expected) && ERR_peek_error() == 0, "ERR_print_errors_fp");
}

/* Saving and restoring a queue. */

static void saving(void)
{
    ERR_STATE *saved = OSSL_ERR_STATE_new();
    const char *file, *func, *data;
    int line, flags;

    check(saved != NULL, "OSSL_ERR_STATE_new");
    raise_buf_error();
    ERR_add_error_data(1, "kept");
    ERR_raise(ERR_LIB_BN, 2);
    OSSL_ERR_STATE_save(saved);
    check(ERR_peek_error() == 0, "OSSL_ERR_STATE_save: takes the queue");
    OSSL_ERR_STATE_restore(saved);
    OSSL_ERR_STATE_restore(saved);
    check(ERR_get_error_all(&file, &line, &func, &data, &flags) == BUF_INVALID
          && same(file, __FILE__) && line == raised_line && same(func, "raise_buf_error")
          && same(data, "kept") && flags == (ERR_TXT_MALLOCED | ERR_TXT_STRING),
          "OSSL_ERR_STATE_restore: copies of the errors, with their details");
    check(drain() == 3, "OSSL_ERR_STATE_restore: adds the errors each time");

    ERR_raise(ERR_LIB_BN, 1);
    ERR_set_mark();
    ERR_raise(ERR_LIB_BN, 2);
    ERR_raise(ERR_LIB_BN, 3);
    OSSL_ERR_STATE_save_to_mark(saved);
    check(ERR_count_to_mark() == 0 && ERR_GET_REASON(ERR_peek_last_error()) == 1,
          "OSSL_ERR_STATE_save_to_mark: takes the errors after the mark");
    check(ERR_pop_to_mark() == 1 && ERR_GET_REASON(ERR_peek_last_error()) == 1,
          "OSSL_ERR_STATE_save_to_mark: leaves the mark");
    OSSL_ERR_STATE_restore(saved);
    check(ERR_GET_REASON(ERR_get_error()) == 1 && ERR_GET_REASON(ERR_get_error()) == 2
          && ERR_GET_REASON(ERR_get_error()) == 3 && ERR_get_error() == 0,
          "OSSL_ERR_STATE_restore: after the errors already there");
    OSSL_ERR_STATE_save_to_mark(saved);
    OSSL_ERR_STATE_restore(saved);
    check(ERR_peek_error() == 0, "OSSL_ERR_STATE_save_to_mark: an empty queue");
    OSSL_ERR_STATE_free(saved);
    OSSL_ERR_STATE_save(NULL);
    OSSL_ERR_STATE_save_to_mark(NULL);
    OSSL_ERR_STATE_restore(NULL);
    OSSL_ERR_STATE_free(NULL);
    check(1, "OSSL_ERR_STATE_*: null is ignored");
}

/* Each thread has its own queue. */

static unsigned long seen_in_thread;
static int thread_errors;

static void *in_thread(void *unused)
{
    (void)unused;
    seen_in_thread = ERR_peek_error();
    ERR_raise(ERR_LIB_BN, 4);
    OPENSSL_thread_stop();
    thread_errors = drain();
    ERR_raise(ERR_LIB_BN, 5);
    return NULL;
}

static void threads(void)
{
    pthread_t thread;
    ERR_STATE *state;

    ERR_raise(ERR_LIB_BN, 3);
    check(pthread_create(&thread, NULL, in_thread, NULL) == 0 && pthread_join(thread, NULL) == 0,
          "a second thread");
    check(seen_in_thread == 0 && ERR_GET_REASON(ERR_peek_error()) == 3,
          "each thread has its own queue");
    check(thread_errors == 0, "OPENSSL_thread_stop: frees the thread's errors");

    state = ERR_get_state();
    check(state != NULL && state->err_buffer[state->top] == ERR_PACK(ERR_LIB_BN, 0, 3)
          && state->top != state->bottom, "ERR_get_state: the thread's queue, in its public layout");
    errno = 1234;
    ERR_peek_error();
    ERR_raise(ERR_LIB_BN, 6);
    check(errno == 1234, "the queue functions keep errno");
    ERR_clear_error();
    ERR_remove_thread_state(NULL);
    ERR_remove_state(0);
    check(1, "ERR_remove_thread_state and ERR_remove_state do nothing");
}

/* Allocation failures. */

static void allocation(void)
{
    const char *file = NULL, *func = NULL;
    int line = 0;

    check(CRYPTO_malloc(SIZE_MAX, "alloc.c", 12) == NULL
          && ERR_get_error_all(&file, &line, &func, NULL, NULL)
                 == ERR_PACK(ERR_LIB_CRYPTO, 0, ERR_R_MALLOC_FAILURE)
          && same(file, "alloc.c") && line == 12 && same(func, "") && ERR_peek_error() == 0,
          "CRYPTO_malloc: a failure raises ERR_R_MALLOC_FAILURE with the caller's file and line");
    check(CRYPTO_zalloc(SIZE_MAX, NULL, 0) == NULL && CRYPTO_malloc(SIZE_MAX, NULL, 0) == NULL
          && ERR_peek_error() == 0, "CRYPTO_malloc: no error without a file or line");
    check(CRYPTO_secure_malloc(SIZE_MAX, "secure.c", 3) == NULL
          && ERR_get_error_line(&file, &line) == ERR_PACK(ERR_LIB_CRYPTO, 0, ERR_R_MALLOC_FAILURE)
          && same(file, "secure.c") && line == 3,
          "CRYPTO_secure_malloc: without a secure heap, as CRYPTO_malloc");
}

/* The deprecated loaders. */

static void loaders(void)
{
    check(ERR_load_ERR_strings() == 1 && ERR_load_ASN1_strings() == 1
          && ERR_load_ASYNC_strings() == 1 && ERR_load_BIO_strings() == 1
          && ERR_load_BN_strings() == 1 && ERR_load_BUF_strings() == 1
          && ERR_load_CMS_strings() == 1 && ERR_load_COMP_strings() == 1
          && ERR_load_CONF_strings() == 1 && ERR_load_CRYPTO_strings() == 1
          && ERR_load_CT_strings() == 1 && ERR_load_DH_strings() == 1
          && ERR_load_DSA_strings() == 1 && ERR_load_EC_strings() == 1
          && ERR_load_ENGINE_strings() == 1 && ERR_load_EVP_strings() == 1
          && ERR_load_KDF_strings() == 1 && ERR_load_OBJ_strings() == 1
          && ERR_load_OCSP_strings() == 1 && ERR_load_OSSL_STORE_strings() == 1
          && ERR_load_PEM_strings() == 1 && ERR_load_PKCS12_strings() == 1
          && ERR_load_PKCS7_strings() == 1 && ERR_load_RAND_strings() == 1
          && ERR_load_RSA_strings() == 1 && ERR_load_TS_strings() == 1
          && ERR_load_UI_strings() == 1 && ERR_load_X509_strings() == 1
          && ERR_load_X509V3_strings() == 1,
          "ERR_load_*_strings: return 1");
    ERR_free_strings();
    err_free_strings_int();
    check(ERR_load_crypto_strings() == 1
          && same(ERR_reason_error_string(ERR_R_MALLOC_FAILURE), "malloc failure"),
          "ERR_load_crypto_strings, ERR_free_strings, and err_free_strings_int");
}

int main(void)
{
    reading();
    attaching();
    splitting();
    ring();
    marks();
    strings();
    applications();
    printing();
    saving();
    threads();
    allocation();
    loaders();
    printf("1..%d\n", number);
    return failures != 0;
}
