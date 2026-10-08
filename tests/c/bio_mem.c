/*
 * Conformance test for the BIO object and the memory and null BIOs (BIO_new(3), BIO_read(3),
 * BIO_ctrl(3), BIO_s_mem(3), BIO_s_null(3), BIO_f_null(3), BIO_push(3), BIO_find_type(3)), in
 * TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
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

static unsigned long next_error(void)
{
    return ERR_get_error();
}

static void memory(void)
{
    BIO *b = BIO_new(BIO_s_mem());
    char buf[64];
    char *data = NULL;
    BUF_MEM *bm = NULL;
    size_t n = 0;

    check(b != NULL && BIO_method_type(b) == BIO_TYPE_MEM
          && same(BIO_method_name(b), "memory buffer"), "BIO_new(BIO_s_mem())");
    check(BIO_get_init(b) == 1 && BIO_get_shutdown(b) == 1 && BIO_pending(b) == 0
          && BIO_eof(b) == 1, "a new memory BIO: initialized, closing, empty");
    check(BIO_write(b, "hello ", 6) == 6 && BIO_puts(b, "world\n") == 6
          && BIO_write(b, "second line\nthird", 17) == 17,
          "BIO_write and BIO_puts");
    check(BIO_pending(b) == 29 && BIO_wpending(b) == 0 && BIO_eof(b) == 0
          && BIO_ctrl_pending(b) == 29 && BIO_ctrl_wpending(b) == 0,
          "BIO_pending counts what is unread");
    check(BIO_get_mem_data(b, &data) == 29 && memcmp(data, "hello world\n", 12) == 0,
          "BIO_get_mem_data");
    check(BIO_gets(b, buf, sizeof(buf)) == 12 && same(buf, "hello world\n"),
          "BIO_gets: up to and including the newline");
    check(BIO_gets(b, buf, 5) == 4 && same(buf, "seco"), "BIO_gets: up to size - 1");
    check(BIO_read(b, buf, 8) == 8 && memcmp(buf, "nd line\n", 8) == 0, "BIO_read");
    check(BIO_number_read(b) == 8 && BIO_number_written(b) == 29,
          "BIO_number_read and _written (BIO_gets isn't counted)");
    check(BIO_read_ex(b, buf, sizeof(buf), &n) == 1 && n == 5 && memcmp(buf, "third", 5) == 0,
          "BIO_read_ex");
    check(BIO_read(b, buf, 4) == -1 && BIO_should_retry(b) && BIO_should_read(b),
          "an empty memory BIO: -1, retry read");
    check(BIO_read_ex(b, buf, 4, &n) == 0 && n == 0, "BIO_read_ex on an empty BIO");
    (void)BIO_set_mem_eof_return(b, 0);
    check(BIO_read(b, buf, 4) == 0 && !BIO_should_retry(b), "BIO_set_mem_eof_return(0): EOF");
    check(BIO_gets(b, buf, sizeof(buf)) == 0 && buf[0] == '\0', "BIO_gets on an empty BIO");

    BIO_write(b, "abcdef", 6);
    check(BIO_get_mem_ptr(b, &bm) == 1 && bm != NULL && bm->length == 6
          && memcmp(bm->data, "abcdef", 6) == 0, "BIO_get_mem_ptr: the buffer, read data moved out");
    BIO_read(b, buf, 2);
    check(BIO_tell(b) == 2 && BIO_seek(b, 1) == 1 && BIO_pending(b) == 5
          && BIO_seek(b, 9) == -1, "BIO_seek and BIO_tell within the buffer");
    check(BIO_reset(b) == 1 && BIO_pending(b) == 0 && bm->length == 0,
          "BIO_reset clears a writable memory BIO");
    check(BIO_get_close(b) == 1 && BIO_set_close(b, BIO_NOCLOSE) == 1 && BIO_get_close(b) == 0,
          "BIO_get_close and BIO_set_close");
    (void)BIO_set_close(b, BIO_CLOSE);
    check(BIO_flush(b) == 1 && BIO_ctrl(b, BIO_CTRL_DUP, 0, NULL) == 1
          && BIO_ctrl(b, BIO_CTRL_PUSH, 0, NULL) == 0 && BIO_ctrl(b, 9999, 0, NULL) == 0,
          "BIO_ctrl: flush, dup, and unknown commands");
    check(BIO_write(b, "x", 0) == 0 && BIO_write(b, "x", -1) == 0 && BIO_read(b, buf, -1) == 0,
          "BIO_write and BIO_read: nothing for zero or negative lengths");
    ERR_clear_error();
    check(BIO_write_ex(b, "x", 0, &n) == 1 && n == 0, "BIO_write_ex: zero bytes succeed");
    BIO_free(b);

    bm = BUF_MEM_new();
    BUF_MEM_grow(bm, 4);
    memcpy(bm->data, "wxyz", 4);
    b = BIO_new(BIO_s_mem());
    check(BIO_set_mem_buf(b, bm, BIO_NOCLOSE) == 1 && BIO_pending(b) == 4
          && BIO_read(b, buf, 4) == 4 && memcmp(buf, "wxyz", 4) == 0,
          "BIO_set_mem_buf: reads the caller's buffer");
    BIO_free(b);
    check(bm->data != NULL, "BIO_NOCLOSE: the buffer survives BIO_free");
    BUF_MEM_free(bm);
}

static void read_only(void)
{
    static const char text[] = "line one\nline two\n";
    BIO *b = BIO_new_mem_buf(text, -1);
    char buf[32];
    char *data = NULL;

    check(b != NULL && BIO_test_flags(b, BIO_FLAGS_MEM_RDONLY) != 0 && BIO_pending(b) == 18,
          "BIO_new_mem_buf(-1): a read-only BIO over the string");
    check(BIO_gets(b, buf, sizeof(buf)) == 9 && same(buf, "line one\n"), "reading it");
    check(BIO_get_mem_data(b, &data) == 9 && data == text + 9, "it reads in place");
    ERR_clear_error();
    check(BIO_write(b, "x", 1) == -1
          && ERR_GET_REASON(next_error()) == BIO_R_WRITE_TO_READ_ONLY_BIO,
          "writing fails");
    check(BIO_reset(b) == 1 && BIO_pending(b) == 18, "BIO_reset rewinds a read-only BIO");
    check(BIO_read(b, buf, 32) == 18 && BIO_read(b, buf, 1) == 0 && !BIO_should_retry(b),
          "at its end it returns 0, without retrying");
    BIO_free(b);
    b = BIO_new_mem_buf(text, 4);
    check(BIO_pending(b) == 4, "BIO_new_mem_buf with a length");
    BIO_free(b);
    ERR_clear_error();
    check(BIO_new_mem_buf(NULL, 4) == NULL
          && ERR_GET_REASON(next_error()) == ERR_R_PASSED_NULL_PARAMETER,
          "BIO_new_mem_buf(NULL)");
}

static void secure(void)
{
    BIO *b = BIO_new(BIO_s_secmem());
    char buf[8];

    check(b != NULL && BIO_method_type(b) == BIO_TYPE_MEM
          && same(BIO_method_name(b), "secure memory buffer"), "BIO_s_secmem");
    check(BIO_write(b, "secret", 6) == 6 && BIO_read(b, buf, 8) == 6
          && memcmp(buf, "secret", 6) == 0, "it works like a memory BIO");
    BIO_free(b);
}

static void nulls(void)
{
    BIO *b = BIO_new(BIO_s_null());
    char buf[8] = "x";

    check(b != NULL && BIO_method_type(b) == BIO_TYPE_NULL && same(BIO_method_name(b), "NULL"),
          "BIO_s_null");
    check(BIO_write(b, "abc", 3) == 3 && BIO_puts(b, "abcd") == 4 && BIO_read(b, buf, 8) == 0
          && BIO_gets(b, buf, 8) == 0, "it swallows writes and reads nothing");
    check(BIO_reset(b) == 1 && BIO_eof(b) == 1 && BIO_pending(b) == 0 && BIO_get_close(b) == 0
          && BIO_flush(b) == 1, "its controls");
    BIO_free(b);

    ERR_clear_error();
    check(BIO_write(NULL, "x", 1) == 0 && ERR_peek_error() == 0,
          "BIO_write(NULL): 0, without an error");
    check(BIO_read(NULL, buf, 1) == -1
          && ERR_GET_REASON(next_error()) == ERR_R_PASSED_NULL_PARAMETER,
          "BIO_read(NULL): -1 with an error");
    check(BIO_puts(NULL, "x") == -1 && BIO_gets(NULL, buf, 2) == -1 && BIO_ctrl(NULL, 1, 0, NULL) == -1
          && BIO_free(NULL) == 0 && BIO_number_read(NULL) == 0 && BIO_next(NULL) == NULL,
          "other functions on NULL");
    ERR_clear_error();
}

static void chains(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *f1 = BIO_new(BIO_f_null()), *f2 = BIO_new(BIO_f_null());
    BIO *chain;
    char buf[16];
    int reason = -1;

    check(f1 != NULL && BIO_method_type(f1) == BIO_TYPE_NULL_FILTER
          && same(BIO_method_name(f1), "NULL filter"), "BIO_f_null");
    chain = BIO_push(f1, f2);
    check(chain == f1 && BIO_push(f1, mem) == f1 && BIO_next(f1) == f2 && BIO_next(f2) == mem
          && BIO_next(mem) == NULL, "BIO_push appends to the end of the chain");
    check(BIO_write(chain, "through", 7) == 7 && BIO_pending(mem) == 7 && BIO_pending(chain) == 7,
          "writes and controls pass through null filters");
    check(BIO_read(chain, buf, 3) == 3 && memcmp(buf, "thr", 3) == 0
          && BIO_gets(chain, buf, sizeof(buf)) == 4 && same(buf, "ough"),
          "reads and gets pass through too");
    check(BIO_find_type(chain, BIO_TYPE_MEM) == mem && BIO_find_type(chain, BIO_TYPE_NULL_FILTER) == f1
          && BIO_find_type(chain, BIO_TYPE_FILTER) == f1
          && BIO_find_type(chain, BIO_TYPE_SOURCE_SINK) == mem
          && BIO_find_type(chain, BIO_TYPE_FD) == NULL, "BIO_find_type: exact or by category");
    check(BIO_read(chain, buf, 1) == -1 && BIO_should_retry(chain) && BIO_should_read(chain)
          && BIO_get_retry_BIO(chain, &reason) == mem && reason == 0,
          "retry flags propagate; BIO_get_retry_BIO finds the source");
    BIO_clear_flags(f1, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
    BIO_copy_next_retry(f2);
    check(BIO_should_retry(f2) && BIO_should_read(f2) && !BIO_should_retry(f1),
          "BIO_copy_next_retry copies the next BIO's retry flags");
    check(BIO_pop(f2) == mem && BIO_next(f1) == mem && BIO_next(f2) == NULL,
          "BIO_pop unlinks a BIO from the middle");
    check(BIO_up_ref(mem) == 1, "BIO_up_ref");
    BIO_free_all(f1);
    check(BIO_write(mem, "still here", 10) == 10,
          "BIO_free_all stops at a BIO with another reference");
    BIO_free(mem);
    BIO_vfree(f2);

    mem = BIO_new(BIO_s_mem());
    BIO_set_next(f2 = BIO_new(BIO_f_null()), mem);
    check(BIO_next(f2) == mem, "BIO_set_next");
    BIO_free(f2);
    BIO_free(mem);
}

static void duplicating(void)
{
    BIO *mem = BIO_new(BIO_s_mem()), *f = BIO_new(BIO_f_null()), *copy;
    char buf[8];

    BIO_write(mem, "data", 4);
    BIO_set_flags(mem, 0x1000);
    copy = BIO_dup_chain(mem);
    check(copy != NULL && copy != mem && BIO_method_type(copy) == BIO_TYPE_MEM,
          "BIO_dup_chain: a memory BIO");
    check(BIO_pending(copy) == 0 && BIO_test_flags(copy, 0x1000) == 0x1000,
          "the copy has the flags, not the data");
    check(BIO_write(copy, "xy", 2) == 2 && BIO_read(copy, buf, 8) == 2 && BIO_pending(mem) == 4,
          "the copy is independent");
    BIO_free_all(copy);
    BIO_push(f, mem);
    check(BIO_dup_chain(f) == NULL, "BIO_dup_chain: the null filter refuses to be copied");
    BIO_free_all(f);
}

static void controls(void)
{
    BIO *b = BIO_new(BIO_s_mem());
    char *p = NULL;

    BIO_write(b, "abc", 3);
    check(BIO_int_ctrl(b, BIO_CTRL_PENDING, 0, 0) == 3, "BIO_int_ctrl");
    p = BIO_ptr_ctrl(b, BIO_CTRL_INFO, 0);
    check(p != NULL && memcmp(p, "abc", 3) == 0, "BIO_ptr_ctrl");
    check(BIO_indent(b, 3, 2) == 1 && BIO_pending(b) == 5 && BIO_indent(b, -1, 5) == 1
          && BIO_pending(b) == 5, "BIO_indent: up to max, none for negative");
    BIO_set_flags(b, 0x4000);
    check(BIO_test_flags(b, 0x4000 | BIO_FLAGS_READ) == 0x4000, "BIO_set_flags, BIO_test_flags");
    BIO_clear_flags(b, 0x4000);
    check(BIO_test_flags(b, 0x4000) == 0, "BIO_clear_flags");
    BIO_set_retry_reason(b, 7);
    check(BIO_get_retry_reason(b) == 7, "BIO_set_retry_reason, BIO_get_retry_reason");
    check(BIO_callback_ctrl(b, BIO_CTRL_SET_CALLBACK, NULL) == -2,
          "BIO_callback_ctrl: the memory BIO has none");
    ERR_clear_error();
    BIO_free(b);
}

static int lines(void)
{
    BIO *b = BIO_new_mem_buf("first\nsecond", -1);
    char buf[32];
    int ok;

    ok = BIO_get_line(b, buf, sizeof(buf)) == 6 && same(buf, "first\n")
         && BIO_get_line(b, buf, 4) == 3 && same(buf, "sec")
         && BIO_get_line(b, buf, sizeof(buf)) == 3 && same(buf, "ond")
         && BIO_get_line(b, buf, sizeof(buf)) == 0 && buf[0] == '\0';
    BIO_free(b);
    ERR_clear_error();
    return ok && BIO_get_line(NULL, buf, 4) == -1 && BIO_get_line(b = BIO_new(BIO_s_mem()), buf, 0) == -1
           && (BIO_free(b), 1);
}

int main(void)
{
    memory();
    read_only();
    secure();
    nulls();
    chains();
    duplicating();
    controls();
    check(lines(), "BIO_get_line");
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures != 0;
}
