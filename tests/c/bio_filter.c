/*
 * Conformance test for the buffering and prefix filters (BIO_f_buffer(3), BIO_f_linebuffer,
 * BIO_f_readbuffer(3), BIO_f_prefix(3)), in TAP format.
 *
 * The filters sit in front of a scripted BIO that logs each write it gets (its size) and can
 * take only part of a write or refuse it with a retry, and that reads from a script in chunks.
 * What the filters pass on, and when, is compared through that log.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

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

static int same(const char *got, const char *expected)
{
    if (strcmp(got, expected) == 0)
        return 1;
    printf("# got \"%s\", expected \"%s\"\n", got, expected);
    return 0;
}

/* The scripted BIO's log, its limits, and its input. */
static char log_text[1024];
static char sink[65536];
static size_t sink_len;
static int write_limit; /* 0: take everything; > 0: at most this much; -1: retry */
static const char *source;
static size_t source_len, source_pos;
static int read_limit; /* 0: as much as asked; > 0: at most this much; -1: retry */

static void note(const char *what, int n)
{
    size_t used = strlen(log_text);

    snprintf(log_text + used, sizeof(log_text) - used, "%s%s%d", used ? " " : "", what, n);
}

static const char *take_log(void)
{
    static char copy[1024];

    strcpy(copy, log_text);
    log_text[0] = '\0';
    return copy;
}

static int script_write(BIO *b, const char *data, int len)
{
    int n = len;

    note("w", len);
    BIO_clear_retry_flags(b);
    if (write_limit < 0) {
        BIO_set_retry_write(b);
        return -1;
    }
    if (write_limit > 0 && n > write_limit)
        n = write_limit;
    memcpy(sink + sink_len, data, (size_t)n);
    sink_len += (size_t)n;
    return n;
}

static int script_read(BIO *b, char *out, int len)
{
    size_t n = (size_t)len;

    note("r", len);
    BIO_clear_retry_flags(b);
    if (read_limit < 0) {
        BIO_set_retry_read(b);
        return -1;
    }
    if (read_limit > 0 && n > (size_t)read_limit)
        n = (size_t)read_limit;
    if (n > source_len - source_pos)
        n = source_len - source_pos;
    memcpy(out, source + source_pos, n);
    source_pos += n;
    return (int)n;
}

static long script_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    (void)b;
    (void)num;
    (void)ptr;
    if (cmd == BIO_CTRL_FLUSH) {
        note("f", 0);
        return 1;
    }
    if (cmd == BIO_CTRL_PENDING)
        return (long)(source_len - source_pos);
    if (cmd == BIO_CTRL_DUP)
        return 1;
    return 0;
}

static int script_create(BIO *b)
{
    BIO_set_init(b, 1);
    return 1;
}

static BIO_METHOD *script_method;

static BIO *script(const char *input)
{
    log_text[0] = '\0';
    sink_len = 0;
    write_limit = 0;
    read_limit = 0;
    source = input;
    source_len = input == NULL ? 0 : strlen(input);
    source_pos = 0;
    return BIO_new(script_method);
}

static int sink_is(const char *expected)
{
    sink[sink_len] = '\0';
    return same(sink, expected);
}

static char big[20000];

static void buffers(void)
{
    BIO *f = BIO_new(BIO_f_buffer()), *s = script(NULL), *copy;
    char out[64];

    BIO_push(f, s);
    check(BIO_write(f, "hello", 5) == 5 && same(take_log(), "") && BIO_wpending(f) == 5
              && BIO_ctrl(f, BIO_CTRL_INFO, 0, NULL) == 5,
          "BIO_f_buffer keeps a small write");
    check(BIO_flush(f) == 1 && same(take_log(), "w5 f0") && sink_is("hello")
              && BIO_wpending(f) == 0,
          "BIO_flush writes it out, then flushes the next BIO");
    check(BIO_write(f, big, 5000) == 5000 && same(take_log(), "w5000"),
          "a write of a buffer or more goes straight through");
    check(BIO_write(f, big, 3000) == 3000 && BIO_write(f, big, 3000) == 3000
              && same(take_log(), "w4096") && BIO_wpending(f) == 1904,
          "a write that overflows the buffer fills it, writes it, and keeps the rest");
    write_limit = 1000;
    check(BIO_flush(f) == 1 && same(take_log(), "w1904 w904 f0"),
          "a flush repeats partial writes until the buffer is empty");
    write_limit = -1;
    check(BIO_write(f, big, 4000) == 4000 && BIO_write(f, big, 200) == 96
              && BIO_should_retry(f) && BIO_should_write(f),
          "when the next BIO retries, the bytes that fit are taken and the retry is copied");
    check(BIO_flush(f) == -1 && BIO_should_retry(f), "a flush that can't write fails with a retry");
    write_limit = 0;
    (void)take_log();
    check(BIO_flush(f) == 1 && same(take_log(), "w4096 f0"), "and succeeds once it can");
    BIO_free_all(f);

    f = BIO_new(BIO_f_buffer());
    s = script("line one\nline two\nlast");
    BIO_push(f, s);
    check(BIO_gets(f, out, sizeof(out)) == 9 && same(out, "line one\n") && same(take_log(), "r4096"),
          "BIO_gets fills the buffer once and returns a line");
    check(BIO_get_buffer_num_lines(f) == 1 && BIO_pending(f) == 13,
          "the buffered lines and bytes are counted");
    check(BIO_buffer_peek(f, out, 5) == 5 && memcmp(out, "line ", 5) == 0 && BIO_pending(f) == 13,
          "BIO_buffer_peek copies without consuming");
    check(BIO_read(f, out, 4) == 4 && memcmp(out, "line", 4) == 0 && BIO_eof(f) == 0,
          "reads take from the buffer");
    check(BIO_gets(f, out, 3) == 2 && same(out, " t"), "BIO_gets stops at its size");
    check(BIO_read(f, out, sizeof(out)) == 7 && memcmp(out, "wo\nlast", 7) == 0
              && same(take_log(), "r4096"),
          "a read past the buffer tries to refill it and returns what there was");
    check(BIO_set_buffer_read_data(f, "preset", 6) == 1 && BIO_read(f, out, 6) == 6
              && memcmp(out, "preset", 6) == 0,
          "BIO_set_buffer_read_data preloads the read buffer");
    read_limit = -1;
    check(BIO_read(f, out, 10) == -1 && BIO_should_retry(f) && BIO_should_read(f),
          "a read the next BIO retries is retried");
    read_limit = 0;
    check(BIO_set_buffer_size(f, 100) == 1 && BIO_set_read_buffer_size(f, 8192) == 1
              && BIO_set_write_buffer_size(f, 8192) == 1,
          "buffer sizes can grow");
    copy = BIO_dup_chain(f);
    check(copy != NULL, "BIO_dup_chain copies the filter");
    BIO_free_all(copy);
    BIO_free_all(f);
}

static void line_buffers(void)
{
    BIO *f = BIO_new(BIO_f_linebuffer()), *s = script(NULL);

    BIO_push(f, s);
    check(BIO_write(f, "abc", 3) == 3 && same(take_log(), "") && BIO_wpending(f) == 3,
          "BIO_f_linebuffer keeps text without a newline");
    check(BIO_write(f, "def\nghi", 7) == 7 && same(take_log(), "w7") && sink_is("abcdef\n")
              && BIO_wpending(f) == 3,
          "a newline writes the buffered text and the line in one write");
    check(BIO_write(f, "1\n2\n3", 5) == 5 && same(take_log(), "w5 w2") && sink_is("abcdef\nghi1\n2\n"),
          "each line goes out on its own");
    check(BIO_flush(f) == 1 && same(take_log(), "w1 f0") && BIO_wpending(f) == 0, "BIO_flush writes the rest");
    memset(big, 'x', 12000);
    check(BIO_write(f, big, 12000) == 12000 && same(take_log(), "w12000"),
          "a line longer than the buffer goes straight through");
    check(BIO_write(f, "partial", 7) == 7 && BIO_set_write_buffer_size(f, 20000) == 1
              && BIO_wpending(f) == 7,
          "a larger buffer keeps what was buffered");
    write_limit = -1;
    check(BIO_write(f, "a\n", 2) == 2 && BIO_should_retry(f),
          "when the next BIO retries, the count still includes what was added");
    write_limit = 0;
    BIO_free_all(f);
}

static void read_buffers(void)
{
    BIO *f = BIO_new(BIO_f_readbuffer()), *s = BIO_new_mem_buf("0123456789\nabc", -1);
    char out[64];

    BIO_push(f, s);
    check(BIO_read(f, out, 4) == 4 && memcmp(out, "0123", 4) == 0 && BIO_tell(f) == 4,
          "BIO_f_readbuffer reads and tells the position");
    check(BIO_seek(f, 1) == 1 && BIO_read(f, out, 3) == 3 && memcmp(out, "123", 3) == 0,
          "it can seek back within what was read");
    check(BIO_seek(f, 50) == 0 && BIO_seek(f, -1) == 0 && BIO_tell(f) == 4,
          "but not past it or before the start");
    check(BIO_gets(f, out, sizeof(out)) == 7 && same(out, "456789\n"),
          "BIO_gets reads the rest of the line a byte at a time");
    check(BIO_reset(f) == 1 && BIO_tell(f) == 0 && BIO_gets(f, out, sizeof(out)) == 11
              && same(out, "0123456789\n"),
          "BIO_reset goes back to the start, and lines come from the buffer");
    check(BIO_read(f, out, sizeof(out)) == 3 && BIO_read(f, out, 1) == 0 && BIO_eof(f) == 1,
          "the end of the source is the end");
    check(BIO_write(f, "x", 1) == 0 && BIO_puts(f, "x") == 0, "it can't be written to");
    check(BIO_ctrl(f, BIO_CTRL_FLUSH, 0, NULL) == 1 && BIO_ctrl(f, BIO_CTRL_WPENDING, 0, NULL) == 0,
          "other controls aren't passed on");
    BIO_free_all(f);
}

static void prefixes(void)
{
    BIO *f = BIO_new(BIO_f_prefix()), *m = BIO_new(BIO_s_mem());
    char *data;
    long len;

    BIO_push(f, m);
    check(BIO_set_prefix(f, "> ") == 1 && BIO_set_indent(f, 2) == 1 && BIO_get_indent(f) == 2,
          "BIO_f_prefix takes a prefix and an indentation");
    check(BIO_printf(f, "a\nbc\n\nd") == 7, "writes through it count the caller's bytes");
    (void)BIO_puts(f, "e\n");
    len = BIO_get_mem_data(m, &data);
    check(len == 25 && memcmp(data, ">   a\n>   bc\n>   \n>   de\n", 25) == 0,
          "each line starts with the prefix and the indentation");
    check(BIO_set_indent(f, -1) == 0 && BIO_get_indent(f) == 2, "a negative indentation is refused");
    (void)BIO_reset(m);
    check(BIO_set_prefix(f, NULL) == 1 && BIO_set_indent(f, 0) == 1 && BIO_write(f, "x\ny", 3) == 3
              && BIO_write(f, "z", 1) == 1,
          "without a prefix or indentation, writes pass through");
    (void)BIO_set_indent(f, 1);
    (void)BIO_write(f, "\nw", 2);
    len = BIO_get_mem_data(m, &data);
    check(len == 7 && memcmp(data, "x\nyz\n w", 7) == 0,
          "and whether the next write starts a line is still tracked");
    (void)BIO_reset(f);
    (void)BIO_write(f, "v", 1);
    len = BIO_get_mem_data(m, &data);
    check(len == 2 && memcmp(data, " v", 2) == 0, "BIO_reset starts a new line");
    BIO_free_all(f);
}

int main(void)
{
    script_method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "script");
    BIO_meth_set_write(script_method, script_write);
    BIO_meth_set_read(script_method, script_read);
    BIO_meth_set_ctrl(script_method, script_ctrl);
    BIO_meth_set_create(script_method, script_create);
    memset(big, 'b', sizeof(big));

    buffers();
    line_buffers();
    read_buffers();
    prefixes();
    BIO_meth_free(script_method);
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
