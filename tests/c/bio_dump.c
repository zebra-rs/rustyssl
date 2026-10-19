/*
 * Conformance test for hex dumps (BIO_dump(3)), BIO_hex_string, and the debug callback
 * (BIO_debug_callback(3)), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
/* BIO_debug_callback and BIO_set_callback are deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The memory BIO's contents as a string, then empties it. */
static const char *contents(BIO *bio)
{
    static char text[8192];
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);

    if (len < 0 || (size_t)len >= sizeof(text))
        len = 0;
    memcpy(text, data, (size_t)len);
    text[len] = '\0';
    (void)BIO_reset(bio);
    return text;
}

static int same(const char *got, const char *expected)
{
    if (strcmp(got, expected) == 0)
        return 1;
    printf("# got:\n%s# expected:\n%s", got, expected);
    return 0;
}

static unsigned char data[40];

static const char dump_20[] =
    "0000 - 00 01 02 03 04 05 06 07-08 09 0a 0b 0c 0d 0e 0f   ................\n"
    "0010 - 41 42 7e 7f                                       AB~.\n";

/* A dump callback that records the lines, and fails on the call numbered `fail_at`. */
static char lines[4096];
static int calls, fail_at;

static int record(const void *line, size_t len, void *u)
{
    calls++;
    if (calls == fail_at)
        return -7;
    strncat(lines, (const char *)line, len);
    return (int)len + (u == NULL ? 0 : 1000);
}

static void dumps(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    char expected[1024];
    FILE *f;
    size_t got;
    int ret;

    for (int i = 0; i < 16; i++)
        data[i] = (unsigned char)i;
    memcpy(data + 16, "AB~\x7f", 4);

    check(BIO_dump(mem, data, 20) == (int)strlen(dump_20) && same(contents(mem), dump_20),
          "BIO_dump writes 16 bytes a line and returns the bytes written");
    check(BIO_dump(mem, data, 0) == 0 && BIO_dump(mem, data, -5) == 0
              && strcmp(contents(mem), "") == 0,
          "nothing to dump writes nothing");
    check(BIO_dump_indent(mem, "abcdefghijklmnopq", 17, 10) > 0
              && same(contents(mem),
                      "          0000 - 61 62 63 64 65 66 67 68-69 6a 6b 6c 6d 6e 6f   abcdefghijklmno\n"
                      "          000f - 70 71                                          pq\n"),
          "an indentation past 6 makes lines shorter");
    check(BIO_dump_indent(mem, "abc", 3, 100) > 0
              && same(contents(mem),
                      "                                                                0000 - 61   a\n"
                      "                                                                0001 - 62   b\n"
                      "                                                                0002 - 63   c\n"),
          "the indentation is at most 64");
    check(BIO_dump_indent(mem, "ab", 2, -3) > 0
              && same(contents(mem),
                      "0000 - 61 62                                             ab\n"),
          "a negative indentation is 0");

    lines[0] = '\0';
    calls = 0;
    fail_at = 0;
    check(BIO_dump_cb(record, NULL, data, 20) == (int)strlen(dump_20) && calls == 2
              && same(lines, dump_20),
          "BIO_dump_cb hands each line to the callback and sums its results");
    lines[0] = '\0';
    calls = 0;
    ret = BIO_dump_indent_cb(record, data, data, 20, 2);
    check(ret == 2 * 1000 + (int)strlen(lines) && calls == 2,
          "BIO_dump_indent_cb passes the callback's argument");
    lines[0] = '\0';
    calls = 0;
    fail_at = 2;
    check(BIO_dump_cb(record, NULL, data, 40) == -7 && calls == 2,
          "a negative result from the callback stops the dump and is returned");
    fail_at = 0;

    f = tmpfile();
    check(BIO_dump_fp(f, data, 20) == 2, "BIO_dump_fp returns the number of lines written");
    check(BIO_dump_indent_fp(f, "ab", 2, 1) == 1, "BIO_dump_indent_fp too");
    rewind(f);
    got = fread(expected, 1, sizeof(expected) - 1, f);
    expected[got] = '\0';
    check(same(expected,
               "0000 - 00 01 02 03 04 05 06 07-08 09 0a 0b 0c 0d 0e 0f   ................\n"
               "0010 - 41 42 7e 7f                                       AB~.\n"
               " 0000 - 61 62                                             ab\n"),
          "BIO_dump_fp writes the dump to the file");
    fclose(f);
    BIO_free(mem);
}

static void hex_strings(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    const unsigned char bytes[] = { 0x00, 0x1f, 0xa0, 0xff, 0x10, 0x20, 0x30 };

    check(BIO_hex_string(mem, 4, 3, bytes, 7) == 1
              && same(contents(mem), "00:1F:A0:\n    FF:10:20:\n    30"),
          "BIO_hex_string writes colon-separated hex, width bytes a line");
    check(BIO_hex_string(mem, 2, 3, bytes, 3) == 1 && same(contents(mem), "00:1F:A0"),
          "no new line before the last byte at the end of a line");
    check(BIO_hex_string(mem, 2, 4, bytes, 1) == 1 && same(contents(mem), "00"),
          "a single byte has no colon");
    check(BIO_hex_string(mem, 2, 2, bytes, 0) == 1 && BIO_hex_string(mem, 2, 2, bytes, -1) == 1
              && same(contents(mem), ""),
          "no bytes writes nothing and returns 1");
    check(BIO_hex_string(mem, -3, 0, bytes, 3) == 1
              && same(contents(mem), "00:\n   1F:\n   A0"),
          "a width of 0 breaks the line after each byte; a negative indentation counts as positive");
    BIO_free(mem);
}

/* The debug callback's prefix for `bio`. */
static const char *prefix(const BIO *bio)
{
    static char text[64];

    snprintf(text, sizeof(text), "BIO[%p]: ", (const void *)bio);
    return text;
}

static void debug_callbacks(void)
{
    BIO *log = BIO_new(BIO_s_mem());
    BIO *b = BIO_new(BIO_s_mem());
    BIO_METHOD *long_name;
    char expected[2048], got[16];
    char name[301];
    int fds[2];

    BIO_set_callback_ex(b, BIO_debug_callback_ex);
    BIO_set_callback_arg(b, (char *)log);
    (void)BIO_write(b, "hello", 5);
    snprintf(expected, sizeof(expected),
             "%swrite(-1,5) - memory buffer\n%swrite return 1 processed: 5\n",
             prefix(b), prefix(b));
    check(same(contents(log), expected), "BIO_debug_callback_ex describes a write");

    (void)BIO_read(b, got, 2);
    (void)BIO_puts(b, "xy");
    (void)BIO_gets(b, got, sizeof(got));
    (void)BIO_pending(b);
    snprintf(expected, sizeof(expected),
             "%sread(-1,2) - memory buffer\n%sread return 1 processed: 2\n"
             "%sputs() - memory buffer\n%sputs return 1 processed: 2\n"
             "%sgets(16) - memory buffer\n%sgets return 1 processed: 5\n"
             "%sctrl(10) - memory buffer\n%sctrl return 0\n",
             prefix(b), prefix(b), prefix(b), prefix(b), prefix(b), prefix(b), prefix(b),
             prefix(b));
    check(same(contents(log), expected),
          "reads, puts, gets, and controls are described with their results");

    (void)BIO_debug_callback_ex(b, 0x55, NULL, 0, 0, 0, 3, NULL);
    snprintf(expected, sizeof(expected), "%sbio callback - unknown type (85)\n", prefix(b));
    check(same(contents(log), expected), "unknown operations are described as such");
    check(BIO_debug_callback_ex(b, BIO_CB_RETURN | BIO_CB_CTRL, NULL, 0, 0, 0, -4, NULL) == -4,
          "BIO_debug_callback_ex returns its ret");
    (void)contents(log);

    snprintf(expected, sizeof(expected), "%sFree - memory buffer\n", prefix(b));
    BIO_free(b);
    check(same(contents(log), expected), "freeing is described");

    b = BIO_new(BIO_s_mem());
    BIO_set_callback(b, BIO_debug_callback);
    BIO_set_callback_arg(b, (char *)log);
    (void)BIO_write(b, "abc", 3);
    snprintf(expected, sizeof(expected),
             "%swrite(-1,3) - memory buffer\n%swrite return 1 processed: 3\n",
             prefix(b), prefix(b));
    check(same(contents(log), expected), "the old-style BIO_debug_callback describes a write");
    check(BIO_debug_callback(b, BIO_CB_RETURN | BIO_CB_READ, NULL, 4, 0, -2) == -2
              && strstr(contents(log), "read return -2 processed: 0\n") != NULL,
          "BIO_debug_callback returns ret and passes non-positive ones on");
    BIO_set_callback(b, NULL);
    BIO_free(b);

    if (pipe(fds) == 0) {
        b = BIO_new_fd(fds[1], BIO_CLOSE);
        BIO_set_callback_ex(b, BIO_debug_callback_ex);
        BIO_set_callback_arg(b, (char *)log);
        (void)BIO_write(b, "x", 1);
        snprintf(expected, sizeof(expected),
                 "%swrite(%d,1) - file descriptor fd=%d\n%swrite return 1 processed: 1\n",
                 prefix(b), fds[1], fds[1], prefix(b));
        check(same(contents(log), expected), "descriptor BIOs show their fd");
        BIO_set_callback_ex(b, NULL);
        BIO_free(b);
        close(fds[0]);
    } else {
        check(0, "pipe");
    }

    memset(name, 'n', sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    long_name = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, name);
    b = BIO_new(long_name);
    BIO_set_callback_arg(b, (char *)log);
    (void)BIO_debug_callback_ex(b, BIO_CB_PUTS, NULL, 0, 0, 0, 1, NULL);
    snprintf(expected, sizeof(expected), "%sputs() - %s\n", prefix(b), name);
    expected[255] = '\0';
    check(same(contents(log), expected), "a description is cut to 255 bytes");
    BIO_free(b);
    BIO_meth_free(long_name);
    BIO_free(log);
}

int main(void)
{
    dumps();
    hex_strings();
    debug_callbacks();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
