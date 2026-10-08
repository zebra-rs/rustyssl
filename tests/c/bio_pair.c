/*
 * Conformance test for BIO pairs (BIO_s_bio(3), BIO_new_bio_pair(3)) and their non-copying
 * reads and writes (BIO_nread0, BIO_nread, BIO_nwrite0, BIO_nwrite), in TAP format.
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

/* Whether the newest error is `reason` from the BIO library; clears the queue. */
static int raised(int reason)
{
    unsigned long code = ERR_peek_last_error();

    ERR_clear_error();
    return ERR_GET_LIB(code) == ERR_LIB_BIO && ERR_GET_REASON(code) == reason;
}

int main(void)
{
    BIO *a = NULL, *b = NULL, *c, *d, *copy;
    char out[64], *p = NULL;

    check(BIO_new_bio_pair(&a, 0, &b, 0) == 1 && a != NULL && b != NULL,
          "BIO_new_bio_pair makes a joined pair");
    check(BIO_ctrl_get_write_guarantee(a) == 17 * 1024 && BIO_get_write_buf_size(a, 0) == 17 * 1024,
          "the buffers default to 17 KiB");
    check(BIO_read(b, out, 10) == -1 && BIO_should_retry(b) && BIO_should_read(b)
              && BIO_ctrl_get_read_request(a) == 10,
          "reading an empty pair retries, and the writer sees the request");
    check(BIO_write(a, "hello", 5) == 5 && BIO_ctrl_get_read_request(a) == 0
              && BIO_pending(b) == 5 && BIO_wpending(a) == 5 && BIO_pending(a) == 0,
          "a write fills the reader's pending bytes and clears the request");
    check(BIO_read(b, out, 3) == 3 && memcmp(out, "hel", 3) == 0 && BIO_pending(b) == 2,
          "reads take from the peer's buffer");
    check(BIO_puts(b, "back") == 4 && BIO_read(a, out, sizeof(out)) == 4
              && memcmp(out, "back", 4) == 0,
          "both directions work");
    check(BIO_ctrl_reset_read_request(a) == 1, "BIO_ctrl_reset_read_request returns 1");
    (void)BIO_read(b, out, 2);
    check(BIO_shutdown_wr(a) == 1 && BIO_write(a, "x", 1) == -1 && raised(BIO_R_BROKEN_PIPE),
          "writes after BIO_shutdown_wr fail with a broken pipe");
    check(BIO_read(b, out, 1) == 0 && !BIO_should_retry(b) && BIO_eof(b) == 1,
          "the reader then sees the end");
    check(BIO_ctrl_get_write_guarantee(a) == 0, "and the writer has no guarantee");
    check(BIO_set_write_buf_size(b, 100) == 0 && raised(BIO_R_IN_USE),
          "a paired buffer can't be resized");
    check(BIO_destroy_bio_pair(a) == 1 && BIO_get_init(a) == 0 && BIO_get_init(b) == 0,
          "BIO_destroy_bio_pair unpairs both ends");
    ERR_clear_error();
    check(BIO_write(b, "x", 1) == -1 && raised(BIO_R_UNINITIALIZED),
          "an unpaired end is uninitialized");
    BIO_free(a);
    BIO_free(b);

    c = BIO_new(BIO_s_bio());
    d = BIO_new(BIO_s_bio());
    check(BIO_set_write_buf_size(c, 8) == 1 && BIO_set_write_buf_size(d, 0) == 0
              && raised(BIO_R_INVALID_ARGUMENT),
          "write buffer sizes are set before pairing; 0 is refused");
    check(BIO_nread0(c, &p) == -2 && raised(BIO_R_UNINITIALIZED),
          "the non-copying functions need a paired end");
    check(BIO_make_bio_pair(c, d) == 1 && BIO_get_write_buf_size(c, 0) == 8,
          "BIO_make_bio_pair joins two ends");
    check(BIO_make_bio_pair(c, d) == 0 && raised(BIO_R_IN_USE), "but not twice");
    check(BIO_write(c, "abcdef", 6) == 6 && BIO_read(d, out, 4) == 4 && BIO_write(c, "ghijkl", 6) == 6
              && BIO_write(c, "m", 1) == -1 && BIO_should_write(c),
          "the ring buffer wraps around, and a full one retries the write");
    check(BIO_nread0(d, &p) == 4 && memcmp(p, "efgh", 4) == 0,
          "BIO_nread0 points at the bytes before the wrap");
    check(BIO_nread(d, &p, 3) == 3 && memcmp(p, "efg", 3) == 0 && BIO_pending(d) == 5
              && BIO_number_read(d) == 7,
          "BIO_nread consumes them and counts them as read");
    check(BIO_nread(d, &p, 100) == 1 && BIO_nread0(d, &p) == 4 && memcmp(p, "ijkl", 4) == 0,
          "and the rest comes after the wrap");
    check(BIO_read(d, out, sizeof(out)) == 4 && BIO_nread0(d, &p) == -1 && BIO_should_read(d),
          "with nothing left, BIO_nread0 is a read that retries");
    check(BIO_nwrite0(c, &p) == 8, "BIO_nwrite0 offers the free space in one piece");
    memcpy(p, "0123456789", 8);
    check(BIO_nwrite(c, &p, 5) == 5 && BIO_number_written(c) == 17 && BIO_pending(d) == 5
              && BIO_read(d, out, sizeof(out)) == 5 && memcmp(out, "01234", 5) == 0,
          "BIO_nwrite adds what was written there");
    check(BIO_nwrite(c, NULL, 6) == 6 && BIO_read(d, out, 4) == 4 && BIO_nwrite0(c, NULL) == 2,
          "the space ends at the buffer's end, without wrapping");
    copy = BIO_dup_chain(c);
    /* The copy is unpaired, yet init is copied too: it must not be read or written. */
    check(copy != NULL && BIO_get_init(copy) == 1 && BIO_get_write_buf_size(copy, 0) == 8,
          "BIO_dup_chain copies an end, unpaired, with its size and init flag");
    BIO_free(copy);
    BIO_free(c);
    ERR_clear_error();
    check(BIO_get_init(d) == 0 && BIO_read(d, out, 1) == -1 && raised(BIO_R_UNINITIALIZED),
          "freeing one end unpairs the other");
    BIO_free(d);

    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
