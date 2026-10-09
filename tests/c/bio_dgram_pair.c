/*
 * Conformance test for datagram pairs and datagram memory BIOs (BIO_s_dgram_pair(3),
 * BIO_new_bio_dgram_pair(3), BIO_s_dgram_mem), in TAP format. The default buffer size depends
 * on the platform's sizeof(BIO_ADDR), so it's printed as a comment, which must match too.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

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

/* Whether the newest error is `reason` from the BIO library; clears the queue. */
static int raised(int reason)
{
    unsigned long code = ERR_peek_last_error();

    ERR_clear_error();
    if (ERR_GET_LIB(code) != ERR_LIB_BIO || ERR_GET_REASON(code) != reason)
        printf("# error %d/%d, expected %d\n", ERR_GET_LIB(code), ERR_GET_REASON(code), reason);
    return ERR_GET_LIB(code) == ERR_LIB_BIO && ERR_GET_REASON(code) == reason;
}

static BIO_ADDR *v4(const char *ip, unsigned short port)
{
    BIO_ADDR *a = BIO_ADDR_new();
    struct in_addr raw;

    inet_pton(AF_INET, ip, &raw);
    BIO_ADDR_rawmake(a, AF_INET, &raw, sizeof(raw), htons(port));
    return a;
}

static void pairs(void)
{
    BIO *a = NULL, *b = NULL, *c, *d;
    char buf[64];
    BIO_ADDR *src = v4("10.0.0.1", 1111), *dst = v4("10.0.0.2", 2222), *got_src = BIO_ADDR_new(),
             *got_dst = BIO_ADDR_new();
    BIO_MSG msg;
    size_t done = 0;

    check(BIO_new_bio_dgram_pair(&a, 0, &b, 0) == 1 && a != NULL && b != NULL
              && BIO_method_type(a) == BIO_TYPE_DGRAM_PAIR,
          "BIO_new_bio_dgram_pair makes a joined pair");
    printf("# default buffer: %ld, guarantee: %ld\n", (long)BIO_get_write_buf_size(a, 0),
           (long)BIO_ctrl_get_write_guarantee(a));
    check(BIO_read(b, buf, sizeof(buf)) == -1 && BIO_should_retry(b) && BIO_should_read(b) && ERR_peek_error() == 0,
          "reading an empty pair retries without an error");
    check(BIO_write(a, "first", 5) == 5 && BIO_write(a, "second!", 7) == 7 && BIO_pending(b) == 5,
          "datagrams queue, and pending is the next one's length");
    check(BIO_read(b, buf, 3) == 3 && memcmp(buf, "fir", 3) == 0 && BIO_pending(b) == 7,
          "a short read truncates the datagram and drops the rest");
    check(BIO_dgram_set_no_trunc(b, 1) == 1 && BIO_dgram_get_no_trunc(b) == 1
              && BIO_read(b, buf, 3) == -1 && !BIO_should_retry(b) && ERR_peek_error() == 0
              && BIO_pending(b) == 7,
          "with no truncation, a short read fails (without a retry) and leaves the datagram");
    check(BIO_read(b, buf, sizeof(buf)) == 7 && memcmp(buf, "second!", 7) == 0, "a long enough read takes it");
    check(BIO_eof(b) == 0, "a pair never reports the end");
    check(BIO_dgram_set_mtu(a, 1000) == 1 && BIO_dgram_get_mtu(b) == 1000, "the MTU is shared");
    check(BIO_dgram_get_local_addr_cap(a) == 0 && BIO_dgram_set_local_addr_enable(a, 1) == 0,
          "without capabilities, local addresses can't be enabled");
    check(BIO_dgram_set_caps(a, BIO_DGRAM_CAP_HANDLES_SRC_ADDR | BIO_DGRAM_CAP_HANDLES_DST_ADDR
                                 | BIO_DGRAM_CAP_PROVIDES_SRC_ADDR | BIO_DGRAM_CAP_PROVIDES_DST_ADDR) == 1
              && BIO_dgram_set_caps(b, BIO_DGRAM_CAP_HANDLES_SRC_ADDR | BIO_DGRAM_CAP_HANDLES_DST_ADDR
                                       | BIO_DGRAM_CAP_PROVIDES_SRC_ADDR | BIO_DGRAM_CAP_PROVIDES_DST_ADDR) == 1
              && BIO_dgram_get_caps(a) == 15 && BIO_dgram_get_effective_caps(a) == 15
              && BIO_dgram_get_local_addr_cap(a) == 1 && BIO_dgram_set_local_addr_enable(a, 1) == 1
              && BIO_dgram_set_local_addr_enable(b, 1) == 1,
          "with capabilities, they can");
    memset(&msg, 0, sizeof(msg));
    msg.data = (void *)"addressed";
    msg.data_len = 9;
    msg.local = src;
    msg.peer = dst;
    check(BIO_sendmmsg(a, &msg, sizeof(msg), 1, 0, &done) == 1 && done == 1, "BIO_sendmmsg with addresses");
    msg.data = buf;
    msg.data_len = sizeof(buf);
    msg.local = got_dst;
    msg.peer = got_src;
    check(BIO_recvmmsg(b, &msg, sizeof(msg), 1, 0, &done) == 1 && done == 1 && msg.data_len == 9
              && memcmp(buf, "addressed", 9) == 0 && BIO_ADDR_rawport(got_src) == htons(1111)
              && BIO_ADDR_rawport(got_dst) == htons(2222),
          "BIO_recvmmsg gives the source and destination");
    check(BIO_recvmmsg(b, &msg, sizeof(msg), 1, 0, &done) == 0 && done == 0 && raised(BIO_R_NON_FATAL),
          "receiving nothing fails with BIO_R_NON_FATAL");
    check(BIO_dgram_set0_local_addr(a, BIO_ADDR_dup(src)) == 1 && BIO_write(a, "x", 1) == 1,
          "BIO_dgram_set0_local_addr gives writes a default source");
    msg.data_len = sizeof(buf);
    check(BIO_recvmmsg(b, &msg, sizeof(msg), 1, 0, &done) == 1 && BIO_ADDR_rawport(got_src) == htons(1111),
          "and it arrives as the source");
    check(BIO_set_write_buf_size(a, 4096) == 0 && raised(BIO_R_IN_USE), "a paired buffer can't be resized");
    check(BIO_reset(a) == 1, "BIO_reset empties this end's buffer");
    /*
     * OpenSSL frees the local address when unpairing without forgetting it, and again when the
     * BIO is freed; clear it first so the reference doesn't double-free it.
     */
    (void)BIO_dgram_set0_local_addr(a, NULL);
    check(BIO_destroy_bio_pair(a) == 1 && BIO_get_init(a) == 0 && BIO_get_init(b) == 0
              && BIO_eof(a) == 1,
          "BIO_destroy_bio_pair unpairs both ends");
    check(BIO_write(a, "x", 1) <= 0, "an unpaired end can't be written to");
    ERR_clear_error();
    BIO_free(a);
    BIO_free(b);

    c = BIO_new(BIO_s_dgram_pair());
    d = BIO_new(BIO_s_mem());
    check(BIO_make_bio_pair(c, d) == 0 && raised(BIO_R_INVALID_ARGUMENT), "only datagram pair ends pair");
    check(BIO_set_write_buf_size(c, 10) == 1 && BIO_get_write_buf_size(c, 0) == 1024,
          "the buffer is at least 1024 bytes");
    BIO_free(c);
    BIO_free(d);
    BIO_ADDR_free(src);
    BIO_ADDR_free(dst);
    BIO_ADDR_free(got_src);
    BIO_ADDR_free(got_dst);
}

static void memory(void)
{
    BIO *m = BIO_new(BIO_s_dgram_mem());
    char big[5000], buf[5000];
    long size;
    int i, ok = 1;

    check(m != NULL && BIO_method_type(m) == BIO_TYPE_DGRAM_MEM && BIO_get_init(m) == 1,
          "a datagram memory BIO is ready at once");
    check(BIO_write(m, "loop", 4) == 4 && BIO_read(m, buf, sizeof(buf)) == 4 && memcmp(buf, "loop", 4) == 0,
          "it reads back what it wrote");
    size = (long)BIO_get_write_buf_size(m, 0);
    memset(big, 'b', sizeof(big));
    for (i = 0; i < 10; i++)
        ok = ok && BIO_write(m, big, sizeof(big)) == (int)sizeof(big);
    check(ok && (long)BIO_get_write_buf_size(m, 0) > size, "its buffer grows as needed");
    printf("# grown buffer: %ld\n", (long)BIO_get_write_buf_size(m, 0));
    check(BIO_read(m, buf, sizeof(buf)) == (int)sizeof(buf) && BIO_pending(m) == (int)sizeof(big),
          "and the datagrams come back in order");
    check(BIO_set_write_buf_size(m, 2048) == 0, "it can't shrink while holding data");
    check(BIO_reset(m) == 1 && BIO_pending(m) == 0 && BIO_set_write_buf_size(m, 2048) == 1
              && BIO_write(m, big, sizeof(big)) == -1 && BIO_should_retry(m),
          "an explicit size stops the growth");
    check(BIO_eof(m) == 0, "a memory BIO doesn't report the end");
    BIO_free(m);
}

int main(void)
{
    pairs();
    memory();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
