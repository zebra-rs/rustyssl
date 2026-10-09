/*
 * Conformance test for the datagram BIO (BIO_s_datagram(3), BIO_new_dgram, the BIO_dgram_*
 * controls, BIO_sendmmsg(3) and BIO_recvmmsg on it) and BIO_dgram_non_fatal_error and
 * BIO_err_is_non_fatal, in TAP format, over loopback UDP. Results that depend on the platform
 * (MTU discovery, don't-fragment) are printed as comments, which must match too.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

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

/* An IPv4 loopback address with `port` (host order). */
static BIO_ADDR *loopback(unsigned short port)
{
    BIO_ADDR *a = BIO_ADDR_new();
    struct in_addr v4;

    inet_pton(AF_INET, "127.0.0.1", &v4);
    BIO_ADDR_rawmake(a, AF_INET, &v4, sizeof(v4), htons(port));
    return a;
}

/* A UDP socket bound to loopback; its address in *bound (to free). */
static int udp_socket(BIO_ADDR **bound)
{
    BIO_ADDR *any = loopback(0);
    union BIO_sock_info_u info;
    int s = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);

    BIO_bind(s, any, 0);
    *bound = BIO_ADDR_new();
    info.addr = *bound;
    BIO_sock_info(s, BIO_SOCK_INFO_ADDRESS, &info);
    BIO_ADDR_free(any);
    return s;
}

static int same_port(const BIO_ADDR *a, const BIO_ADDR *b)
{
    return BIO_ADDR_family(a) == BIO_ADDR_family(b) && BIO_ADDR_rawport(a) == BIO_ADDR_rawport(b);
}

static void datagrams(void)
{
    BIO_ADDR *addr_a, *addr_b, *peer = BIO_ADDR_new();
    int sa = udp_socket(&addr_a), sb = udp_socket(&addr_b), fd = -1, enabled = -1;
    BIO *a = BIO_new_dgram(sa, BIO_CLOSE), *b = BIO_new_dgram(sb, BIO_CLOSE);
    char buf[64];
    struct timeval tv = { 0, 200000 }, got;

    check(a != NULL && b != NULL && BIO_get_fd(a, &fd) == sa && fd == sa && BIO_method_type(a) == BIO_TYPE_DGRAM,
          "BIO_new_dgram wraps a UDP socket");
    check(BIO_dgram_set_peer(a, addr_b) == 1 && BIO_write(a, "hello", 5) == 5,
          "an unconnected BIO sends to the peer set");
    check(BIO_read(b, buf, sizeof(buf)) == 5 && memcmp(buf, "hello", 5) == 0,
          "the datagram arrives");
    check(BIO_dgram_get_peer(b, peer) == (int)sizeof(struct sockaddr_in) && same_port(peer, addr_a),
          "reading sets the peer to the sender");
    check(BIO_puts(b, "back") == 4 && BIO_read(a, buf, sizeof(buf)) == 4 && memcmp(buf, "back", 4) == 0,
          "replies go to the peer read from");
    check(BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEEK_MODE, 1, NULL) == 1 && BIO_write(a, "peek", 4) == 4
              && BIO_read(b, buf, 2) == 2 && BIO_read(b, buf, sizeof(buf)) == 4 && BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEEK_MODE, 0, NULL) == 1
              && BIO_read(b, buf, sizeof(buf)) == 4,
          "peek mode leaves the datagram queued");
    check(BIO_dgram_get_mtu_overhead(a) == 28 && BIO_ctrl(a, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0, NULL) == 548,
          "IPv4 header overhead and fallback MTU");
    check(BIO_dgram_set_mtu(a, 1200) == 1200 && BIO_dgram_get_mtu(a) == 1200, "the MTU set is kept");
    printf("# query MTU: %ld, discover: %ld, don't fragment: %ld\n", BIO_ctrl(a, BIO_CTRL_DGRAM_QUERY_MTU, 0, NULL),
           BIO_ctrl(a, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL), BIO_ctrl(a, BIO_CTRL_DGRAM_SET_DONT_FRAG, 1, NULL));
    ERR_clear_error();
    check(BIO_ctrl(b, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv) == 0
              && BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT, 0, &got) == (long)sizeof(got)
              && got.tv_sec == 0 && got.tv_usec >= 190000,
          "receive timeouts are set and read");
    check(BIO_read(b, buf, sizeof(buf)) == -1 && BIO_should_retry(b) && BIO_dgram_recv_timedout(b) == 1
              && BIO_dgram_recv_timedout(b) == 0,
          "a timed-out read retries, and the timeout is reported once");
    check(BIO_ctrl(b, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &tv) == 0
              && BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMEOUT, 0, &got) == (long)sizeof(got),
          "send timeouts too");
    check(BIO_dgram_get_local_addr_cap(a) == 1 && BIO_dgram_get_local_addr_enable(a, &enabled) == 1 && enabled == 0
              && BIO_dgram_get_effective_caps(a) == 15,
          "local addresses can be enabled; the effective capabilities");
    check(BIO_dgram_detect_peer_addr(b, peer) > 0 && same_port(peer, addr_a), "BIO_dgram_detect_peer_addr");
    check(BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, addr_a) == 1 && BIO_write(b, "c", 1) == -1
              && !BIO_should_retry(b),
          "a BIO marked connected writes with write(), which fails on an unconnected socket");
    check(BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, NULL) == 1 && BIO_dgram_get_peer(b, peer) > 0
              && BIO_ADDR_family(peer) == AF_UNSPEC,
          "unmarking clears the peer");
    BIO_set_nbio(a, 1);
    check(BIO_read(a, buf, sizeof(buf)) == -1 && BIO_should_retry(a) && BIO_should_read(a),
          "a non-blocking read with nothing there retries");
    check(BIO_pending(a) == 0 && BIO_wpending(a) == 0 && BIO_flush(a) == 1 && BIO_reset(a) == 0,
          "pending, flush, and reset");
    BIO_free(a);
    BIO_free(b);
    BIO_ADDR_free(addr_a);
    BIO_ADDR_free(addr_b);
    BIO_ADDR_free(peer);
}

static void messages(void)
{
    BIO_ADDR *addr_a, *addr_b, *from = BIO_ADDR_new(), *local = BIO_ADDR_new();
    int sa = udp_socket(&addr_a), sb = udp_socket(&addr_b);
    BIO *a = BIO_new_dgram(sa, BIO_CLOSE), *b = BIO_new_dgram(sb, BIO_CLOSE);
    char one[] = "one", two[] = "twotwo", in[2][16];
    BIO_MSG out[2], got[2];
    size_t done = 99;

    memset(out, 0, sizeof(out));
    memset(got, 0, sizeof(got));
    out[0].data = one;
    out[0].data_len = 3;
    out[0].peer = addr_b;
    out[1].data = two;
    out[1].data_len = 6;
    out[1].peer = addr_b;
    check(BIO_sendmmsg(a, out, sizeof(BIO_MSG), 1, 0, &done) == 1 && done == 1 && out[0].data_len == 3,
          "BIO_sendmmsg sends a message to its peer");
    got[0].data = in[0];
    got[0].data_len = sizeof(in[0]);
    got[0].peer = from;
    check(BIO_recvmmsg(b, got, sizeof(BIO_MSG), 1, 0, &done) == 1 && done == 1 && got[0].data_len == 3
              && memcmp(in[0], "one", 3) == 0 && same_port(from, addr_a),
          "BIO_recvmmsg receives it with its sender");
    got[0].local = local;
    check(BIO_recvmmsg(b, got, sizeof(BIO_MSG), 1, 0, &done) == 0 && done == 0
              && ERR_GET_REASON(ERR_get_error()) == BIO_R_LOCAL_ADDR_NOT_AVAILABLE,
          "local addresses must be enabled first");
    check(BIO_dgram_set_local_addr_enable(b, 1) == 1, "BIO_dgram_set_local_addr_enable");
    check(BIO_sendmmsg(a, &out[1], sizeof(BIO_MSG), 1, 0, &done) == 1 && done == 1, "another message");
    got[0].data_len = sizeof(in[0]);
    check(BIO_recvmmsg(b, got, sizeof(BIO_MSG), 1, 0, &done) == 1 && done == 1 && got[0].data_len == 6
              && (BIO_ADDR_family(local) == AF_INET || BIO_ADDR_family(local) == AF_UNSPEC),
          "it arrives with its destination address (or none, as macOS sometimes gives)");
    check(BIO_sendmmsg(a, out, sizeof(BIO_MSG), 0, 0, &done) == 1 && done == 0, "no messages is no work");
    BIO_free(a);
    BIO_free(b);
    BIO_ADDR_free(addr_a);
    BIO_ADDR_free(addr_b);
    BIO_ADDR_free(from);
    BIO_ADDR_free(local);
}

static void errors(void)
{
    check(BIO_dgram_non_fatal_error(EAGAIN) && BIO_dgram_non_fatal_error(EINTR) && !BIO_dgram_non_fatal_error(ENOTCONN)
              && !BIO_dgram_non_fatal_error(ECONNREFUSED),
          "BIO_dgram_non_fatal_error, which unlike sockets excludes ENOTCONN");
    check(BIO_err_is_non_fatal(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NON_FATAL)) == 1
              && BIO_err_is_non_fatal(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_BROKEN_PIPE)) == 0
              && BIO_err_is_non_fatal(ERR_SYSTEM_FLAG | EAGAIN) == 1
              && BIO_err_is_non_fatal(ERR_SYSTEM_FLAG | ECONNREFUSED) == 0,
          "BIO_err_is_non_fatal");
    {
        BIO *none = BIO_new_dgram(-1, BIO_NOCLOSE);

        check(none != NULL && BIO_get_fd(none, NULL) == -1, "a datagram BIO on no socket");
        BIO_free(none);
        none = BIO_new(BIO_s_datagram());
        check(none != NULL && BIO_get_init(none) == 0 && BIO_get_fd(none, NULL) == -1,
              "BIO_s_datagram makes one without a socket");
        BIO_free(none);
    }
}

int main(void)
{
    datagrams();
    messages();
    errors();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
