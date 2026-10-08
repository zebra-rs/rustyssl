/*
 * Conformance test for the socket helpers (BIO_socket(3), BIO_connect(3), BIO_listen(3),
 * BIO_accept_ex, ...), the socket BIO (BIO_s_socket(3)), the accept BIO (BIO_s_accept(3)),
 * BIO_wait, BIO_do_connect_retry, OSSL_sleep, and the deprecated socket functions, in TAP
 * format. Everything runs over loopback; ports are ephemeral, so only their relations are
 * checked. Results that depend on the platform's settings (TCP Fast Open) are printed as
 * comments, which must match too.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
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

/* Whether the newest error is `reason` from `lib`; clears the queue. */
static int raised(int lib, int reason)
{
    unsigned long code = ERR_peek_last_error();

    ERR_clear_error();
    if (ERR_GET_LIB(code) != lib || ERR_GET_REASON(code) != reason)
        printf("# error %d/%d, expected %d/%d\n", ERR_GET_LIB(code), ERR_GET_REASON(code), lib, reason);
    return ERR_GET_LIB(code) == lib && ERR_GET_REASON(code) == reason;
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

/* The local port of a socket, in host order. */
static unsigned short local_port(int s)
{
    BIO_ADDR *a = BIO_ADDR_new();
    union BIO_sock_info_u info;
    unsigned short port = 0;

    info.addr = a;
    if (BIO_sock_info(s, BIO_SOCK_INFO_ADDRESS, &info))
        port = ntohs(BIO_ADDR_rawport(a));
    BIO_ADDR_free(a);
    return port;
}

static void helpers(void)
{
    BIO_ADDR *any = loopback(0), *peer = BIO_ADDR_new(), *target;
    int s, c, a, value = 0;
    unsigned short port;
    char *name = NULL;

    check(BIO_sock_init() == 1, "BIO_sock_init returns 1");
    check(BIO_sock_non_fatal_error(EAGAIN) && BIO_sock_non_fatal_error(EINTR) && BIO_sock_non_fatal_error(EINPROGRESS)
              && !BIO_sock_non_fatal_error(ECONNREFUSED) && !BIO_sock_non_fatal_error(0),
          "BIO_sock_non_fatal_error knows the errors to retry");
    errno = EAGAIN;
    check(BIO_sock_should_retry(-1) == 1 && BIO_sock_should_retry(5) == 0, "BIO_sock_should_retry reads errno");
    s = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);
    check(s >= 0 && BIO_listen(s, any, BIO_SOCK_REUSEADDR) == 1, "BIO_socket and BIO_listen");
    port = local_port(s);
    check(port != 0, "BIO_sock_info gives the bound address");
    target = loopback(port);
    c = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);
    check(BIO_connect(c, target, BIO_SOCK_NODELAY | BIO_SOCK_KEEPALIVE) == 1, "BIO_connect with options");
    a = BIO_accept_ex(s, peer, 0);
    check(a >= 0 && BIO_ADDR_family(peer) == AF_INET && (name = BIO_ADDR_hostname_string(peer, 1)) != NULL
              && strcmp(name, "127.0.0.1") == 0,
          "BIO_accept_ex gives the peer's address");
    OPENSSL_free(name);
    check(BIO_sock_error(c) == 0 && BIO_set_tcp_ndelay(c, 1) == 1, "BIO_sock_error and BIO_set_tcp_ndelay");
    check(write(c, "abc", 3) == 3 && BIO_socket_wait(a, 1, time(NULL) + 5) == 1
              && BIO_socket_ioctl(a, FIONREAD, &value) == 0 && value == 3,
          "BIO_socket_wait and BIO_socket_ioctl");
    check(BIO_socket_wait(a, 1, 0) == 1 && BIO_socket_wait(-1, 1, time(NULL) + 1) == -1
              && BIO_socket_wait(a, 0, 1) == 0,
          "BIO_socket_wait without a deadline, for a bad socket, and past its deadline");
    check(BIO_socket_nbio(a, 1) == 1 && BIO_socket_nbio(a, 0) == 1, "BIO_socket_nbio");
    check(BIO_socket_nbio(-1, 1) == 0 && raised(ERR_LIB_SYS, EBADF), "BIO_socket_nbio raises the system error");
    check(BIO_closesocket(a) == 1 && BIO_closesocket(c) == 1 && BIO_closesocket(-1) == 0, "BIO_closesocket");
    check(BIO_connect(-1, target, 0) == 0 && raised(ERR_LIB_BIO, BIO_R_INVALID_SOCKET)
              && BIO_listen(-1, target, 0) == 0 && raised(ERR_LIB_BIO, BIO_R_INVALID_SOCKET),
          "an invalid socket is refused");
    BIO_closesocket(s);
    c = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);
    check(BIO_connect(c, target, 0) == 0 && raised(ERR_LIB_BIO, BIO_R_CONNECT_ERROR),
          "connecting to a closed port fails");
    BIO_closesocket(c);
    s = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);
    printf("# listen with TCP Fast Open: %d\n", BIO_listen(s, any, BIO_SOCK_TFO));
    ERR_clear_error();
    BIO_closesocket(s);
    s = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    check(BIO_bind(s, any, BIO_SOCK_REUSEADDR) == 1 && local_port(s) != 0
              && BIO_bind(-1, any, 0) == 0 && raised(ERR_LIB_BIO, BIO_R_INVALID_SOCKET),
          "BIO_bind binds a datagram socket");
    BIO_closesocket(s);
    s = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
    check(BIO_listen(s, any, 0) == 1 && local_port(s) != 0, "BIO_listen only binds a datagram socket");
    BIO_closesocket(s);
    check(BIO_sock_info(0, 99, NULL) == 0 && raised(ERR_LIB_BIO, BIO_R_UNKNOWN_INFO_TYPE),
          "BIO_sock_info knows one type");
    BIO_ADDR_free(any);
    BIO_ADDR_free(peer);
    BIO_ADDR_free(target);
}

/* Connects a client to a listening socket; returns the client's socket. */
static int connect_to(unsigned short port)
{
    BIO_ADDR *target = loopback(port);
    int c = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);

    if (!BIO_connect(c, target, 0)) {
        BIO_closesocket(c);
        c = -1;
    }
    BIO_ADDR_free(target);
    return c;
}

/* Reads exactly `len` bytes from a blocking socket BIO, which TCP may deliver in pieces. */
static int read_all(BIO *b, char *buf, int len)
{
    int got = 0, n;

    while (got < len && (n = BIO_read(b, buf + got, len - got)) > 0)
        got += n;
    return got;
}

static void socket_bios(void)
{
    BIO_ADDR *any = loopback(0);
    int s = BIO_socket(AF_INET, SOCK_STREAM, 0, 0), c, a, fd = -1;
    BIO *bc, *ba;
    char buf[32];

    BIO_listen(s, any, BIO_SOCK_REUSEADDR);
    c = connect_to(local_port(s));
    a = BIO_accept_ex(s, NULL, 0);
    bc = BIO_new_socket(c, BIO_CLOSE);
    ba = BIO_new_socket(a, BIO_CLOSE);
    check(bc != NULL && ba != NULL && BIO_get_fd(ba, &fd) == a && fd == a && BIO_get_close(ba) == BIO_CLOSE,
          "BIO_new_socket wraps a socket");
    check(BIO_write(bc, "hello", 5) == 5 && BIO_puts(bc, " world") == 6,
          "writes go to the socket");
    check(read_all(ba, buf, 11) == 11 && memcmp(buf, "hello world", 11) == 0,
          "reads come from the socket");
    check(BIO_gets(ba, buf, sizeof(buf)) == -2 && raised(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD),
          "socket BIOs have no gets");
    BIO_socket_nbio(a, 1);
    check(BIO_read(ba, buf, sizeof(buf)) == -1 && BIO_should_retry(ba) && BIO_should_read(ba),
          "a non-blocking read with nothing there retries");
    check(BIO_pending(ba) == 0 && BIO_flush(ba) == 1 && BIO_eof(ba) == 0, "pending, flush, and eof");
    BIO_free(bc);
    BIO_socket_wait(a, 1, time(NULL) + 5);
    check(BIO_read(ba, buf, sizeof(buf)) == 0 && !BIO_should_retry(ba) && BIO_eof(ba) == 1,
          "the peer's close is the end of input");
    check(BIO_wait(ba, 0, 0) == 1, "BIO_wait without a deadline succeeds at once");
    check(BIO_do_connect_retry(ba, 1, 10) == -1 && raised(ERR_LIB_BIO, BIO_R_CONNECT_ERROR),
          "BIO_do_connect_retry on a BIO that can't connect fails");
    check(BIO_do_connect_retry(NULL, 1, 10) == -1 && raised(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER),
          "BIO_do_connect_retry needs a BIO");
    BIO_free(ba);
    bc = BIO_new(BIO_s_socket());
    check(BIO_get_fd(bc, NULL) == -1 && BIO_set_close(bc, BIO_NOCLOSE) == 1 && BIO_get_close(bc) == BIO_NOCLOSE,
          "a socket BIO without a socket");
    BIO_free(bc);
    ba = BIO_new(BIO_s_mem());
    check(BIO_wait(ba, time(NULL) - 10, 0) == 0 && raised(ERR_LIB_BIO, BIO_R_TRANSFER_TIMEOUT),
          "BIO_wait past its deadline times out");
    BIO_free(ba);
    OSSL_sleep(5);
    BIO_closesocket(s);
    BIO_ADDR_free(any);
}

static void accept_bios(void)
{
    BIO *acc = BIO_new_accept("127.0.0.1:0"), *conn, *client, *chain;
    char buf[32], expected[32];
    const char *text;
    int c, port;

    check(acc != NULL && BIO_do_accept(acc) == 1, "the first BIO_do_accept binds and listens");
    text = BIO_get_accept_name(acc);
    check(text != NULL && strcmp(text, "127.0.0.1") == 0, "BIO_get_accept_name");
    port = atoi(BIO_get_accept_port(acc));
    check(port > 0 && BIO_get_accept_ip_family(acc) == BIO_FAMILY_IPV4 && BIO_get_fd(acc, NULL) >= 0,
          "the listening port, family, and socket");
    c = connect_to((unsigned short)port);
    check(c >= 0 && BIO_do_accept(acc) == 1, "the second BIO_do_accept accepts a connection");
    text = BIO_get_peer_name(acc);
    check(text != NULL && strcmp(text, "127.0.0.1") == 0 && BIO_get_peer_port(acc) != NULL,
          "the peer's name and port");
    conn = BIO_pop(acc);
    check(conn != NULL && BIO_method_type(conn) == BIO_TYPE_SOCKET, "the connection is a socket BIO");
    client = BIO_new_socket(c, BIO_CLOSE);
    check(BIO_write(client, "ping", 4) == 4 && BIO_read(conn, buf, sizeof(buf)) == 4
              && memcmp(buf, "ping", 4) == 0,
          "data flows over the accepted connection");
    BIO_free(conn);
    BIO_free(client);

    chain = BIO_new(BIO_f_buffer());
    check(BIO_set_accept_bios(acc, chain) == 1, "BIO_set_accept_bios");
    c = connect_to((unsigned short)port);
    client = BIO_new_socket(c, BIO_CLOSE);
    check(BIO_write(client, "pong", 4) == 4 && BIO_read(acc, buf, 4) == 4 && memcmp(buf, "pong", 4) == 0,
          "a read accepts the next connection behind a copy of the chain");
    conn = BIO_pop(acc);
    check(conn != NULL && BIO_method_type(conn) == BIO_TYPE_BUFFER
              && BIO_method_type(BIO_next(conn)) == BIO_TYPE_SOCKET,
          "the chain is in front of the socket");
    BIO_free_all(conn);
    BIO_free(client);

    check(BIO_set_nbio_accept(acc, 1) == 1 && BIO_set_bind_mode(acc, BIO_BIND_REUSEADDR) == 1
              && BIO_get_bind_mode(acc) == BIO_BIND_REUSEADDR,
          "accept and bind modes");
    BIO_free(acc);

    acc = BIO_new_accept("127.0.0.1:0");
    (void)BIO_set_nbio_accept(acc, 1);
    check(BIO_do_accept(acc) == 1 && BIO_do_accept(acc) == -1 && BIO_should_io_special(acc)
              && BIO_get_retry_reason(acc) == BIO_RR_ACCEPT,
          "a non-blocking accept with no connection retries");
    snprintf(expected, sizeof(expected), "%d", atoi(BIO_get_accept_port(acc)));
    check(BIO_reset(acc) == 0 && BIO_get_fd(acc, NULL) == -1, "BIO_reset closes the listening socket");
    BIO_free(acc);

    acc = BIO_new(BIO_s_accept());
    check(BIO_do_accept(acc) == -1 && raised(ERR_LIB_BIO, BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED),
          "an accept BIO needs an address");
    BIO_free(acc);
    check(BIO_new_accept("a:b:c") == NULL && raised(ERR_LIB_BIO, BIO_R_AMBIGUOUS_HOST_OR_SERVICE),
          "BIO_new_accept parses its argument");
}

static void deprecated(void)
{
    int s = BIO_get_accept_socket((char *)"127.0.0.1:0", 1), c, a;
    char *ip_port = NULL;

    check(s >= 0, "BIO_get_accept_socket listens");
    c = connect_to(local_port(s));
    a = BIO_accept(s, &ip_port);
    check(a >= 0 && ip_port != NULL && strncmp(ip_port, "127.0.0.1:", 10) == 0,
          "BIO_accept gives host:port");
    OPENSSL_free(ip_port);
    BIO_closesocket(a);
    BIO_closesocket(c);
    BIO_socket_nbio(s, 1);
    check(BIO_accept(s, NULL) == -2, "a non-blocking BIO_accept with no connection returns -2");
    BIO_closesocket(s);
    check(BIO_gethostbyname("127.0.0.1") != NULL, "BIO_gethostbyname");
}

int main(void)
{
    helpers();
    socket_bios();
    accept_bios();
    deprecated();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
