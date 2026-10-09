/*
 * Conformance test for the connect BIO (BIO_s_connect(3), BIO_new_connect, BIO_do_connect, the
 * BIO_get_conn_* and BIO_set_conn_* controls, the info callback, datagram mode) and
 * BIO_do_connect_retry, in TAP format, over loopback with an accept BIO as the server. The
 * callback's sequence of states is printed, so it's compared too; ports are ephemeral, so only
 * their relations are checked.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static char trace[256];

static int info_callback(BIO *b, int state, int ret)
{
    size_t used = strlen(trace);

    (void)b;
    snprintf(trace + used, sizeof(trace) - used, "%d:%d ", state, ret);
    return ret;
}

/* A listening accept BIO on loopback; its port as a string in `port`. */
static BIO *server(char *port, size_t size)
{
    BIO *acc = BIO_new_accept("127.0.0.1:0");

    if (acc == NULL || BIO_do_accept(acc) <= 0)
        return NULL;
    snprintf(port, size, "%s", BIO_get_accept_port(acc));
    return acc;
}

static void connecting(void)
{
    char port[16], target[64], buf[32];
    BIO *acc = server(port, sizeof(port)), *conn, *peer = NULL, *copy;
    const BIO_ADDR *ad;
    const char *any = NULL;
    int fd = -1, ret;

    snprintf(target, sizeof(target), "127.0.0.1:%s", port);
    conn = BIO_new_connect(target);
    check(conn != NULL && strcmp(BIO_get_conn_hostname(conn), "127.0.0.1") == 0
              && strcmp(BIO_get_conn_port(conn), port) == 0 && BIO_get_fd(conn, NULL) == -1,
          "BIO_new_connect parses host:port");
    check(BIO_set_info_callback(conn, info_callback) == 1, "BIO_set_info_callback");
    check(BIO_do_connect(conn) == 1, "BIO_do_connect connects");
    printf("# states: %s\n", trace);
    ad = BIO_get_conn_address(conn);
    ret = BIO_get_fd(conn, &fd);
    check(ad != NULL && BIO_ADDR_family(ad) == AF_INET && ret == fd && fd >= 0,
          "the address and the socket");
    /* The family and mode macros pass a null pointer, which the control refuses: always 0. */
    check(BIO_get_conn_ip_family(conn) == 0 && BIO_get_conn_mode(conn) == 0
              && BIO_ctrl(conn, BIO_C_GET_CONNECT, 3, &any) == BIO_FAMILY_IPV4
              && BIO_ctrl(conn, BIO_C_GET_CONNECT, 4, &any) == 0,
          "the family and mode, through the control with a pointer");
    check(BIO_do_accept(acc) == 1 && (peer = BIO_pop(acc)) != NULL, "the server accepts it");
    check(BIO_puts(conn, "line one\nline two\n") == 18, "writes go through");
    check(BIO_gets(peer, buf, sizeof(buf)) == -2 && raised(BIO_R_UNSUPPORTED_METHOD),
          "the accepted socket BIO has no gets");
    check(BIO_write(peer, "reply\nmore", 10) == 10 && BIO_gets(conn, buf, sizeof(buf)) == 6
              && strcmp(buf, "reply\n") == 0 && BIO_read(conn, buf, sizeof(buf)) == 4,
          "the connect BIO reads lines a byte at a time");
    check(BIO_pending(conn) == 0 && BIO_flush(conn) == 1 && BIO_eof(conn) == 0, "pending, flush, and eof");
    copy = BIO_dup_chain(conn);
    check(copy != NULL && strcmp(BIO_get_conn_hostname(copy), "127.0.0.1") == 0
              && strcmp(BIO_get_conn_port(copy), port) == 0,
          "BIO_dup_chain copies the target");
    BIO_free(copy);
    BIO_free(peer);
    BIO_free(conn);
    check(BIO_reset(acc) == 0, "the server stops listening");
    trace[0] = '\0';
    conn = BIO_new_connect(target);
    check(BIO_set_info_callback(conn, info_callback) == 1, "BIO_set_info_callback");
    /*
     * The callback returns 0 after the failed connect, which ends the state machine before it
     * raises BIO_R_CONNECT_ERROR: the system error is the last one.
     */
    check(BIO_do_connect(conn) <= 0 && ERR_GET_LIB(ERR_peek_last_error()) == ERR_LIB_SYS
              && ERR_GET_REASON(ERR_peek_last_error()) == ECONNREFUSED,
          "connecting to a closed port fails");
    ERR_clear_error();
    printf("# states: %s\n", trace);
    BIO_free(conn);
    BIO_free(acc);

    conn = BIO_new(BIO_s_connect());
    check(BIO_do_connect(conn) <= 0 && raised(BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED),
          "a connect BIO needs a target");
    check(BIO_set_conn_port(conn, "1") == 1 && BIO_set_conn_ip_family(conn, 99) == 1
              && BIO_do_connect(conn) <= 0 && raised(BIO_R_UNSUPPORTED_IP_FAMILY),
          "an unknown family is refused");
    BIO_free(conn);
}

static void nonblocking(void)
{
    char port[16], target[64];
    BIO *acc = server(port, sizeof(port)), *conn, *peer = NULL;
    const char *any = NULL;
    int ret;

    snprintf(target, sizeof(target), "127.0.0.1:%s", port);
    conn = BIO_new_connect(target);
    check(BIO_set_nbio(conn, 1) == 1 && BIO_ctrl(conn, BIO_C_GET_CONNECT, 4, &any) == BIO_SOCK_NONBLOCK,
          "BIO_set_nbio");
    ret = BIO_do_connect(conn);
    check(ret == 1 || (ret <= 0 && BIO_should_io_special(conn) && BIO_get_retry_reason(conn) == BIO_RR_CONNECT),
          "a non-blocking connect may have to be retried");
    check(BIO_do_connect_retry(conn, 5, 10) == 1, "BIO_do_connect_retry finishes it");
    check(BIO_do_accept(acc) == 1 && (peer = BIO_pop(acc)) != NULL && BIO_write(conn, "nb", 2) == 2,
          "and data flows");
    BIO_free(peer);
    BIO_free(conn);
    BIO_free(acc);
}

static void datagram(void)
{
    BIO *conn = BIO_new(BIO_s_connect()), *dgram = NULL;

    check(BIO_get_sock_type(conn) == SOCK_STREAM && BIO_set_sock_type(conn, 42) == 0
              && BIO_set_sock_type(conn, SOCK_DGRAM) == 1 && BIO_get_sock_type(conn) == SOCK_DGRAM,
          "the socket type can be set before connecting");
    check(BIO_set_conn_hostname(conn, "127.0.0.1:9") == 1 && BIO_do_connect(conn) == 1,
          "a datagram connect needs no listener");
    check(BIO_ctrl(conn, BIO_C_GET_DGRAM_BIO, 0, &dgram) == 1 && dgram != NULL && BIO_method_type(dgram) == BIO_TYPE_DGRAM,
          "it wraps a datagram BIO");
    check(BIO_set_sock_type(conn, SOCK_STREAM) == 0, "but not after connecting");
    check(BIO_write(conn, "u", 1) == 1, "writes go through the datagram BIO");
    check(BIO_gets(conn, (char[8]){ 0 }, 8) == -1 && raised(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED),
          "gets isn't for datagrams");
    BIO_free(conn);
}

int main(void)
{
    connecting();
    nonblocking();
    datagram();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
