/*
 * Conformance test for socket addresses and lookups (BIO_ADDR(3), BIO_ADDRINFO(3),
 * BIO_lookup(3), BIO_parse_hostserv(3), and the deprecated BIO_get_host_ip and BIO_get_port),
 * in TAP format. Lookups use numeric hosts and the local services database, so they don't
 * depend on the network.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

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
    return ERR_GET_LIB(code) == lib && ERR_GET_REASON(code) == reason;
}

/* Compares an OPENSSL_malloc'd string with `expected` and frees it. */
static int is_text(char *got, const char *expected)
{
    int ok = got != NULL && expected != NULL ? strcmp(got, expected) == 0 : got == expected;

    if (!ok)
        printf("# got \"%s\", expected \"%s\"\n", got == NULL ? "(null)" : got,
               expected == NULL ? "(null)" : expected);
    OPENSSL_free(got);
    return ok;
}

static void addresses(void)
{
    BIO_ADDR *a = BIO_ADDR_new(), *copy;
    struct in_addr v4;
    struct in6_addr v6;
    unsigned char raw[16];
    size_t len = 0;
    char path[200];

    check(a != NULL && BIO_ADDR_family(a) == AF_UNSPEC, "BIO_ADDR_new makes an unspecified address");
    check(BIO_ADDR_rawport(a) == 0 && BIO_ADDR_rawaddress(a, NULL, &len) == 0
              && BIO_ADDR_path_string(a) == NULL,
          "an unspecified address has no port, raw address, or path");
    inet_pton(AF_INET, "127.0.0.1", &v4);
    check(BIO_ADDR_rawmake(a, AF_INET, &v4, sizeof(v4), htons(443)) == 1 && BIO_ADDR_family(a) == AF_INET
              && BIO_ADDR_rawport(a) == htons(443),
          "BIO_ADDR_rawmake makes an IPv4 address with a port in network order");
    check(BIO_ADDR_rawaddress(a, raw, &len) == 1 && len == 4 && memcmp(raw, &v4, 4) == 0,
          "BIO_ADDR_rawaddress copies the 4 address bytes");
    check(is_text(BIO_ADDR_hostname_string(a, 1), "127.0.0.1") && is_text(BIO_ADDR_service_string(a, 1), "443"),
          "numeric host and service strings");
    check(is_text(BIO_ADDR_service_string(a, 0), "https"), "a service name from the services database");
    check(BIO_ADDR_rawmake(a, AF_INET, &v4, 3, 0) == 0 && BIO_ADDR_rawmake(a, 12345, &v4, 4, 0) == 0,
          "a wrong length or an unknown family is refused");
    inet_pton(AF_INET6, "::1", &v6);
    check(BIO_ADDR_rawmake(a, AF_INET6, &v6, sizeof(v6), htons(8443)) == 1 && BIO_ADDR_family(a) == AF_INET6
              && BIO_ADDR_rawaddress(a, raw, &len) == 1 && len == 16
              && is_text(BIO_ADDR_hostname_string(a, 1), "::1") && is_text(BIO_ADDR_service_string(a, 1), "8443"),
          "an IPv6 address");
    copy = BIO_ADDR_dup(a);
    check(copy != NULL && BIO_ADDR_family(copy) == AF_INET6 && BIO_ADDR_rawport(copy) == htons(8443),
          "BIO_ADDR_dup copies it");
    BIO_ADDR_clear(copy);
    check(BIO_ADDR_family(copy) == AF_UNSPEC && BIO_ADDR_copy(a, copy) == 1 && BIO_ADDR_family(a) == AF_UNSPEC,
          "BIO_ADDR_clear unspecifies, and copying that unspecifies too");
    check(BIO_ADDR_copy(NULL, copy) == 0 && BIO_ADDR_copy(a, NULL) == 0 && BIO_ADDR_dup(NULL) == NULL,
          "null arguments are refused");
    check(BIO_ADDR_rawmake(a, AF_UNIX, "/tmp/sock", 9, 0) == 1 && BIO_ADDR_family(a) == AF_UNIX
              && is_text(BIO_ADDR_path_string(a), "/tmp/sock")
              && BIO_ADDR_rawaddress(a, NULL, &len) == 1 && len == 9 && BIO_ADDR_rawport(a) == 0,
          "a Unix-domain address");
    memset(path, 'p', sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
    check(BIO_ADDR_rawmake(a, AF_UNIX, path, sizeof(((struct sockaddr_un *)0)->sun_path), 0) == 0
              && BIO_ADDR_rawmake(a, AF_UNIX, path, sizeof(((struct sockaddr_un *)0)->sun_path) - 1, 0) == 1
              && BIO_ADDR_rawaddress(a, NULL, &len) == 1
              && len == sizeof(((struct sockaddr_un *)0)->sun_path) - 1,
          "a path must leave room for its NUL");
    BIO_ADDR_free(copy);
    BIO_ADDR_free(a);
    BIO_ADDR_free(NULL);
}

/* The value the outputs start with, to tell when they're left alone. */
static char untouched[] = "-";

/* Parses `spec` and checks the host and service it gives (NULL for none, "-" for untouched). */
static int parses(const char *spec, int prio, const char *host, const char *service)
{
    char *h = untouched, *s = untouched;
    int ok = BIO_parse_hostserv(spec, &h, &s, prio) == 1;

    if (host != NULL && strcmp(host, "-") == 0)
        ok = ok && h == untouched;
    else if (h == untouched)
        ok = 0;
    else
        ok = is_text(h, host) && ok;
    if (service != NULL && strcmp(service, "-") == 0)
        ok = ok && s == untouched;
    else if (s == untouched)
        ok = 0;
    else
        ok = is_text(s, service) && ok;
    return ok;
}

static void host_services(void)
{
    char *h = NULL, *s = NULL;

    check(parses("example.com:443", BIO_PARSE_PRIO_HOST, "example.com", "443"), "host:service");
    check(parses("[::1]:8443", BIO_PARSE_PRIO_HOST, "::1", "8443") && parses("[::1]", BIO_PARSE_PRIO_SERV, "::1", "-"),
          "a bracketed IPv6 host, with or without a service");
    check(parses("*:443", BIO_PARSE_PRIO_HOST, NULL, "443") && parses(":443", BIO_PARSE_PRIO_HOST, NULL, "443"),
          "an empty or * host is null");
    check(parses("host:", BIO_PARSE_PRIO_HOST, "host", NULL) && parses("host:*", BIO_PARSE_PRIO_SERV, "host", NULL),
          "an empty or * service is null");
    check(parses("443", BIO_PARSE_PRIO_SERV, "-", "443") && parses("443", BIO_PARSE_PRIO_HOST, "443", "-"),
          "without a colon, the priority decides");
    check(BIO_parse_hostserv("a:b:c", &h, &s, BIO_PARSE_PRIO_HOST) == 0
              && raised(ERR_LIB_BIO, BIO_R_AMBIGUOUS_HOST_OR_SERVICE),
          "several colons are ambiguous");
    check(BIO_parse_hostserv("[::1", &h, &s, BIO_PARSE_PRIO_HOST) == 0
              && raised(ERR_LIB_BIO, BIO_R_MALFORMED_HOST_OR_SERVICE)
              && BIO_parse_hostserv("[::1]x", &h, &s, BIO_PARSE_PRIO_HOST) == 0
              && raised(ERR_LIB_BIO, BIO_R_MALFORMED_HOST_OR_SERVICE)
              && BIO_parse_hostserv("[::1]:a:b", &h, &s, BIO_PARSE_PRIO_HOST) == 0
              && raised(ERR_LIB_BIO, BIO_R_MALFORMED_HOST_OR_SERVICE),
          "malformed brackets or services");
    check(BIO_parse_hostserv("h:s", NULL, NULL, BIO_PARSE_PRIO_HOST) == 1, "the outputs may be null");
}

static void lookups(void)
{
    BIO_ADDRINFO *res = NULL;
    const BIO_ADDR *ad;
    unsigned char ip[4] = { 0 };
    unsigned short port = 0;

    check(BIO_lookup("127.0.0.1", "443", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res) == 1 && res != NULL,
          "BIO_lookup of a numeric host and port");
    ad = BIO_ADDRINFO_address(res);
    check(BIO_ADDRINFO_family(res) == AF_INET && BIO_ADDRINFO_socktype(res) == SOCK_STREAM
              && BIO_ADDRINFO_protocol(res) == IPPROTO_TCP && BIO_ADDRINFO_next(res) == NULL
              && BIO_ADDR_rawport(ad) == htons(443) && is_text(BIO_ADDR_hostname_string(ad, 1), "127.0.0.1"),
          "its one entry");
    BIO_ADDRINFO_free(res);
    res = NULL;
    check(BIO_lookup_ex(NULL, "80", BIO_LOOKUP_SERVER, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &res) == 1
              && BIO_ADDRINFO_protocol(res) == IPPROTO_UDP
              && is_text(BIO_ADDR_hostname_string(BIO_ADDRINFO_address(res), 1), "0.0.0.0"),
          "a server lookup without a host binds to any address");
    BIO_ADDRINFO_free(res);
    res = NULL;
    check(BIO_lookup("127.0.0.1", "nosuchservice-x", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res) == 0
              && raised(ERR_LIB_BIO, ERR_R_SYS_LIB),
          "an unknown service fails with the lookup's error");
    check(BIO_lookup("127.0.0.1", "1", BIO_LOOKUP_CLIENT, 12345, SOCK_STREAM, &res) == 0
              && raised(ERR_LIB_BIO, BIO_R_UNSUPPORTED_PROTOCOL_FAMILY),
          "an unsupported family is refused");
    check(BIO_lookup("/tmp/unix.sock", NULL, BIO_LOOKUP_CLIENT, AF_UNIX, SOCK_STREAM, &res) == 1
              && BIO_ADDRINFO_family(res) == AF_UNIX && BIO_ADDRINFO_protocol(res) == 0
              && is_text(BIO_ADDR_path_string(BIO_ADDRINFO_address(res)), "/tmp/unix.sock"),
          "a Unix-domain lookup makes one entry for the path");
    BIO_ADDRINFO_free(res);
    BIO_ADDRINFO_free(NULL);
    check(BIO_ADDRINFO_next(NULL) == NULL && BIO_ADDRINFO_family(NULL) == 0 && BIO_ADDRINFO_socktype(NULL) == 0
              && BIO_ADDRINFO_protocol(NULL) == 0 && BIO_ADDRINFO_address(NULL) == NULL,
          "the accessors take null");
    check(BIO_get_host_ip("127.0.0.1", ip) == 1 && ip[0] == 127 && ip[3] == 1, "BIO_get_host_ip");
    check(BIO_get_port("443", &port) == 1 && port == 443, "BIO_get_port");
    check(BIO_get_port(NULL, &port) == 0 && raised(ERR_LIB_BIO, BIO_R_NO_PORT_DEFINED),
          "BIO_get_port needs a service");
}

int main(void)
{
    addresses();
    host_services();
    lookups();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
