/*
 * Conformance test for the HTTP client (OSSL_HTTP_REQ_CTX(3), OSSL_HTTP_transfer(3),
 * OSSL_HTTP_parse_url(3), OCSP_sendreq_new(3), X509_load_http(3)): requests written to memory
 * BIOs and compared octet by octet, canned responses read (text, ASN.1 with short and long
 * lengths, redirections, errors, bad and inconsistent headers, limits, keep-alive), the
 * refusal of CR and LF in what goes into a request; and against a server forked here on the
 * loopback interface: GET with redirections (relative, absolute, too many), a proxy, CONNECT
 * (with Basic authentication, and refused), the TLS callback, OCSP over HTTP, and
 * certificates and CRLs loaded by URL. The server logs each request it gets.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/http.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int failures = 0;
static int number = 0;
static char port_text[16];

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Prints the text with the server's port as PORT, and CR and LF as \r and \n. */
static void show(const char *s, size_t n)
{
    size_t i, pl = strlen(port_text);

    for (i = 0; i < n; i++) {
        if (pl > 0 && i + pl <= n && memcmp(s + i, port_text, pl) == 0) {
            printf("PORT");
            i += pl - 1;
        } else if (s[i] == '\r') {
            printf("\\r");
        } else if (s[i] == '\n') {
            printf("\\n");
        } else if (s[i] < 0x20 || s[i] > 0x7e) {
            printf("\\x%02x", (unsigned char)s[i]);
        } else {
            putchar(s[i]);
        }
    }
}

/* The error queue: each entry's library and reason, and its text when it has one. */
static void errors(void)
{
    unsigned long e;
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0') {
            printf(" [");
            show(data, strlen(data));
            printf("]");
        }
    }
    printf("\n");
}

/* The memory BIO's contents, shown, then emptied. */
static void sent(const char *label, BIO *b)
{
    char *p;
    long n = BIO_get_mem_data(b, &p);

    printf("  %s (%ld): ", label, n);
    show(p, n > 0 ? (size_t)n : 0);
    printf("\n");
    (void)BIO_reset(b);
}

/*
 * Made with the reference's openssl tool: the EC root of the CMS and OCSP tests in DER
 * (ca.der) and an empty CRL it issued (crl.der).
 */
static const unsigned char CA_DER[] = {
    0x30, 0x82, 0x01, 0x94, 0x30, 0x82, 0x01, 0x3a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x42,
    0xcf, 0x19, 0x12, 0xb3, 0x16, 0x3c, 0x87, 0xa7, 0x68, 0x3f, 0xee, 0x3b, 0x39, 0x70, 0xa3, 0x1c,
    0xb0, 0x96, 0x79, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x27, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x45, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x53, 0x4d,
    0x49, 0x4d, 0x45, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x30,
    0x31, 0x37, 0x32, 0x32, 0x31, 0x37, 0x31, 0x35, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x30,
    0x39, 0x32, 0x33, 0x32, 0x32, 0x31, 0x37, 0x31, 0x35, 0x5a, 0x30, 0x27, 0x31, 0x10, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x53, 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x52,
    0x6f, 0x6f, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x1f, 0xc0,
    0x2d, 0x35, 0x5c, 0x38, 0xd5, 0x1f, 0x54, 0xd2, 0x56, 0xf8, 0x8f, 0x26, 0xfa, 0x91, 0x59, 0x66,
    0xfd, 0x84, 0xd6, 0x7b, 0x9e, 0x6a, 0x8b, 0x48, 0xc6, 0xdc, 0xae, 0x0a, 0xe5, 0x3b, 0xbe, 0x0b,
    0x57, 0xf8, 0x1e, 0x62, 0xa7, 0x1e, 0xea, 0x2e, 0xa6, 0xc2, 0xa5, 0x77, 0x3b, 0xb9, 0x3c, 0x39,
    0xf9, 0x55, 0x14, 0xd3, 0x7e, 0x4f, 0xdf, 0xae, 0xb9, 0x1e, 0x58, 0x65, 0x13, 0x4f, 0xa3, 0x42,
    0x30, 0x40, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
    0x02, 0x01, 0x06, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x75, 0xb5,
    0xd3, 0x50, 0x79, 0xdb, 0x54, 0xb4, 0x38, 0xa5, 0x97, 0x03, 0x21, 0x5b, 0x00, 0xf0, 0x1d, 0x68,
    0xa0, 0x45, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48,
    0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0x99, 0xde, 0xd0, 0xd8, 0x7e, 0xa9, 0xa3, 0x8f, 0xc9, 0xf1,
    0xc7, 0xf7, 0x5d, 0x7b, 0x48, 0x7d, 0xff, 0x1e, 0x83, 0x6c, 0xba, 0x00, 0xad, 0x92, 0x37, 0x13,
    0xb3, 0xe9, 0x0d, 0x09, 0x1c, 0x99, 0x02, 0x20, 0x73, 0x21, 0x81, 0xae, 0x38, 0x27, 0x22, 0xe7,
    0x6f, 0xca, 0x9a, 0x24, 0xfb, 0x4d, 0x7a, 0xce, 0xa0, 0xba, 0x0f, 0x8d, 0x66, 0xa0, 0xf4, 0x58,
    0xd0, 0x39, 0xf2, 0xd6, 0x2a, 0x9e, 0x09, 0x90
};

static const unsigned char CRL_DER[] = {
    0x30, 0x81, 0xc1, 0x30, 0x68, 0x02, 0x01, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x04, 0x03, 0x02, 0x30, 0x27, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x07, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0a, 0x53, 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x17, 0x0d, 0x32,
    0x36, 0x31, 0x30, 0x31, 0x38, 0x30, 0x33, 0x32, 0x38, 0x32, 0x35, 0x5a, 0x18, 0x0f, 0x32, 0x31,
    0x32, 0x36, 0x30, 0x39, 0x32, 0x34, 0x30, 0x33, 0x32, 0x38, 0x32, 0x35, 0x5a, 0xa0, 0x0e, 0x30,
    0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x14, 0x04, 0x03, 0x02, 0x01, 0x01, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21,
    0x00, 0x87, 0x97, 0x51, 0x62, 0xe8, 0xcc, 0x68, 0x09, 0xd9, 0xcb, 0x75, 0xe2, 0x97, 0x92, 0x93,
    0x23, 0x48, 0x69, 0xb0, 0x35, 0x62, 0x25, 0x2c, 0x0e, 0x83, 0x9f, 0x97, 0x66, 0xa2, 0xde, 0xf6,
    0x96, 0x02, 0x21, 0x00, 0xd7, 0x1f, 0xc2, 0xc7, 0xf7, 0x56, 0x8d, 0xcf, 0x92, 0x49, 0x2c, 0x7d,
    0xd7, 0x02, 0xf9, 0x1b, 0xf8, 0xcc, 0x8b, 0x83, 0x4e, 0x10, 0xcf, 0x77, 0x66, 0x3c, 0xcf, 0xd1,
    0x16, 0xb0, 0x81, 0xb1
};

/* A minimal OCSPResponse: malformedRequest. */
static const unsigned char OCSP_MALFORMED[] = { 0x30, 0x03, 0x0a, 0x01, 0x01 };

static void parse_urls(void)
{
    static const char *const urls[] = {
        "http://host/path?q#f", "https://u@[::1]/", "host:8080", "ftp://host/", "http://h:0/x",
        "https://h:0", "//h/p", "http://h:99999/", NULL
    };
    int i;

    printf("# OSSL_HTTP_parse_url\n");
    for (i = 0; urls[i] != NULL; i++) {
        int ssl = -1, num = -1;
        char *user = NULL, *host = NULL, *port = NULL, *path = NULL, *query = NULL, *frag = NULL;
        int r = OSSL_HTTP_parse_url(urls[i], &ssl, &user, &host, &port, &num, &path, &query, &frag);

        printf("  %s: %d ssl=%d user=%s host=%s port=%s num=%d path=%s query=%s frag=%s\n", urls[i], r, ssl,
               user ? user : "(null)", host ? host : "(null)", port ? port : "(null)", num,
               path ? path : "(null)", query ? query : "(null)", frag ? frag : "(null)");
        errors();
        OPENSSL_free(user);
        OPENSSL_free(host);
        OPENSSL_free(port);
        OPENSSL_free(path);
        OPENSSL_free(query);
        OPENSSL_free(frag);
    }
    check(OSSL_HTTP_parse_url("http://h/", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == 1, "no outputs");

    printf("# OSSL_HTTP_adapt_proxy\n");
    {
        static const char *const servers[] = { "h", "a.b", "[::1]", "x.a.b", "", NULL };
        static const char *const lists[] = { NULL, "a.b", "h, a.b", "x.a.bb,a.b", "::1", "", NULL };
        int s, l;

        for (s = 0; servers[s] != NULL; s++)
            for (l = 0; l < 6; l++) {
                const char *p = OSSL_HTTP_adapt_proxy("http://proxy:8080", lists[l], servers[s], 0);

                printf("  %s / %s: %s\n", servers[s], lists[l] ? lists[l] : "(null)", p ? p : "(null)");
            }
        /* CVE-2025-9232: a bracketed host longer than NI_MAXHOST was copied past its buffer. */
        {
            char longhost[3000];

            longhost[0] = '[';
            memset(longhost + 1, 'a', sizeof(longhost) - 3);
            longhost[sizeof(longhost) - 2] = ']';
            longhost[sizeof(longhost) - 1] = '\0';
            printf("  CVE-2025-9232, a long bracketed host: %s\n",
                   OSSL_HTTP_adapt_proxy("http://proxy:8080", "aaaa", longhost, 0) ? "set" : "(null)");
            printf("  an empty bracketed host: %s\n", OSSL_HTTP_adapt_proxy("http://proxy:8080", "x", "[]", 0) ? "set" : "(null)");
            printf("  a lone bracket: %s\n", OSSL_HTTP_adapt_proxy("http://proxy:8080", "[", "[", 0) ? "set" : "(null)");
        }
        printf("  no proxy: %s\n", OSSL_HTTP_adapt_proxy(NULL, NULL, "h", 0) ? "set" : "(null)");
        printf("  empty: %s\n", OSSL_HTTP_adapt_proxy("", NULL, "h", 0) ? "set" : "(null)");
        setenv("http_proxy", "http://env-proxy:3128", 1);
        setenv("HTTPS_PROXY", "http://env-sproxy:3128", 1);
        setenv("no_proxy", "skip.me", 1);
        printf("  http env: %s\n", OSSL_HTTP_adapt_proxy(NULL, NULL, "h", 0));
        printf("  https env: %s\n", OSSL_HTTP_adapt_proxy(NULL, NULL, "h", 1));
        printf("  no_proxy env: %s\n", OSSL_HTTP_adapt_proxy(NULL, NULL, "skip.me", 0) ? "set" : "(null)");
        unsetenv("http_proxy");
        unsetenv("HTTPS_PROXY");
        unsetenv("no_proxy");
    }
}

static void show_bio(const char *label, BIO *b)
{
    char buf[512];
    int n = b == NULL ? -1 : BIO_read(b, buf, sizeof(buf));

    printf("  %s (%d): ", label, n);
    show(buf, n > 0 ? (size_t)n : 0);
    printf("\n");
}

/* A context over a memory BIO to write to and one with the response to read. */
static OSSL_HTTP_REQ_CTX *canned(BIO **w, BIO **r, const char *resp, size_t n, int buf_size)
{
    *w = BIO_new(BIO_s_mem());
    *r = BIO_new(BIO_s_mem());
    BIO_write(*r, resp, (int)n);
    BIO_set_mem_eof_return(*r, 0);
    return OSSL_HTTP_REQ_CTX_new(*w, *r, buf_size);
}

/* Runs a GET of /p expecting `ct` (and ASN.1 or not), and shows what came of it. */
static void run(const char *label, const char *resp, size_t n, const char *ct, int asn1, int buf_size,
                size_t max_lines, unsigned long max_len, int keep)
{
    BIO *w, *r, *got;
    OSSL_HTTP_REQ_CTX *rctx = canned(&w, &r, resp, n, buf_size);

    printf("# %s\n", label);
    OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/p");
    OSSL_HTTP_REQ_CTX_set_expected(rctx, ct, asn1, 0, keep);
    if (max_lines != (size_t)-1)
        OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(rctx, max_lines);
    if (max_len != 0)
        OSSL_HTTP_REQ_CTX_set_max_response_length(rctx, max_len);
    got = OSSL_HTTP_REQ_CTX_exchange(rctx);
    printf("  exchange: %s, resp_len %zu, alive %d\n", got == NULL ? "NULL" : got == r ? "the stream" : "the memory BIO",
           OSSL_HTTP_REQ_CTX_get_resp_len(rctx), OSSL_HTTP_is_alive(rctx));
    errors();
    if (got != NULL) {
        char buf[512];
        int k = BIO_read(got, buf, sizeof(buf));

        printf("  content (%d): ", k);
        show(buf, k > 0 ? (size_t)k : 0);
        printf("\n");
    }
    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(w);
    BIO_free(r);
}

#define RUN(label, resp, ct, asn1) run(label, resp, sizeof(resp) - 1, ct, asn1, 0, (size_t)-1, 0, 0)

static void canned_responses(void)
{
    static const char der_short[] = "HTTP/1.0 200 OK\r\nContent-Type: application/x\r\n\r\n\x30\x03\x02\x01\x05tail";
    static const char der_long[] = "HTTP/1.1 200 OK\r\nContent-Length: 133\r\n\r\n\x30\x81\x82"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char big[300];

    RUN("text", "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nhello\n", "text/plain", 0);
    RUN("text with a charset", "HTTP/1.0 200 OK\r\nContent-Type: Text/Plain; charset=utf-8\r\n\r\nhi\n",
        "text/plain", 0);
    RUN("the wrong content type", "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nhi\n", "text/plain", 0);
    RUN("no content type", "HTTP/1.0 200 OK\r\n\r\nhi\n", "text/plain", 0);
    RUN("ASN.1", der_short, NULL, 1);
    RUN("ASN.1 with a long length", der_long, NULL, 1);
    RUN("ASN.1 with a length that disagrees", "HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\n\x30\x03\x02\x01\x05", NULL,
        1);
    RUN("ASN.1 that is not a SEQUENCE", "HTTP/1.0 200 OK\r\n\r\n\x04\x03\x02\x01\x05", NULL, 1);
    RUN("ASN.1 with a 5-octet length", "HTTP/1.0 200 OK\r\n\r\n\x30\x85\x01\x01\x01\x01\x01\x01", NULL, 1);
    RUN("ASN.1 cut short", "HTTP/1.0 200 OK\r\n\r\n\x30\x05\x02\x01", NULL, 1);
    RUN("text when ASN.1 is expected", "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nno\n", NULL, 1);
    RUN("404", "HTTP/1.0 404 Not Found  \r\nContent-Type: text/html\r\n\r\ngone\n", NULL, 0);
    RUN("500", "HTTP/1.1 500 Internal Server Error\r\n\r\n", NULL, 0);
    RUN("204", "HTTP/1.1 204 No Content\r\n\r\n", NULL, 0);
    RUN("302 without a location", "HTTP/1.0 302 Found\r\n\r\n", NULL, 0);
    RUN("302", "HTTP/1.0 302 Found\r\nLocation: http://elsewhere/x\r\n\r\n", NULL, 0);
    RUN("not HTTP", "SMTP 220 hello\r\n\r\n", NULL, 0);
    RUN("HTTP/2", "HTTP/2 200 OK\r\n\r\n", NULL, 0);
    RUN("a code that is no number", "HTTP/1.0 2x0 OK\r\n\r\n", NULL, 0);
    RUN("no reason", "HTTP/1.0 200\r\n\r\nx", NULL, 0);
    RUN("no code", "HTTP/1.0\r\n\r\n", NULL, 0);
    RUN("a bad content length", "HTTP/1.0 200 OK\r\nContent-Length: 12z\r\n\r\nx", NULL, 0);
    RUN("an empty content length", "HTTP/1.0 200 OK\r\nContent-Length: \r\n\r\nx", NULL, 0);
    RUN("a negative content length", "HTTP/1.0 200 OK\r\nContent-Length: -1\r\n\r\nx", NULL, 0);
    RUN("a header with no value", "HTTP/1.0 200 OK\r\nX-Empty:\r\nX-Other: 1\r\n\r\nbody", NULL, 0);
    RUN("a line starting with a colon ends the header", "HTTP/1.0 200 OK\r\n: odd\r\nX: 1\r\n\r\nbody", NULL, 0);
    RUN("no blank line", "HTTP/1.0 200 OK\r\nX: 1\r\n", NULL, 0);
    RUN("LF only", "HTTP/1.0 200 OK\nContent-Type: text/plain\n\nbody", "text/plain", 0);
    RUN("nothing", "", NULL, 0);
    run("too many header lines", "HTTP/1.0 200 OK\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\nx", 37, NULL, 0, 0, 3, 0, 0);
    run("no limit on header lines", "HTTP/1.0 200 OK\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\nx", 37, NULL, 0, 0, 0, 0, 0);
    memset(big, 'x', sizeof(big));
    memcpy(big, "HTTP/1.0 200 OK\r\nX-Long: ", 25);
    memcpy(big + sizeof(big) - 6, "\r\n\r\nz", 5);
    run("a line longer than the buffer", big, sizeof(big) - 1, NULL, 0, 64, (size_t)-1, 0, 0);
    run("a content length past the maximum", "HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\nx", 41, NULL, 0, 0,
        (size_t)-1, 50, 0);
    run("ASN.1 past the maximum", der_long, sizeof(der_long) - 1, NULL, 1, 0, (size_t)-1, 100, 0);
    run("keep-alive kept", "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\nx", 44, NULL, 0, 0, (size_t)-1, 0, 1);
    run("keep-alive dropped", "HTTP/1.0 200 OK\r\n\r\nx", 20, NULL, 0, 0, (size_t)-1, 0, 1);
    run("keep-alive required", "HTTP/1.0 200 OK\r\n\r\nx", 20, NULL, 0, 0, (size_t)-1, 0, 2);
    run("keep-alive by HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\nx", 20, NULL, 0, 0, (size_t)-1, 0, 1);
    run("keep-alive closed", "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nx", 39, NULL, 0, 0, (size_t)-1, 0, 2);
}

static void requests(void)
{
    BIO *w, *r;
    OSSL_HTTP_REQ_CTX *rctx;
    BIO *body;
    ASN1_VALUE *val = NULL;

    printf("# building requests\n");
    rctx = canned(&w, &r, "HTTP/1.0 200 OK\r\n\r\n\x30\x03\x02\x01\x07", 24, 0);
    check(OSSL_HTTP_REQ_CTX_add1_header(rctx, "X", "y") == 0, "a header before the request line");
    errors();
    check(OSSL_HTTP_REQ_CTX_set_request_line(rctx, 1, "proxy.target", "8080", "path") == 1, "a request line for a proxy");
    check(OSSL_HTTP_REQ_CTX_add1_header(rctx, "Accept", "*/*") == 1, "a header");
    check(OSSL_HTTP_REQ_CTX_add1_header(rctx, "X-Flag", NULL) == 1, "a header with no value");
    check(OSSL_HTTP_REQ_CTX_add1_header(rctx, "X-Bad", "a\r\nInjected: 1") == 0, "CR LF in a value");
    errors();
    check(OSSL_HTTP_REQ_CTX_add1_header(rctx, "X\nBad", "1") == 0, "LF in a name");
    errors();
    check(OSSL_HTTP_REQ_CTX_add1_header(rctx, "", "1") == 0, "an empty name");
    check(OSSL_HTTP_REQ_CTX_add1_header(rctx, "X-Empty", "") == 0, "an empty value");
    check(OSSL_HTTP_REQ_CTX_set_expected(rctx, NULL, 1, 10, 1) == 1, "keep-alive asked for");
    {
        ASN1_INTEGER *i = ASN1_INTEGER_new();

        ASN1_INTEGER_set(i, 0x1234);
        check(OSSL_HTTP_REQ_CTX_set1_req(rctx, "application/x-int", ASN1_ITEM_rptr(ASN1_INTEGER), (ASN1_VALUE *)i) == 1,
              "OSSL_HTTP_REQ_CTX_set1_req");
        ASN1_INTEGER_free(i);
    }
    check(OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx) != NULL, "OSSL_HTTP_REQ_CTX_get0_mem_bio");
    check(OSSL_HTTP_REQ_CTX_nbio_d2i(rctx, &val, ASN1_ITEM_rptr(ASN1_SEQUENCE_ANY)) == 1, "OSSL_HTTP_REQ_CTX_nbio_d2i");
    printf("  elements %d, resp_len %zu\n", sk_ASN1_TYPE_num((STACK_OF(ASN1_TYPE) *)val),
           OSSL_HTTP_REQ_CTX_get_resp_len(rctx));
    sk_ASN1_TYPE_pop_free((STACK_OF(ASN1_TYPE) *)val, ASN1_TYPE_free);
    sent("sent", w);
    check(OSSL_HTTP_REQ_CTX_set_expected(rctx, NULL, 0, 0, 1) == 0, "keep-alive asked for too late");
    errors();
    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(w);
    BIO_free(r);

    rctx = canned(&w, &r, "", 0, 0);
    check(OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, "s", NULL, "http://other/") == 0, "a full URL and a server");
    errors();
    check(OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, "s\r", NULL, "/") == 0, "CR in a server");
    errors();
    check(OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, "80\n", "/") == 0, "LF in a port");
    errors();
    check(OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "/a\r\nb") == 0, "CR LF in a path");
    errors();
    check(OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL, "http://full/url") == 1, "a full URL alone");
    check(OSSL_HTTP_REQ_CTX_set1_req(rctx, NULL, ASN1_ITEM_rptr(ASN1_INTEGER), NULL) == 1, "no content");
    body = BIO_new_mem_buf("data", 4);
    check(OSSL_HTTP_REQ_CTX_set1_req(rctx, NULL, NULL, NULL) == 1, "none again");
    OSSL_HTTP_REQ_CTX_set_expected(rctx, NULL, 0, 0, 0);
    check(OSSL_HTTP_REQ_CTX_nbio(rctx) == 0, "nothing comes back");
    errors();
    sent("sent", w);
    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(body);
    BIO_free(w);
    BIO_free(r);

    printf("# NULL arguments\n");
    check(OSSL_HTTP_REQ_CTX_new(NULL, NULL, 0) == NULL, "OSSL_HTTP_REQ_CTX_new");
    errors();
    check(OSSL_HTTP_REQ_CTX_nbio(NULL) == 0, "OSSL_HTTP_REQ_CTX_nbio");
    errors();
    check(OSSL_HTTP_REQ_CTX_exchange(NULL) == NULL, "OSSL_HTTP_REQ_CTX_exchange");
    errors();
    check(OSSL_HTTP_REQ_CTX_get0_mem_bio(NULL) == NULL, "OSSL_HTTP_REQ_CTX_get0_mem_bio");
    errors();
    check(OSSL_HTTP_REQ_CTX_get_resp_len(NULL) == 0, "OSSL_HTTP_REQ_CTX_get_resp_len");
    errors();
    OSSL_HTTP_REQ_CTX_set_max_response_length(NULL, 1);
    OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(NULL, 1);
    errors();
    check(OSSL_HTTP_is_alive(NULL) == 0, "OSSL_HTTP_is_alive");
    check(OSSL_HTTP_close(NULL, 1) == 1, "OSSL_HTTP_close");
    check(OSSL_HTTP_exchange(NULL, NULL) == NULL, "OSSL_HTTP_exchange");
    errors();
    check(OSSL_HTTP_set1_request(NULL, "/", NULL, NULL, NULL, NULL, 0, 0, 0, 0) == 0, "OSSL_HTTP_set1_request");
    errors();
    check(OSSL_HTTP_get(NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, 0) == NULL, "OSSL_HTTP_get");
    errors();
    check(OSSL_HTTP_open(NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, 0) == NULL, "OSSL_HTTP_open");
    errors();
    check(OSSL_HTTP_open("h", NULL, NULL, NULL, 1, NULL, NULL, NULL, NULL, 0, 0) == NULL, "TLS without a callback");
    errors();
    {
        BIO *m = BIO_new(BIO_s_mem());

        check(OSSL_HTTP_open(NULL, NULL, "p", NULL, 0, m, NULL, NULL, NULL, 0, 0) == NULL, "a BIO and a proxy");
        errors();
        check(OSSL_HTTP_open(NULL, NULL, NULL, NULL, 0, NULL, m, NULL, NULL, 0, 0) == NULL, "a read BIO alone");
        errors();
        check(OSSL_HTTP_proxy_connect(NULL, "s", NULL, NULL, NULL, 0, NULL, NULL) == 0, "OSSL_HTTP_proxy_connect");
        errors();
        check(OSSL_HTTP_proxy_connect(m, "s\r\n", NULL, NULL, NULL, 0, NULL, NULL) == 0, "CR LF in the server");
        errors();
        BIO_free(m);
    }
}

/* OSSL_HTTP_transfer over given BIOs, and OCSP over memory BIOs. */
static void transfers(void)
{
    BIO *w = BIO_new(BIO_s_mem()), *r = BIO_new(BIO_s_mem()), *resp, *req = BIO_new_mem_buf("payload", 7);
    STACK_OF(CONF_VALUE) *headers = NULL;
    OSSL_HTTP_REQ_CTX *rctx = NULL;
    OCSP_RESPONSE *ocsp;

    printf("# OSSL_HTTP_transfer over given BIOs\n");
    X509V3_add_value("X-One", "1", &headers);
    X509V3_add_value("host", "given.host", &headers);
    BIO_puts(r, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\nanswer");
    BIO_set_mem_eof_return(r, 0);
    resp = OSSL_HTTP_transfer(&rctx, "srv", "81", "/up", 0, NULL, NULL, w, r, NULL, NULL, 0, headers, "text/plain", req,
                              "text/plain", 0, 0, 30, 1);
    check(resp == r, "the stream");
    check(rctx != NULL && OSSL_HTTP_is_alive(rctx), "kept alive");
    errors();
    sent("sent", w);
    show_bio("content", resp);
    BIO_free(resp);
    OSSL_HTTP_close(rctx, 1);
    rctx = NULL;
    BIO_puts(r, "HTTP/1.0 200 OK\r\n\r\nx");
    resp = OSSL_HTTP_transfer(&rctx, "srv", NULL, NULL, 0, NULL, NULL, w, r, NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, 0, 0,
                              0);
    check(resp != NULL && rctx == NULL, "a GET, closed");
    errors();
    sent("sent", w);
    BIO_free(resp);
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
    BIO_free(req);

    printf("# OCSP over memory BIOs\n");
    {
        BIO *io = BIO_new(BIO_s_mem());
        OCSP_REQUEST *oreq = OCSP_REQUEST_new();
        OSSL_HTTP_REQ_CTX *octx;

        BIO_puts(io, "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\n");
        BIO_write(io, OCSP_MALFORMED, sizeof(OCSP_MALFORMED));
        BIO_set_mem_eof_return(io, 0);
        ocsp = OCSP_sendreq_bio(io, "/ocsp", oreq);
        check(ocsp != NULL && OCSP_response_status(ocsp) == OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, "OCSP_sendreq_bio");
        errors();
        OCSP_RESPONSE_free(ocsp);
        BIO_free(io);
        io = BIO_new(BIO_s_mem());
        octx = OCSP_sendreq_new(io, NULL, NULL, 0);
        check(octx != NULL, "OCSP_sendreq_new with no request");
        OSSL_HTTP_REQ_CTX_set1_req(octx, "application/ocsp-request", ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE *)oreq);
        /* The request goes into the memory BIO and is read back as the answer. */
        printf("  nbio: %d\n", OSSL_HTTP_REQ_CTX_nbio(octx));
        errors();
        OSSL_HTTP_REQ_CTX_free(octx);
        BIO_free(io);
        OCSP_REQUEST_free(oreq);
    }
    BIO_free(w);
    BIO_free(r);
}

/* The server: answers each request on a connection by its request line, and logs it. */
static void serve(int lfd, FILE *log)
{
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        char head[8192];

        if (fd < 0)
            continue;
        for (;;) {
            size_t n = 0;
            const char *resp;
            char dyn[1024];
            const unsigned char *extra = NULL;
            size_t extra_len = 0;
            int keep = 1;
            char *cl;

            while (n < sizeof(head) - 1 && read(fd, head + n, 1) == 1) {
                n++;
                if (n >= 4 && memcmp(head + n - 4, "\r\n\r\n", 4) == 0)
                    break;
            }
            head[n] = '\0';
            if (n == 0)
                break;
            if ((cl = strstr(head, "Content-Length: ")) != NULL) {
                long len = atol(cl + 16);
                char c;

                while (len-- > 0 && read(fd, &c, 1) == 1)
                    continue;
            }
            {
                size_t i;

                /* One line per request, with its CRs and LFs escaped. */
                for (i = 0; i < n; i++)
                    fputs(head[i] == '\r' ? "\\r" : head[i] == '\n' ? "\\n" : (char[]){ head[i], '\0' }, log);
                fputc('\n', log);
            }
            fflush(log);
            if (strncmp(head, "GET /text ", 10) == 0) {
                resp = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nhello from the server\n";
                keep = 0;
            } else if (strncmp(head, "GET /cert ", 10) == 0) {
                snprintf(dyn, sizeof(dyn), "HTTP/1.0 200 OK\r\nContent-Type: application/pkix-cert\r\nContent-Length: %d\r\n\r\n",
                         (int)sizeof(CA_DER));
                resp = dyn;
                extra = CA_DER;
                extra_len = sizeof(CA_DER);
                keep = 0;
            } else if (strncmp(head, "GET /crl ", 9) == 0) {
                snprintf(dyn, sizeof(dyn), "HTTP/1.0 200 OK\r\n\r\n");
                resp = dyn;
                extra = CRL_DER;
                extra_len = sizeof(CRL_DER);
                keep = 0;
            } else if (strncmp(head, "GET /moved ", 11) == 0) {
                resp = "HTTP/1.0 302 Found\r\nLocation: /cert\r\n\r\n";
            } else if (strncmp(head, "GET /away ", 10) == 0) {
                snprintf(dyn, sizeof(dyn), "HTTP/1.0 301 Moved\r\nLocation: http://127.0.0.1:%s/cert\r\n\r\n", port_text);
                resp = dyn;
            } else if (strncmp(head, "GET /loop ", 10) == 0) {
                resp = "HTTP/1.0 302 Found\r\nLocation: /loop\r\n\r\n";
            } else if (strncmp(head, "POST /ocsp ", 11) == 0) {
                resp = "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\n";
                extra = OCSP_MALFORMED;
                extra_len = sizeof(OCSP_MALFORMED);
                keep = 0;
            } else if (strncmp(head, "GET http://example.test/proxied ", 32) == 0) {
                resp = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nvia the proxy\n";
                keep = 0;
            } else if (strncmp(head, "CONNECT target.test:443 ", 24) == 0) {
                resp = "HTTP/1.0 200 Connection established\r\nX-Proxy: yes\r\n\r\n";
                keep = 0;
            } else if (strncmp(head, "CONNECT [::1]:8443 ", 19) == 0) {
                resp = "HTTP/1.1 407 Proxy Authentication Required  \r\n\r\n";
                keep = 0;
            } else if (strncmp(head, "CONNECT wrong.version:443 ", 26) == 0) {
                resp = "HTTP/2.0 200 OK\r\n\r\n";
                keep = 0;
            } else {
                resp = "HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\nno such thing\n";
                keep = 0;
            }
            if (write(fd, resp, strlen(resp)) < 0 || (extra != NULL && write(fd, extra, extra_len) < 0))
                break;
            if (!keep)
                break;
        }
        close(fd);
    }
}

static BIO *update_cb(BIO *bio, void *arg, int connect, int detail)
{
    printf("  callback: %s, connect %d, detail %d\n", (const char *)arg, connect, detail);
    return bio;
}


static void against_a_server(void)
{
    int lfd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a;
    socklen_t al = sizeof(a);
    pid_t pid;
    FILE *log = tmpfile();
    char url[128], proxy[64];
    BIO *b;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(lfd, 8) != 0
        || getsockname(lfd, (struct sockaddr *)&a, &al) != 0) {
        check(0, "a server");
        return;
    }
    snprintf(port_text, sizeof(port_text), "%d", ntohs(a.sin_port));
    pid = fork();
    if (pid == 0) {
        serve(lfd, log);
        _exit(0);
    }
    close(lfd);

    printf("# GET\n");
    snprintf(url, sizeof(url), "http://127.0.0.1:%s/text", port_text);
    b = OSSL_HTTP_get(url, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, "text/plain", 0, 0, 10);
    show_bio("text", b);
    errors();
    BIO_free(b);
    snprintf(url, sizeof(url), "http://127.0.0.1:%s/moved", port_text);
    b = OSSL_HTTP_get(url, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 1, 0, 10);
    check(b != NULL && BIO_get_mem_data(b, NULL) == (long)sizeof(CA_DER), "a relative redirection");
    errors();
    BIO_free(b);
    snprintf(url, sizeof(url), "http://127.0.0.1:%s/away", port_text);
    b = OSSL_HTTP_get(url, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 1, 0, 10);
    check(b != NULL && BIO_get_mem_data(b, NULL) == (long)sizeof(CA_DER), "an absolute redirection");
    errors();
    BIO_free(b);
    snprintf(url, sizeof(url), "http://127.0.0.1:%s/loop", port_text);
    b = OSSL_HTTP_get(url, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 1, 0, 30);
    check(b == NULL, "too many redirections");
    errors();
    snprintf(url, sizeof(url), "http://127.0.0.1:%s/nothing", port_text);
    b = OSSL_HTTP_get(url, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, 10);
    /* A 404 is an error in the queue, but its content comes back. */
    show_bio("not found", b);
    errors();
    BIO_free(b);
    b = OSSL_HTTP_get("ftp://127.0.0.1/x", NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, 10);
    check(b == NULL, "another scheme");
    errors();

    printf("# loading by URL\n");
    snprintf(url, sizeof(url), "http://127.0.0.1:%s/cert", port_text);
    {
        X509 *x = X509_load_http(url, NULL, NULL, 10);

        check(x != NULL, "X509_load_http");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(x), 0, XN_FLAG_ONELINE);
        printf("\n");
        X509_free(x);
    }
    snprintf(url, sizeof(url), "http://127.0.0.1:%s/crl", port_text);
    {
        X509_CRL *crl = X509_CRL_load_http(url, NULL, NULL, 10);

        check(crl != NULL && sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl)) <= 0, "X509_CRL_load_http");
        X509_CRL_free(crl);
    }
    errors();

    printf("# a proxy and the TLS callback\n");
    snprintf(proxy, sizeof(proxy), "http://127.0.0.1:%s", port_text);
    b = OSSL_HTTP_transfer(NULL, "example.test", NULL, "/proxied", 0, proxy, NULL, NULL, NULL, update_cb, "cb", 0, NULL,
                           NULL, NULL, "text/plain", 0, 0, 10, 0);
    show_bio("proxied", b);
    errors();
    BIO_free(b);
    b = OSSL_HTTP_transfer(NULL, "example.test", NULL, "/proxied", 0, proxy, "example.test", NULL, NULL, NULL, NULL, 0,
                           NULL, NULL, NULL, NULL, 0, 0, 2, 0);
    check(b == NULL, "no_proxy lists the server, which does not resolve");
    ERR_clear_error();

    printf("# OCSP\n");
    {
        OSSL_HTTP_REQ_CTX *rctx = OSSL_HTTP_open("127.0.0.1", port_text, NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, 10);
        OCSP_REQUEST *req = OCSP_REQUEST_new();
        BIO *io;
        OCSP_RESPONSE *resp;

        check(rctx != NULL, "OSSL_HTTP_open");
        check(OSSL_HTTP_set1_request(rctx, "/ocsp", NULL, "application/ocsp-request", NULL, "application/ocsp-response", 1,
                                     0, 10, 0) == 0,
              "a POST content type with no content");
        errors();
        io = BIO_new(BIO_s_mem());
        i2d_OCSP_REQUEST_bio(io, req);
        check(OSSL_HTTP_set1_request(rctx, "/ocsp", NULL, "application/ocsp-request", io, "application/ocsp-response", 1,
                                     0, 10, 0) == 1,
              "OSSL_HTTP_set1_request");
        BIO_free(io);
        io = OSSL_HTTP_exchange(rctx, NULL);
        resp = d2i_OCSP_RESPONSE_bio(io, NULL);
        check(resp != NULL && OCSP_response_status(resp) == 1, "OSSL_HTTP_exchange");
        errors();
        OCSP_RESPONSE_free(resp);
        BIO_free(io);
        OSSL_HTTP_close(rctx, 1);
        OCSP_REQUEST_free(req);
    }

    printf("# CONNECT\n");
    {
        static const char *const targets[][2] = {
            { "target.test", "443" }, { "::1", "8443" }, { "wrong.version", NULL }, { NULL, NULL }
        };
        int i;

        for (i = 0; targets[i][0] != NULL; i++) {
            BIO *c = BIO_new_connect("127.0.0.1");
            BIO *err = BIO_new(BIO_s_mem());
            int r;

            BIO_set_conn_port(c, port_text);
            BIO_do_connect(c);
            r = OSSL_HTTP_proxy_connect(c, targets[i][0], targets[i][1], i == 0 ? "user" : NULL, "secret", 10, err,
                                        "prog");
            printf("  %s: %d\n", targets[i][0], r);
            sent("bio_err", err);
            errors();
            BIO_free(err);
            BIO_free_all(c);
        }
    }

    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    printf("# what the server got\n");
    {
        char buf[16384];
        size_t n;

        char *line, *prev = NULL, *save = NULL;
        int same = 0;

        rewind(log);
        n = fread(buf, 1, sizeof(buf) - 1, log);
        buf[n] = '\0';
        /* One request per line; repeats are counted. */
        for (line = strtok_r(buf, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
            if (prev != NULL && strcmp(prev, line) == 0) {
                same++;
                continue;
            }
            if (same > 0)
                printf("  ... %d more\n", same);
            same = 0;
            printf("  ");
            show(line, strlen(line));
            printf("\n");
            prev = line;
        }
        if (same > 0)
            printf("  ... %d more\n", same);
    }
    fclose(log);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    unsetenv("http_proxy");
    unsetenv("https_proxy");
    unsetenv("HTTP_PROXY");
    unsetenv("HTTPS_PROXY");
    unsetenv("no_proxy");
    unsetenv("NO_PROXY");
    parse_urls();
    canned_responses();
    requests();
    transfers();
    against_a_server();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
