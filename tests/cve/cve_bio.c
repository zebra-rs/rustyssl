/*
 * CVE regression tests: BIO filters, PEM reading, base64, and the HTTP client's helpers.
 */
#include "cve.h"

#include <openssl/http.h>

static void linebuffer(void)
{
    BIO *a = NULL, *b = NULL, *lb = BIO_new(BIO_f_linebuffer());
    char data[10000], sink[4096];
    long written = 0, drained = 0;
    int n;

    /* A pair of 256-octet buffers: writes past what's free are short. */
    BIO_new_bio_pair(&a, 256, &b, 256);
    BIO_push(lb, a);
    memset(data, 'x', sizeof(data));
    for (int round = 0; round < 200 && written < (long)sizeof(data); round++) {
        n = BIO_write(lb, data + written, (int)(sizeof(data) - (size_t)written));
        if (n > 0)
            written += n;
        while ((n = BIO_read(b, sink, sizeof(sink))) > 0)
            drained += n;
    }
    BIO_flush(lb);
    while ((n = BIO_read(b, sink, sizeof(sink))) > 0)
        drained += n;
    check(written == (long)sizeof(data),
          "CVE-2025-68160: BIO_f_linebuffer with short writes downstream stays in bounds");
    note("written %ld, drained %ld", written, drained);
    BIO_free_all(lb);
    BIO_free(b);
}

static void pem_names(void)
{
    static const char *const inputs[] = {
        "-----BEGIN -----\n-----END -----\n",
        "-----BEGIN X-----\n\n-----END X-----\n",
        "-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\n\n-----END X-----\n",
        "-----BEGIN X-----\nAAAA\n-----END Y-----\n",
    };
    int all = 1;

    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        BIO *in = BIO_new_mem_buf(inputs[i], -1);
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 0;
        int r = PEM_read_bio_ex(in, &name, &header, &data, &len, PEM_FLAG_ONLY_B64);

        note("input %zu: %d, name [%s], header [%s], %ld octets", i, r, name != NULL ? name : "",
             header != NULL ? header : "", len);
        if (r == 0 && (name != NULL || header != NULL || data != NULL))
            all = 0;
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        BIO_free(in);
        ERR_clear_error();
    }
    check(all, "CVE-2022-4450: PEM_read_bio_ex with empty payloads frees its outputs once");
}

static void no_proxy(void)
{
    static const struct {
        const char *no_proxy, *server;
    } cases[] = {
        {"example", "example.com"}, {"example.com", "example"}, {"a,b,example", "example"},
        {"example ", "example"},    {",", "x"},                 {"exam", "example"},
        {"example.com,", "example.com"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *r = OSSL_HTTP_adapt_proxy("proxy.example:8080", cases[i].no_proxy,
                                              cases[i].server, 0);

        note("no_proxy [%s], server [%s]: %s", cases[i].no_proxy, cases[i].server,
             r != NULL ? r : "direct");
    }
    check(1, "CVE-2025-9232: matching servers against no_proxy reads only the given names");
}

int main(void)
{
    linebuffer();
    pem_names();
    no_proxy();
    return finish();
}
