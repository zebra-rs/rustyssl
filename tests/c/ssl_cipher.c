/*
 * Conformance test for cipher lists and SSL_CIPHER (SSL_CTX_set_cipher_list(3),
 * SSL_CTX_set_ciphersuites(3), SSL_get_ciphers(3), SSL_CIPHER_get_name(3),
 * SSL_CIPHER_description, SSL_bytes_to_cipher_list(3), SSL_get_shared_ciphers): the default
 * lists, many cipher strings and TLS 1.3 suite lists on a context and on a connection, every
 * suite's description and getters, lookups by wire octets and by name, the parsing of a
 * ClientHello's list, method changes, and the errors of bad arguments.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void errors(void)
{
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static void names(const char *label, STACK_OF(SSL_CIPHER) *sk)
{
    int i;

    if (sk == NULL) {
        printf("  %s: (null)\n", label);
        return;
    }
    printf("  %s (%d):", label, sk_SSL_CIPHER_num(sk));
    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++)
        printf("%s%s", i == 0 ? " " : ":", SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)));
    printf("\n");
}

static const char *const strings[] = {
    "DEFAULT", "ALL", "HIGH", "ALL:!aNULL", "ECDHE+AESGCM", "kRSA", "AES128:@STRENGTH", "-ALL:+AES",
    "@SECLEVEL=0:ALL", "COMPLEMENTOFDEFAULT", "COMPLEMENTOFALL", "eNULL", "aNULL", "NULL", "PSK",
    "SRP", "CHACHA20", "CAMELLIA", "ARIA", "3DES", "SHA256", "TLSv1.2", "SSLv3", "ECDSA", "DHE",
    "nonexistent", "AES128-SHA:nonexistent:AES256-SHA", "!ALL", "ALL:-HIGH:+MEDIUM", "", NULL
};

static void lists(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s;
    int i;

    printf("# the default lists\n");
    check(ctx != NULL, "a context");
    names("context", SSL_CTX_get_ciphers(ctx));
    s = SSL_new(ctx);
    check(SSL_get_ciphers(s) == SSL_CTX_get_ciphers(ctx), "a connection uses its context's list");
    printf("  first %s, 3rd %s, 999th %s\n", SSL_get_cipher_list(s, 0), SSL_get_cipher_list(s, 2),
           SSL_get_cipher_list(s, 999) == NULL ? "NULL" : "?");

    printf("# cipher strings on the context\n");
    for (i = 0; strings[i] != NULL; i++) {
        int r = SSL_CTX_set_cipher_list(ctx, strings[i]);

        printf("  \"%s\" -> %d\n", strings[i], r);
        names("list", SSL_CTX_get_ciphers(ctx));
        errors();
    }
    check(SSL_CTX_set_cipher_list(ctx, "DEFAULT") == 1, "back to the default");

    printf("# TLS 1.3 suites\n");
    {
        static const char *const suites[] = {
            "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384", "",
            "nonexistent", "TLS_AES_128_CCM_SHA256:nonexistent", " TLS_AES_128_GCM_SHA256 ",
            "TLS_RSA_WITH_AES_128_CBC_SHA", NULL
        };
        for (i = 0; suites[i] != NULL; i++) {
            int r = SSL_CTX_set_ciphersuites(ctx, suites[i]);

            printf("  \"%s\" -> %d\n", suites[i], r);
            names("list", SSL_CTX_get_ciphers(ctx));
            errors();
        }
        check(SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256") == 1, "two suites");
        check(SSL_CTX_set_cipher_list(ctx, "AES256-SHA") == 1, "a list keeps the TLS 1.3 suites");
        names("list", SSL_CTX_get_ciphers(ctx));
    }

    printf("# a connection's own lists\n");
    {
        SSL *t = SSL_new(ctx);

        check(SSL_set_cipher_list(t, "ECDHE-RSA-AES128-GCM-SHA256") == 1, "SSL_set_cipher_list");
        names("connection", SSL_get_ciphers(t));
        names("context", SSL_CTX_get_ciphers(ctx));
        check(SSL_get_ciphers(t) != SSL_CTX_get_ciphers(ctx), "its own list");
        check(SSL_set_ciphersuites(t, "TLS_CHACHA20_POLY1305_SHA256") == 1, "SSL_set_ciphersuites");
        names("connection", SSL_get_ciphers(t));
        check(SSL_set_cipher_list(t, "nonexistent") == 0, "no match");
        names("connection", SSL_get_ciphers(t));
        errors();
        SSL_free(t);
        t = SSL_new(ctx);
        check(SSL_set_ciphersuites(t, "nonexistent") == 0, "SSL_set_ciphersuites refused");
        errors();
        check(SSL_get_ciphers(t) != SSL_CTX_get_ciphers(ctx), "still made its own list");
        names("connection", SSL_get_ciphers(t));
        SSL_free(t);
    }

    printf("# @SECLEVEL and Suite B\n");
    check(SSL_CTX_set_cipher_list(ctx, "DEFAULT:@SECLEVEL=0") == 1, "@SECLEVEL=0");
    printf("  level %d\n", SSL_CTX_get_security_level(ctx));
    check(SSL_CTX_set_cipher_list(ctx, "@SECLEVEL=9") == 0, "@SECLEVEL=9");
    errors();
    printf("  level %d\n", SSL_CTX_get_security_level(ctx));
    check(SSL_CTX_set_cipher_list(ctx, "@SECLEVEL=3:nonexistent") == 0, "a level set by a failing string");
    errors();
    printf("  level %d\n", SSL_CTX_get_security_level(ctx));
    check(SSL_CTX_set_cipher_list(ctx, "SUITEB128") == 1, "SUITEB128");
    names("list", SSL_CTX_get_ciphers(ctx));
    check(SSL_CTX_set_cipher_list(ctx, "ALL") == 1, "Suite B stays on");
    names("list", SSL_CTX_get_ciphers(ctx));

    printf("# NULL arguments\n");
    check(SSL_CTX_get_ciphers(NULL) == NULL, "SSL_CTX_get_ciphers(NULL)");
    check(SSL_get_ciphers(NULL) == NULL, "SSL_get_ciphers(NULL)");
    check(SSL_get_cipher_list(NULL, 0) == NULL, "SSL_get_cipher_list(NULL)");
    check(SSL_get_cipher_list(s, -1) == NULL, "SSL_get_cipher_list(-1)");
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void getters(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    STACK_OF(SSL_CIPHER) *sk;
    char buf[128], small[64], *p;
    int i;

    printf("# every suite\n");
    SSL_CTX_set_security_level(ctx, 0);
    check(SSL_CTX_set_cipher_list(ctx, "ALL:COMPLEMENTOFALL") == 1, "every suite");
    sk = SSL_CTX_get_ciphers(ctx);
    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
        const EVP_MD *md = SSL_CIPHER_get_handshake_digest(c);
        int alg_bits = -1, bits = SSL_CIPHER_get_bits(c, &alg_bits);

        printf("  %s", SSL_CIPHER_description(c, buf, sizeof(buf)));
        printf("    %s %s id %08x proto %04x bits %d/%d nids %d %d %d %d hs %s aead %d back %s\n",
               SSL_CIPHER_get_version(c), SSL_CIPHER_standard_name(c), (unsigned)SSL_CIPHER_get_id(c),
               SSL_CIPHER_get_protocol_id(c), bits, alg_bits, SSL_CIPHER_get_cipher_nid(c),
               SSL_CIPHER_get_digest_nid(c), SSL_CIPHER_get_kx_nid(c), SSL_CIPHER_get_auth_nid(c),
               md == NULL ? "-" : EVP_MD_get0_name(md), SSL_CIPHER_is_aead(c),
               OPENSSL_cipher_name(SSL_CIPHER_standard_name(c)));
    }

    printf("# descriptions and buffers\n");
    {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, 0);

        p = SSL_CIPHER_description(c, NULL, 0);
        check(p != NULL && strcmp(p, SSL_CIPHER_description(c, buf, sizeof(buf))) == 0, "an allocated buffer");
        OPENSSL_free(p);
        check(SSL_CIPHER_description(c, small, sizeof(small)) == NULL, "a buffer under 128 octets");
        check(SSL_CIPHER_description(c, buf, 128) == buf, "exactly 128 octets");
    }
    printf("  NULL: %s %s %s %d\n", SSL_CIPHER_get_name(NULL), SSL_CIPHER_get_version(NULL),
           SSL_CIPHER_standard_name(NULL), SSL_CIPHER_get_bits(NULL, NULL));
    printf("  cipher nid of NULL %d\n", SSL_CIPHER_get_cipher_nid(NULL));
    printf("  names: %s %s %s\n", OPENSSL_cipher_name("TLS_AES_128_GCM_SHA256"), OPENSSL_cipher_name("nonexistent"),
           OPENSSL_cipher_name(NULL));

    printf("# lookups by wire octets\n");
    {
        SSL *s = SSL_new(ctx);
        static const unsigned char ids[][2] = { { 0x13, 0x01 }, { 0xc0, 0x2f }, { 0x00, 0xff }, { 0x56, 0x00 },
                                                { 0x00, 0x00 }, { 0xfe, 0xfe } };

        for (i = 0; i < (int)(sizeof(ids) / sizeof(ids[0])); i++) {
            const SSL_CIPHER *c = SSL_CIPHER_find(s, ids[i]);

            printf("  %02x%02x: %s\n", ids[i][0], ids[i][1], c == NULL ? "(none)" : SSL_CIPHER_get_name(c));
        }
        SSL_free(s);
    }
    SSL_CTX_free(ctx);
}

static void client_lists(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *s = SSL_new(ctx);
    STACK_OF(SSL_CIPHER) *sk = NULL, *scsvs = NULL;
    static const unsigned char v3[] = { 0x13, 0x01, 0xc0, 0x2f, 0x00, 0xff, 0x56, 0x00, 0xfe, 0xfe, 0x00, 0x2f };
    static const unsigned char v2[] = { 0x00, 0x13, 0x01, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0x00, 0x00, 0x35 };
    char buf[64];

    printf("# a ClientHello's list\n");
    check(SSL_bytes_to_cipher_list(s, v3, sizeof(v3), 0, &sk, &scsvs) == 1, "two-octet entries");
    names("suites", sk);
    names("signalling", scsvs);
    sk_SSL_CIPHER_free(sk);
    sk_SSL_CIPHER_free(scsvs);
    sk = scsvs = NULL;
    check(SSL_bytes_to_cipher_list(s, v2, sizeof(v2), 1, &sk, &scsvs) == 1, "SSLv2's three-octet entries");
    names("suites", sk);
    names("signalling", scsvs);
    sk_SSL_CIPHER_free(sk);
    sk_SSL_CIPHER_free(scsvs);
    check(SSL_bytes_to_cipher_list(s, v3, 4, 0, NULL, NULL) == 1, "without slots");
    check(SSL_bytes_to_cipher_list(s, v3, 0, 0, &sk, NULL) == 0, "an empty list");
    errors();
    check(SSL_bytes_to_cipher_list(s, v3, 3, 0, &sk, NULL) == 0, "an odd length");
    errors();
    check(SSL_bytes_to_cipher_list(s, v2, 4, 1, &sk, NULL) == 0, "a length not a multiple of three");
    errors();
    check(SSL_bytes_to_cipher_list(NULL, v3, 2, 0, &sk, NULL) == 0, "no connection");

    printf("# shared and client lists of an idle connection\n");
    SSL_set_connect_state(s);
    check(SSL_get_client_ciphers(s) == NULL, "a client has no client list");
    check(SSL_get_shared_ciphers(s, buf, sizeof(buf)) == NULL, "nor a shared one");
    check(SSL_get_shared_ciphers(s, buf, 1) == NULL, "a one-octet buffer");
    check(SSL_get_shared_ciphers(s, NULL, 64) == NULL, "no buffer");
    SSL_set_accept_state(s);
    check(SSL_get_client_ciphers(s) == NULL, "a server before a ClientHello");
    buf[0] = 'x';
    check(SSL_get_shared_ciphers(s, buf, sizeof(buf)) == buf && buf[0] == '\0', "an empty shared list");
    check(SSL_get_shared_ciphers(NULL, buf, sizeof(buf)) == NULL, "NULL");
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void methods(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());

    printf("# method changes\n");
    check(SSL_CTX_set_cipher_list(ctx, "AES128-SHA") == 1, "a short list");
    check(SSL_CTX_set_ssl_version(ctx, TLSv1_2_method()) == 1, "TLSv1_2_method");
    names("rebuilt", SSL_CTX_get_ciphers(ctx));
    check(SSL_CTX_set_ssl_version(ctx, TLS_method()) == 1, "TLS_method");
    SSL_CTX_free(ctx);

    ctx = SSL_CTX_new(TLSv1_1_method());
    printf("# a TLS 1.1 context\n");
    names("default", SSL_CTX_get_ciphers(ctx));
    check(SSL_CTX_set_cipher_list(ctx, "SUITEB128") == 0, "Suite B needs TLS 1.2 suites");
    errors();
    SSL_CTX_free(ctx);

    ctx = SSL_CTX_new(DTLS_method());
    printf("# a DTLS context\n");
    names("default", SSL_CTX_get_ciphers(ctx));
    check(SSL_CTX_set_cipher_list(ctx, "CHACHA20:RC4") == 1, "DTLS has no stream ciphers");
    names("list", SSL_CTX_get_ciphers(ctx));
    SSL_CTX_free(ctx);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    lists();
    getters();
    client_lists();
    methods();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
