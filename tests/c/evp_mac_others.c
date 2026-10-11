/*
 * Conformance test for the other MACs (EVP_MAC-KMAC(7), EVP_MAC-Poly1305(7),
 * EVP_MAC-Siphash(7), EVP_MAC-BLAKE2(7)) and HMAC's TLS record mode (EVP_MAC-HMAC(7),
 * "tls-data-size"), in TAP format: the methods and their parameter lists, the SP 800-185,
 * RFC 8439, SipHash, and BLAKE2 vectors, each MAC's lifecycle (keys, sizes, customization,
 * rounds, copies, reinit), its errors, and a TLS record's MAC against HMAC's of its data.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

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
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static int unhex(const char *s, unsigned char *out)
{
    int n = 0;
    unsigned int b;

    while (s[0] != '\0' && s[1] != '\0' && sscanf(s, "%2x", &b) == 1) {
        out[n++] = (unsigned char)b;
        s += 2;
    }
    return n;
}

static int same_hex(const unsigned char *p, size_t n, const char *want)
{
    unsigned char w[256];

    return (size_t)unhex(want, w) == n && memcmp(p, w, n) == 0;
}

static void list(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" NULL");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u/%zu", p->key, p->data_type, p->data_size);
    printf("\n");
}

static void name_cb(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static EVP_MAC_CTX *context(const char *name)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, name, NULL);
    EVP_MAC_CTX *ctx = mac == NULL ? NULL : EVP_MAC_CTX_new(mac);

    EVP_MAC_free(mac);
    return ctx;
}

static void sizes(EVP_MAC_CTX *ctx, const char *label)
{
    printf("  %s: size %zu block %zu\n", label, EVP_MAC_CTX_get_mac_size(ctx),
           EVP_MAC_CTX_get_block_size(ctx));
}

static void methods(void)
{
    static const char *names[] = { "KMAC-128", "KMAC256", "2.16.840.1.101.3.4.2.20", "POLY1305",
                                   "SIPHASH", "BLAKE2BMAC", "BLAKE2SMAC",
                                   "1.3.6.1.4.1.1722.12.2.2", NULL };
    const char **n;

    for (n = names; *n != NULL; n++) {
        EVP_MAC *mac = EVP_MAC_fetch(NULL, *n, NULL);

        check(mac != NULL, *n);
        if (mac == NULL)
            continue;
        printf("  %s:", *n);
        EVP_MAC_names_do_all(mac, name_cb, NULL);
        printf("\n");
        list("gettable", EVP_MAC_gettable_params(mac));
        list("gettable ctx", EVP_MAC_gettable_ctx_params(mac));
        list("settable ctx", EVP_MAC_settable_ctx_params(mac));
        EVP_MAC_free(mac);
    }
    errors();
}

/* SP 800-185's KMAC samples: the key 0x40..0x5f and data 00010203 or 0x00..0xc7. */
static void kmac(void)
{
    static const char *tagged = "My Tagged Application";
    unsigned char key[32], data[200], out[64], out2[64];
    EVP_MAC_CTX *ctx = context("KMAC-128"), *dup;
    OSSL_PARAM params[4];
    size_t outl = 0, size;
    int i, r, xof = 1;

    for (i = 0; i < 32; i++)
        key[i] = (unsigned char)(0x40 + i);
    for (i = 0; i < 200; i++)
        data[i] = (unsigned char)i;
    check(ctx != NULL, "a KMAC-128 context");
    sizes(ctx, "new");
    r = EVP_MAC_init(ctx, NULL, 0, NULL);
    check(r == 0, "init without a key");
    errors();
    r = EVP_MAC_init(ctx, key, 3, NULL);
    check(r == 0, "a key of 3 octets");
    errors();
    r = EVP_MAC_update(ctx, data, 4);
    check(r == 0, "update before init");
    errors();
    check(EVP_MAC_init(ctx, key, 32, NULL) == 1 && EVP_MAC_update(ctx, data, 4) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
          && same_hex(out, outl,
                      "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e"),
          "SP 800-185 KMAC128 sample 1");
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, (void *)tagged,
                                                  strlen(tagged));
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_MAC_init(ctx, NULL, 0, params) == 1 && EVP_MAC_update(ctx, data, 4) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
          && same_hex(out, outl,
                      "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5"),
          "SP 800-185 KMAC128 sample 2");
    check(EVP_MAC_init(ctx, NULL, 0, NULL) == 1 && EVP_MAC_update(ctx, data, 100) == 1,
          "the start of sample 3");
    dup = EVP_MAC_CTX_dup(ctx);
    check(dup != NULL, "copy");
    check(EVP_MAC_update(ctx, data + 100, 100) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
          && same_hex(out, outl,
                      "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230"),
          "SP 800-185 KMAC128 sample 3");
    check(EVP_MAC_update(dup, data + 100, 100) == 1
          && EVP_MAC_final(dup, out2, &outl, sizeof(out2)) == 1 && memcmp(out, out2, 32) == 0,
          "the copy agrees");
    EVP_MAC_CTX_free(dup);

    /* Other sizes, and XOF mode. */
    size = 20;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_MAC_init(ctx, NULL, 0, params) == 1 && EVP_MAC_update(ctx, data, 4) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && outl == 20, "20 octets");
    hex("20", out, outl);
    sizes(ctx, "20");
    check(EVP_MAC_init(ctx, NULL, 0, NULL) == 1 && EVP_MAC_update(ctx, data, 4) == 1
          && EVP_MAC_finalXOF(ctx, out, 20) == 1, "XOF of 20 octets");
    hex("XOF 20", out, 20);
    params[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &xof);
    check(EVP_MAC_init(ctx, NULL, 0, params) == 1 && EVP_MAC_update(ctx, data, 4) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1, "XOF by parameter");
    hex("XOF param", out, outl);
    size = 0x200000;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "an output too long");
    errors();
    {
        unsigned char custom[513];

        memset(custom, 'c', sizeof(custom));
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, custom, 513);
        r = EVP_MAC_CTX_set_params(ctx, params);
        check(r == 0, "a customization string too long");
        errors();
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, custom, 512);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, custom, 512);
        params[2] = OSSL_PARAM_construct_end();
        check(EVP_MAC_CTX_set_params(ctx, params) == 1 && EVP_MAC_init(ctx, NULL, 0, NULL) == 1
              && EVP_MAC_update(ctx, data, 200) == 1
              && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1, "the longest key and string");
        hex("longest", out, outl);
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, custom, 513);
        params[1] = OSSL_PARAM_construct_end();
        r = EVP_MAC_CTX_set_params(ctx, params);
        check(r == 0, "a key too long");
        errors();
    }
    EVP_MAC_CTX_free(ctx);

    ctx = context("KMAC-256");
    sizes(ctx, "KMAC-256");
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, (void *)tagged,
                                                  strlen(tagged));
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_MAC_init(ctx, key, 32, params) == 1 && EVP_MAC_update(ctx, data, 4) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
          && same_hex(out, outl,
                      "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7"
                      "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"),
          "SP 800-185 KMAC256 sample 4");
    EVP_MAC_CTX_free(ctx);
}

static void poly1305(void)
{
    static const char *msg = "Cryptographic Forum Research Group";
    unsigned char key[32], out[32];
    EVP_MAC_CTX *ctx = context("POLY1305"), *dup;
    OSSL_PARAM params[2];
    size_t outl = 0;
    int r;

    unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key);
    check(ctx != NULL, "a Poly1305 context");
    sizes(ctx, "new");
    r = EVP_MAC_update(ctx, (const unsigned char *)msg, 1);
    check(r == 0, "update without a key");
    errors();
    r = EVP_MAC_final(ctx, out, &outl, sizeof(out));
    check(r == 0, "final without a key");
    errors();
    r = EVP_MAC_init(ctx, key, 31, NULL);
    check(r == 0, "a key of 31 octets");
    errors();
    check(EVP_MAC_init(ctx, key, 32, NULL) == 1 && EVP_MAC_init(ctx, NULL, 0, NULL) == 1,
          "init, again before use");
    check(EVP_MAC_update(ctx, (const unsigned char *)msg, 10) == 1, "update");
    dup = EVP_MAC_CTX_dup(ctx);
    check(dup != NULL, "copy");
    r = EVP_MAC_init(ctx, NULL, 0, NULL);
    check(r == 0, "no init again after use");
    errors();
    check(EVP_MAC_update(ctx, (const unsigned char *)msg + 10, strlen(msg) - 10) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
          && same_hex(out, outl, "a8061dc1305136c6c22b8baf0c0127a9"), "RFC 8439 2.5.2");
    check(EVP_MAC_update(dup, NULL, 0) == 1
          && EVP_MAC_update(dup, (const unsigned char *)msg + 10, strlen(msg) - 10) == 1
          && EVP_MAC_final(dup, out, &outl, sizeof(out)) == 1
          && same_hex(out, outl, "a8061dc1305136c6c22b8baf0c0127a9"), "the copy agrees");
    EVP_MAC_CTX_free(dup);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, 32);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_MAC_CTX_set_params(ctx, params) == 1 && EVP_MAC_init(ctx, NULL, 0, NULL) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1, "a key by parameter, no data");
    hex("empty", out, outl);
    EVP_MAC_CTX_free(ctx);
}

static void siphash(void)
{
    unsigned char key[16], data[64], out[16];
    EVP_MAC_CTX *ctx = context("SIPHASH"), *dup;
    OSSL_PARAM params[4];
    size_t outl = 0, size;
    unsigned int c = 0, d = 0;
    int i, r;

    for (i = 0; i < 16; i++)
        key[i] = (unsigned char)i;
    for (i = 0; i < 64; i++)
        data[i] = (unsigned char)i;
    check(ctx != NULL, "a SipHash context");
    sizes(ctx, "new");
    params[0] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_C_ROUNDS, &c);
    params[1] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_D_ROUNDS, &d);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_MAC_CTX_get_params(ctx, params) == 1 && c == 2 && d == 4, "2-4 by default");
    r = EVP_MAC_final(ctx, out, &outl, sizeof(out));
    check(r == 0, "final without a key");
    check(EVP_MAC_update(ctx, data, 9) == 1, "update without a key");
    r = EVP_MAC_init(ctx, key, 15, NULL);
    check(r == 0, "a key of 15 octets");
    size = 8;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_MAC_init(ctx, key, 16, params) == 1 && EVP_MAC_update(ctx, data, 15) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
          && same_hex(out, outl, "e545be4961ca29a1"), "SipHash-2-4, 64 bits, 15 octets");
    check(EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1
          && same_hex(out, outl, "e545be4961ca29a1"), "final again, the same");
    size = 16;
    check(EVP_MAC_CTX_set_params(ctx, params) == 1, "16 octets, after the key");
    sizes(ctx, "16");
    check(EVP_MAC_init(ctx, NULL, 0, NULL) == 1 && EVP_MAC_update(ctx, data, 7) == 1
          && EVP_MAC_update(ctx, data + 7, 8) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1, "128 bits, 15 octets");
    hex("128", out, outl);
    r = EVP_MAC_final(ctx, out, &outl, 15);
    check(r == 0, "into too little room");
    errors();
    check(EVP_MAC_init(ctx, key, 16, NULL) == 1 && EVP_MAC_update(ctx, data, 33) == 1,
          "a new key");
    dup = EVP_MAC_CTX_dup(ctx);
    check(dup != NULL && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1, "copy");
    hex("33", out, outl);
    {
        unsigned char out2[16];

        check(EVP_MAC_final(dup, out2, &outl, sizeof(out2)) == 1 && memcmp(out, out2, 16) == 0,
              "the copy agrees");
    }
    EVP_MAC_CTX_free(dup);
    c = 1;
    d = 3;
    params[0] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_C_ROUNDS, &c);
    params[1] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_D_ROUNDS, &d);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, 16);
    params[3] = OSSL_PARAM_construct_end();
    check(EVP_MAC_CTX_set_params(ctx, params) == 1 && EVP_MAC_update(ctx, data, 64) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1, "SipHash-1-3");
    hex("1-3", out, outl);
    size = 12;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "a size of 12");
    errors();
    EVP_MAC_CTX_free(ctx);
}

static void blake2(const char *name, int max, const char *want)
{
    unsigned char key[64], data[200], out[64];
    EVP_MAC_CTX *ctx = context(name), *dup;
    OSSL_PARAM params[4];
    size_t outl = 0, size;
    int i, r;

    for (i = 0; i < 64; i++)
        key[i] = (unsigned char)i;
    for (i = 0; i < 200; i++)
        data[i] = (unsigned char)i;
    check(ctx != NULL, name);
    sizes(ctx, "new");
    r = EVP_MAC_init(ctx, NULL, 0, NULL);
    check(r == 0, "init without a key");
    errors();
    memset(out, 0xee, sizeof(out));
    check(EVP_MAC_update(ctx, data, 3) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && (int)outl == max
          && out[0] == 0xee, "final before init writes nothing");
    r = EVP_MAC_init(ctx, key, (size_t)max + 1, NULL);
    check(r == 0, "a key too long");
    errors();
    check(EVP_MAC_init(ctx, key, (size_t)max, NULL) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && same_hex(out, outl, want),
          "the keyed empty message's vector");
    memset(out, 0xee, sizeof(out));
    check(EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && out[0] == 0xee,
          "final again writes nothing");
    check(EVP_MAC_init(ctx, NULL, 0, NULL) == 1 && EVP_MAC_update(ctx, data, 100) == 1,
          "init again");
    dup = EVP_MAC_CTX_dup(ctx);
    check(dup != NULL && EVP_MAC_update(ctx, data + 100, 100) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1, "copy and finish");
    hex("200", out, outl);
    {
        unsigned char out2[64];

        check(EVP_MAC_update(dup, data + 100, 100) == 1
              && EVP_MAC_final(dup, out2, &outl, sizeof(out2)) == 1
              && memcmp(out, out2, outl) == 0, "the copy agrees");
    }
    EVP_MAC_CTX_free(dup);

    size = 20;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_SALT, "saltsalt", 8);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, "personal", 8);
    params[3] = OSSL_PARAM_construct_end();
    check(EVP_MAC_init(ctx, key, 7, params) == 1 && EVP_MAC_update(ctx, data, 31) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && outl == 20,
          "size, salt, and custom");
    hex("20", out, outl);
    sizes(ctx, "20");
    size = 0;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "a size of 0");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_SALT, data, (size_t)max / 4 + 1);
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "a salt too long");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, data, (size_t)max / 4 + 1);
    r = EVP_MAC_CTX_set_params(ctx, params);
    check(r == 0, "a custom string too long");
    errors();
    EVP_MAC_CTX_free(ctx);
}

/* A TLS record's MAC against HMAC's of its header and data. */
static void tls_record(const char *digest, size_t data_size, size_t total)
{
    unsigned char header[13], record[600], key[48], out[64], want[64];
    EVP_MAC_CTX *ctx = context("HMAC");
    OSSL_PARAM params[4];
    size_t outl = 0, wantl = 0, i;
    char what[80];
    int r;

    for (i = 0; i < sizeof(header); i++)
        header[i] = (unsigned char)(i * 9 + 1);
    for (i = 0; i < sizeof(record); i++)
        record[i] = (unsigned char)(i * 13 + 5);
    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(0xa0 ^ i);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)digest, 0);
    params[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, &total);
    params[2] = OSSL_PARAM_construct_end();
    snprintf(what, sizeof(what), "TLS %s %zu of %zu", digest, data_size, total);
    r = EVP_MAC_init(ctx, key, 20, params) == 1 && EVP_MAC_update(ctx, header, 13) == 1
        && EVP_MAC_update(ctx, record, data_size) == 1
        && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1;
    EVP_MAC_CTX_free(ctx);
    ctx = context("HMAC");
    params[1] = OSSL_PARAM_construct_end();
    EVP_MAC_init(ctx, key, 20, params);
    EVP_MAC_update(ctx, header, 13);
    EVP_MAC_update(ctx, record, data_size);
    EVP_MAC_final(ctx, want, &wantl, sizeof(want));
    EVP_MAC_CTX_free(ctx);
    check(r && outl == wantl && memcmp(out, want, outl) == 0, what);
}

static void tls(void)
{
    unsigned char header[13] = { 0 }, record[300] = { 0 }, out[64];
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[3];
    size_t outl = 0, total = 300;
    int r;

    tls_record("SHA1", 0, 300);
    tls_record("SHA1", 17, 64);
    tls_record("SHA256", 200, 300);
    tls_record("SHA2-224", 100, 160);
    tls_record("SHA384", 250, 320);
    tls_record("SHA512", 1, 512);
    tls_record("MD5", 64, 96);

    ctx = context("HMAC");
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, &total);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_MAC_init(ctx, (const unsigned char *)"key", 3, params) == 1, "TLS mode");
    r = EVP_MAC_final(ctx, out, &outl, sizeof(out));
    check(r == 0, "no MAC before a record");
    r = EVP_MAC_update(ctx, header, 12);
    check(r == 0, "a header of 12 octets");
    check(EVP_MAC_update(ctx, header, 13) == 1, "the header");
    r = EVP_MAC_update(ctx, record, 301);
    check(r == 0, "data longer than the record");
    check(EVP_MAC_update(ctx, record, 10) == 1 && EVP_MAC_update(ctx, record, 20) == 1
          && EVP_MAC_final(ctx, out, &outl, sizeof(out)) == 1 && outl == 32,
          "each update a record");
    hex("last record", out, outl);
    EVP_MAC_CTX_free(ctx);

    ctx = context("HMAC");
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA3-256", 0);
    check(EVP_MAC_init(ctx, (const unsigned char *)"key", 3, params) == 1
          && EVP_MAC_update(ctx, header, 13) == 1, "TLS mode with SHA3-256");
    r = EVP_MAC_update(ctx, record, 10);
    check(r == 0, "which the record MAC doesn't take");
    r = EVP_MAC_final(ctx, out, &outl, sizeof(out));
    check(r == 0, "so no MAC");
    errors();
    EVP_MAC_CTX_free(ctx);
}

int main(void)
{
    methods();
    kmac();
    poly1305();
    siphash();
    blake2("BLAKE2BMAC", 64,
           "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
           "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568");
    blake2("BLAKE2SMAC", 32, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49");
    tls();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
