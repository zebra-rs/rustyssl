/*
 * Conformance test for the default provider's X448 exchange and Ed448 signatures
 * (EVP_KEYEXCH-X448(7), EVP_SIGNATURE-ED448(7)), in TAP format: the algorithms and their
 * parameter lists; RFC 7748's shared secret, sized and cut short, with a low-order peer and a
 * public key; RFC 8032's signatures for Ed448 (with and without a context) and Ed448ph
 * (through EVP_DigestSign and through the message API), verified, changed, and malformed; the
 * instance and context-string parameters and their errors (an Ed25519 instance on an Ed448
 * key); the algorithm identifier; a caller's 64-octet prehash; and copies of contexts.
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
#include <openssl/provider.h>

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
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t len)
{
    size_t i;

    printf("  %s (%zu):", label, len);
    for (i = 0; i < len; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" (none)");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static void print_name(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static unsigned char *octets(const char *h, size_t *len)
{
    long n = 0;
    unsigned char *p = OPENSSL_hexstr2buf(h, &n);

    *len = (size_t)n;
    return p;
}

static EVP_PKEY *raw(int id, const char *h, int priv)
{
    size_t n;
    unsigned char *b = octets(h, &n);
    EVP_PKEY *k = priv ? EVP_PKEY_new_raw_private_key(id, NULL, b, n)
                       : EVP_PKEY_new_raw_public_key(id, NULL, b, n);

    OPENSSL_free(b);
    return k;
}

/* RFC 7748 6.2. */
static const char A_PRIV[] = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5"
                             "74a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
static const char B_PRIV[] = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120"
                             "bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
static const char B_PUB[] = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972"
                            "fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
static const char ZERO56[] = "0000000000000000000000000000000000000000000000000000000000000000"
                             "000000000000000000000000000000000000000000000000";
static const char ONE56[] = "0100000000000000000000000000000000000000000000000000000000000000"
                            "000000000000000000000000000000000000000000000000";
/* RFC 8032 7.4: the 1-octet key (also with "foo"), and 7.5's Ed448ph key. */
static const char K1_PRIV[] = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a"
                              "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e";
static const char PH_PRIV[] = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
                              "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49";

static void test_exchange(void)
{
    EVP_KEYEXCH *x = EVP_KEYEXCH_fetch(NULL, "X448", NULL);
    EVP_PKEY *a = raw(EVP_PKEY_X448, A_PRIV, 1), *b = raw(EVP_PKEY_X448, B_PRIV, 1);
    EVP_PKEY *bpub = raw(EVP_PKEY_X448, B_PUB, 0);
    EVP_PKEY *zero = raw(EVP_PKEY_X448, ZERO56, 0), *one = raw(EVP_PKEY_X448, ONE56, 0);
    EVP_PKEY *x25519 = raw(EVP_PKEY_X25519,
                           "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", 1);
    EVP_PKEY_CTX *c;
    unsigned char s[100];
    size_t len;
    int r;

    check(x != NULL, "X448");
    if (x != NULL) {
        printf("  names:");
        EVP_KEYEXCH_names_do_all(x, print_name, NULL);
        printf("\n");
        names("gettable", EVP_KEYEXCH_gettable_ctx_params(x));
        names("settable", EVP_KEYEXCH_settable_ctx_params(x));
        EVP_KEYEXCH_free(x);
    }
    c = EVP_PKEY_CTX_new_from_pkey(NULL, a, NULL);
    r = EVP_PKEY_derive_init(c);
    r = r * 10 + EVP_PKEY_derive_set_peer(c, bpub);
    len = 0;
    r = r * 10 + EVP_PKEY_derive(c, NULL, &len);
    printf("  init/peer/size %d %zu\n", r, len);
    len = sizeof(s);
    r = EVP_PKEY_derive(c, s, &len);
    check(r == 1, "RFC 7748's secret");
    hex("secret", s, len);
    errors();
    len = 55;
    r = EVP_PKEY_derive(c, s, &len);
    printf("  into 55 octets %d\n", r);
    errors();
    {
        EVP_PKEY_CTX *d = EVP_PKEY_CTX_dup(c);

        len = sizeof(s);
        r = d != NULL ? EVP_PKEY_derive(d, s, &len) : -9;
        printf("  a copy derives %d\n", r);
        hex("secret", s, len);
        EVP_PKEY_CTX_free(d);
    }
    r = EVP_PKEY_derive_set_peer(c, zero);
    len = sizeof(s);
    memset(s, 0x77, sizeof(s));
    r = r * 10 + EVP_PKEY_derive(c, s, &len);
    printf("  a peer of 0 %d\n", r);
    hex("buffer", s, 56);
    errors();
    r = EVP_PKEY_derive_set_peer(c, one);
    len = sizeof(s);
    memset(s, 0x77, sizeof(s));
    r = r * 10 + EVP_PKEY_derive(c, s, &len);
    printf("  a peer of 1 %d\n", r);
    hex("buffer", s, 56);
    errors();
    r = EVP_PKEY_derive_set_peer(c, x25519);
    printf("  an X25519 peer %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, bpub, NULL);
    r = EVP_PKEY_derive_init(c);
    r = r * 10 + EVP_PKEY_derive_set_peer(c, a);
    len = sizeof(s);
    r = r * 10 + EVP_PKEY_derive(c, s, &len);
    printf("  a public key derives %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, b, NULL);
    r = EVP_PKEY_derive_init(c);
    len = sizeof(s);
    r = r * 10 + EVP_PKEY_derive(c, s, &len);
    printf("  no peer %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    EVP_PKEY_free(bpub);
    EVP_PKEY_free(zero);
    EVP_PKEY_free(one);
    EVP_PKEY_free(x25519);
}

/* Signs msg with the algorithm (NULL: EVP_DigestSign) and context; prints and verifies. */
static void sign(const char *what, const char *priv, const char *alg, const char *instance,
                 const char *ctxhex, const unsigned char *msg, size_t msglen)
{
    EVP_PKEY *k = raw(EVP_PKEY_ED448, priv, 1);
    OSSL_PARAM ps[3], *p = ps;
    unsigned char sig[200], *ctx = NULL;
    size_t len = sizeof(sig), cl = 0;
    int r;

    if (instance != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, (char *)instance,
                                                0);
    if (ctxhex != NULL) {
        ctx = octets(ctxhex, &cl);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx, cl);
    }
    *p = OSSL_PARAM_construct_end();
    if (alg == NULL) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        r = EVP_DigestSignInit_ex(m, NULL, NULL, NULL, NULL, k, ps);
        r = r * 10 + EVP_DigestSign(m, sig, &len, msg, msglen);
        printf("  %s: %d", what, r);
        if (r == 11)
            hex("sig", sig, len);
        else
            printf("\n");
        errors();
        if (r == 11) {
            r = EVP_DigestVerifyInit_ex(m, NULL, NULL, NULL, NULL, k, ps);
            r = r * 10 + EVP_DigestVerify(m, sig, len, msg, msglen);
            sig[0] ^= 1;
            printf("  verify %d changed %d\n", r, EVP_DigestVerify(m, sig, len, msg, msglen));
            errors();
        }
        EVP_MD_CTX_free(m);
    } else {
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

        r = EVP_PKEY_sign_message_init(c, s, ps);
        r = r * 10 + EVP_PKEY_sign(c, sig, &len, msg, msglen);
        printf("  %s: %d", what, r);
        if (r == 11)
            hex("sig", sig, len);
        else
            printf("\n");
        errors();
        if (r == 11) {
            r = EVP_PKEY_verify_message_init(c, s, ps);
            r = r * 10 + EVP_PKEY_verify(c, sig, len, msg, msglen);
            printf("  verify %d", r);
            r = EVP_PKEY_verify_init_ex2(c, s, ps);
            r = r * 10 + EVP_PKEY_verify(c, sig, len, msg, msglen);
            printf(" through verify_init %d\n", r);
            errors();
        }
        EVP_PKEY_CTX_free(c);
        EVP_SIGNATURE_free(s);
    }
    OPENSSL_free(ctx);
    EVP_PKEY_free(k);
}

static void test_signatures(void)
{
    static const char *const algs[] = { "ED448", "ED448ph" };
    static const unsigned char abc[] = "abc";
    size_t i;

    for (i = 0; i < 2; i++) {
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, algs[i], NULL);

        check(s != NULL, algs[i]);
        if (s == NULL) {
            errors();
            continue;
        }
        printf("  names:");
        EVP_SIGNATURE_names_do_all(s, print_name, NULL);
        printf("\n");
        names("gettable", EVP_SIGNATURE_gettable_ctx_params(s));
        names("settable", EVP_SIGNATURE_settable_ctx_params(s));
        EVP_SIGNATURE_free(s);
    }
    sign("Ed448, DigestSign", K1_PRIV, NULL, NULL, NULL, (const unsigned char *)"\x03", 1);
    sign("Ed448, message", K1_PRIV, "ED448", NULL, NULL, (const unsigned char *)"\x03", 1);
    sign("Ed448 foo, DigestSign", K1_PRIV, NULL, NULL, "666f6f", (const unsigned char *)"\x03", 1);
    sign("Ed448 foo, message", K1_PRIV, "ED448", NULL, "666f6f", (const unsigned char *)"\x03", 1);
    sign("Ed448ph abc, message", PH_PRIV, "ED448ph", NULL, NULL, abc, 3);
    sign("Ed448ph abc, DigestSign", PH_PRIV, NULL, "Ed448ph", NULL, abc, 3);
    sign("Ed448ph with a context", PH_PRIV, "ED448ph", NULL, "01", abc, 3);
    sign("an instance on a preset one", K1_PRIV, "ED448", "Ed448ph", NULL, abc, 3);
    sign("an Ed25519 instance", K1_PRIV, NULL, "Ed25519ph", NULL, abc, 3);
    sign("a bogus instance", K1_PRIV, NULL, "Ed448bogus", NULL, abc, 3);
    {
        char big[600];

        memset(big, 'a', 512);
        big[512] = '\0';
        sign("a 256-octet context", K1_PRIV, "ED448", NULL, big, abc, 3);
        big[510] = '\0';
        sign("a 255-octet context", K1_PRIV, "ED448", NULL, big, abc, 3);
    }
}

static void test_more(void)
{
    EVP_PKEY *k = raw(EVP_PKEY_ED448, K1_PRIV, 1);
    EVP_PKEY *pub = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_SIGNATURE *ph = EVP_SIGNATURE_fetch(NULL, "ED448ph", NULL);
    unsigned char sig[200], dg[64], aid[40];
    size_t len, n = 57;
    OSSL_PARAM g[2];
    int r;

    {
        unsigned char q[57];

        EVP_PKEY_get_raw_public_key(k, q, &n);
        pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, q, n);
    }
    r = EVP_PKEY_sign_init(c);
    len = 0;
    r = r * 10 + EVP_PKEY_sign(c, NULL, &len, (const unsigned char *)"x", 1);
    printf("  sign_init and size %d %zu\n", r, len);
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, (const unsigned char *)"x", 1);
    printf("  sign_init then sign %d\n", r);
    errors();
    g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    g[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(c, g);
    printf("  get_params %d\n", r);
    hex("algorithm-id", aid, g[0].return_size);
    r = EVP_PKEY_sign_init_ex2(c, ph, NULL);
    memset(dg, 0x11, sizeof(dg));
    len = sizeof(sig);
    r = r * 10 + EVP_PKEY_sign(c, sig, &len, dg, 64);
    printf("  Ed448ph over a 64-octet hash %d\n", r);
    hex("sig", sig, len);
    errors();
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, dg, 63);
    printf("  over 63 octets %d\n", r);
    errors();
    len = 113;
    r = EVP_PKEY_sign(c, sig, &len, dg, 64);
    printf("  into 113 octets %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    r = EVP_PKEY_sign_message_init(c, ph, NULL);
    len = sizeof(sig);
    r = r * 10 + EVP_PKEY_sign(c, sig, &len, dg, 64);
    printf("  a public key signs %d\n", r);
    errors();
    r = EVP_PKEY_verify_message_init(c, ph, NULL);
    r = r * 10 + EVP_PKEY_verify(c, sig, 113, dg, 64);
    printf("  a 113-octet signature %d\n", r);
    errors();
    {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        r = EVP_DigestSignInit_ex(m, NULL, "SHAKE256", NULL, NULL, k, NULL);
        printf("  DigestSignInit with SHAKE256 %d\n", r);
        errors();
        EVP_MD_CTX_free(m);
    }
    EVP_PKEY_CTX_free(c);
    EVP_SIGNATURE_free(ph);
    EVP_PKEY_free(k);
    EVP_PKEY_free(pub);
}

int main(void)
{
    test_exchange();
    test_signatures();
    test_more();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
