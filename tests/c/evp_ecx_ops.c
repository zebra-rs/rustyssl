/*
 * Conformance test for the default provider's X25519 exchange and Ed25519 signatures
 * (EVP_KEYEXCH-X25519(7), EVP_SIGNATURE-ED25519(7)), in TAP format: the algorithms and their
 * parameter lists; RFC 7748's shared secret, sized and cut short, with a low-order peer and a
 * public key; RFC 8032's signatures for Ed25519, Ed25519ctx, and Ed25519ph (one-shot, through
 * EVP_DigestSign, and through the message API), verified, changed, and malformed; the
 * instance and context-string parameters and their errors; the algorithm identifier; and
 * copies of contexts.
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
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

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

static const char A_PRIV[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char B_PRIV[] = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
static const char B_PUB[] = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

static void test_exchange(void)
{
    EVP_KEYEXCH *x = EVP_KEYEXCH_fetch(NULL, "X25519", NULL);
    EVP_PKEY *a = raw(EVP_PKEY_X25519, A_PRIV, 1), *b = raw(EVP_PKEY_X25519, B_PRIV, 1);
    EVP_PKEY *bpub = raw(EVP_PKEY_X25519, B_PUB, 0);
    EVP_PKEY *zero = raw(EVP_PKEY_X25519,
                         "0000000000000000000000000000000000000000000000000000000000000000", 0);
    EVP_PKEY *ed = raw(EVP_PKEY_ED25519, A_PRIV, 1);
    EVP_PKEY_CTX *c;
    unsigned char s[64];
    size_t len;
    int r;

    check(x != NULL, "X25519");
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
    len = 31;
    r = EVP_PKEY_derive(c, s, &len);
    printf("  into 31 octets %d\n", r);
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
    printf("  a low-order peer %d\n", r);
    hex("buffer", s, 32);
    errors();
    r = EVP_PKEY_derive_set_peer(c, ed);
    printf("  an Ed25519 peer %d\n", r);
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
    EVP_PKEY_free(ed);
}

/* RFC 8032 7.1 TEST 2, 7.2 (foo), 7.3 (abc). */
static const char T2_PRIV[] = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
static const char CTX_PRIV[] = "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6";
static const char PH_PRIV[] = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";

/* Signs msg with the algorithm (NULL: EVP_DigestSign) and context; prints and verifies. */
static void sign(const char *what, const char *priv, const char *alg, const char *instance,
                 const char *ctxhex, const unsigned char *msg, size_t msglen)
{
    EVP_PKEY *k = raw(EVP_PKEY_ED25519, priv, 1);
    OSSL_PARAM ps[3], *p = ps;
    unsigned char sig[100], *ctx = NULL;
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
    static const char *const algs[] = { "ED25519", "ED25519ph", "ED25519ctx" };
    static const unsigned char abc[] = "abc", foo_msg[] = {
        0xf7, 0x26, 0x93, 0x6d, 0x19, 0xc8, 0x00, 0x49,
        0x4e, 0x3f, 0xda, 0xff, 0x20, 0xb2, 0x76, 0xa8
    };
    size_t i;

    for (i = 0; i < 3; i++) {
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
    sign("Ed25519, DigestSign", T2_PRIV, NULL, NULL, NULL, (const unsigned char *)"\x72", 1);
    sign("Ed25519, message", T2_PRIV, "ED25519", NULL, NULL, (const unsigned char *)"\x72", 1);
    sign("Ed25519ctx foo, message", CTX_PRIV, "ED25519ctx", NULL, "666f6f", foo_msg, 16);
    sign("Ed25519ctx foo, DigestSign", CTX_PRIV, NULL, "Ed25519ctx", "666f6f", foo_msg, 16);
    sign("Ed25519ctx without a context", CTX_PRIV, "ED25519ctx", NULL, NULL, foo_msg, 16);
    sign("Ed25519ph abc, message", PH_PRIV, "ED25519ph", NULL, NULL, abc, 3);
    sign("Ed25519ph abc, DigestSign", PH_PRIV, NULL, "Ed25519ph", NULL, abc, 3);
    sign("Ed25519ph with a context", PH_PRIV, "ED25519ph", NULL, "01", abc, 3);
    sign("Ed25519 with a context", T2_PRIV, NULL, NULL, "01", abc, 3);
    sign("an instance on a preset one", T2_PRIV, "ED25519", "Ed25519ph", NULL, abc, 3);
    sign("an unknown instance", T2_PRIV, NULL, "Ed448", NULL, abc, 3);
    sign("a bogus instance", T2_PRIV, NULL, "Ed25519bogus", NULL, abc, 3);
    {
        char big[600];

        memset(big, 'a', 512);
        big[512] = '\0';
        sign("a 256-octet context", CTX_PRIV, "ED25519ctx", NULL, big, abc, 3);
    }
}

static void test_more(void)
{
    EVP_PKEY *k = raw(EVP_PKEY_ED25519, T2_PRIV, 1);
    EVP_PKEY *pub = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_SIGNATURE *ph = EVP_SIGNATURE_fetch(NULL, "ED25519ph", NULL);
    unsigned char sig[100], dg[64], aid[40];
    size_t len, n = 32;
    OSSL_PARAM g[2];
    int r;

    {
        unsigned char q[32];

        EVP_PKEY_get_raw_public_key(k, q, &n);
        pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, q, n);
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
    names("gettable", EVP_PKEY_CTX_gettable_params(c));
    names("settable", EVP_PKEY_CTX_settable_params(c));
    r = EVP_PKEY_sign_init_ex2(c, ph, NULL);
    memset(dg, 0x11, sizeof(dg));
    len = sizeof(sig);
    r = r * 10 + EVP_PKEY_sign(c, sig, &len, dg, 64);
    printf("  Ed25519ph over a 64-octet hash %d\n", r);
    hex("sig", sig, len);
    errors();
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, dg, 63);
    printf("  over 63 octets %d\n", r);
    errors();
    len = 10;
    r = EVP_PKEY_sign(c, sig, &len, dg, 64);
    printf("  into 10 octets %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    r = EVP_PKEY_sign_message_init(c, ph, NULL);
    len = sizeof(sig);
    r = r * 10 + EVP_PKEY_sign(c, sig, &len, dg, 64);
    printf("  a public key signs %d\n", r);
    errors();
    r = EVP_PKEY_verify_message_init(c, ph, NULL);
    r = r * 10 + EVP_PKEY_verify(c, sig, 63, dg, 64);
    printf("  a 63-octet signature %d\n", r);
    errors();
    {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        r = EVP_DigestSignInit_ex(m, NULL, "SHA512", NULL, NULL, k, NULL);
        printf("  DigestSignInit with SHA512 %d\n", r);
        errors();
        EVP_MD_CTX_free(m);
    }
    EVP_PKEY_CTX_free(c);
    EVP_SIGNATURE_free(ph);
    EVP_PKEY_free(k);
    EVP_PKEY_free(pub);
}

/*
 * Generation from a key with a type but no data (EVP_PKEY_set_type), as oqs-provider makes its
 * hybrids' classical halves: the key manager gets no template. EC's needs one and fails.
 */
static void test_typed_template(void)
{
    static const int types[] = { EVP_PKEY_X25519, EVP_PKEY_X448, EVP_PKEY_ED25519,
                                 EVP_PKEY_ED448, EVP_PKEY_RSA, EVP_PKEY_EC };
    size_t i;

    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        EVP_PKEY *t = EVP_PKEY_new(), *k = NULL;
        EVP_PKEY_CTX *c;
        char what[96];
        int r;

        snprintf(what, sizeof(what), "a typed template: set_type %s",
                 OBJ_nid2sn(types[i]));
        check(t != NULL && EVP_PKEY_set_type(t, types[i]) == 1, what);
        c = EVP_PKEY_CTX_new_from_pkey(NULL, t, NULL);
        check(c != NULL && EVP_PKEY_keygen_init(c) == 1, "  a context for it, initialized");
        if (types[i] == EVP_PKEY_RSA)
            EVP_PKEY_CTX_set_rsa_keygen_bits(c, 1024);
        r = c != NULL ? EVP_PKEY_keygen(c, &k) : -9;
        printf("  keygen %d, key %s, id %d\n", r, k != NULL ? "made" : "none",
               k != NULL ? EVP_PKEY_get_id(k) : 0);
        check(types[i] == EVP_PKEY_EC ? r == 0 && k == NULL
                                      : r == 1 && k != NULL && EVP_PKEY_get_id(k) == types[i],
              "  generates as the reference does");
        errors();
        EVP_PKEY_free(k);
        EVP_PKEY_CTX_free(c);
        EVP_PKEY_free(t);
    }
}

int main(void)
{
    test_exchange();
    test_signatures();
    test_more();
    test_typed_template();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
