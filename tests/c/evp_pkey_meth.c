/*
 * Conformance test for the application methods of keys and key contexts
 * (EVP_PKEY_ASN1_METHOD(3), EVP_PKEY_asn1_new(3), EVP_PKEY_METHOD(3), EVP_PKEY_meth_new(3),
 * EVP_PKEY_assign(3)), in TAP format: the built-in methods' tables, then a key type of the
 * test's own (an object it creates) with an ASN.1 method and a key method whose functions log
 * each call. Keys of the type hold a few octets through EVP_PKEY_assign; the test drives the
 * key functions that go to the ASN.1 method (sizes, comparisons, parameters, raw keys, the
 * default digest, freeing) and every key context operation that goes to the key method
 * (generation, signing and verifying, digest signing, encryption, derivation, checks, ctrls and
 * ctrl strings, parameters translated to ctrls, copies), so the output shows what OpenSSL calls
 * and when. A key method registered for HMAC shows the application's method taking the place
 * of the provider's.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

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

static const char *str(const char *s)
{
    return s == NULL ? "(null)" : s;
}

/* The key type ------------------------------------------------------------------------------ */

static int toy_nid, toy_alias;

typedef struct {
    unsigned char k[16];
    size_t len;
} TOY;

static TOY *toy_new(const char *octets)
{
    TOY *t = OPENSSL_zalloc(sizeof(*t));

    if (t != NULL) {
        t->len = strlen(octets) < sizeof(t->k) ? strlen(octets) : sizeof(t->k);
        memcpy(t->k, octets, t->len);
    }
    return t;
}

static const TOY *toy_of(const EVP_PKEY *pk)
{
    return EVP_PKEY_get0(pk);
}

/* The ASN.1 method's functions. */

static int am_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const TOY *x = toy_of(a), *y = toy_of(b);

    printf("    [am pub_cmp]\n");
    return x != NULL && y != NULL && x->len == y->len && memcmp(x->k, y->k, x->len) == 0;
}

static int am_size(const EVP_PKEY *pk)
{
    printf("    [am size]\n");
    return toy_of(pk) == NULL ? 0 : (int)toy_of(pk)->len;
}

static int am_bits(const EVP_PKEY *pk)
{
    printf("    [am bits]\n");
    return toy_of(pk) == NULL ? 0 : (int)toy_of(pk)->len * 8;
}

static int am_security_bits(const EVP_PKEY *pk)
{
    printf("    [am security_bits]\n");
    return toy_of(pk) == NULL ? 0 : (int)toy_of(pk)->len * 4;
}

static int am_param_missing(const EVP_PKEY *pk)
{
    printf("    [am param_missing]\n");
    return toy_of(pk) == NULL;
}

static int am_param_copy(EVP_PKEY *to, const EVP_PKEY *from)
{
    printf("    [am param_copy %d %d]\n", toy_of(to) != NULL, toy_of(from) != NULL);
    return 1;
}

static int am_param_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    printf("    [am param_cmp]\n");
    (void)a;
    (void)b;
    return 1;
}

static void am_free(EVP_PKEY *pk)
{
    const TOY *t = toy_of(pk);

    printf("    [am free %zu]\n", t == NULL ? (size_t)0 : t->len);
    OPENSSL_free((void *)t);
}

static int am_ctrl(EVP_PKEY *pk, int op, long arg1, void *arg2)
{
    printf("    [am ctrl %d %ld]\n", op, arg1);
    (void)pk;
    switch (op) {
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        *(int *)arg2 = NID_sha256;
        return 2;
    case ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
        return arg1 > 0;
    case ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
        *(unsigned char **)arg2 = OPENSSL_memdup("enc", 3);
        return 3;
    }
    return -2;
}

static int am_check(const EVP_PKEY *pk)
{
    printf("    [am check]\n");
    return toy_of(pk) != NULL;
}

static int am_public_check(const EVP_PKEY *pk)
{
    printf("    [am public_check]\n");
    return toy_of(pk) != NULL;
}

static int am_param_check(const EVP_PKEY *pk)
{
    printf("    [am param_check]\n");
    return toy_of(pk) != NULL;
}

static int am_set_priv_key(EVP_PKEY *pk, const unsigned char *priv, size_t len)
{
    TOY *t = OPENSSL_zalloc(sizeof(*t));

    printf("    [am set_priv_key %zu]\n", len);
    if (t == NULL || len > sizeof(t->k)) {
        OPENSSL_free(t);
        return 0;
    }
    memcpy(t->k, priv, len);
    t->len = len;
    return EVP_PKEY_assign(pk, toy_nid, t);
}

static int am_set_pub_key(EVP_PKEY *pk, const unsigned char *pub, size_t len)
{
    printf("    [am set_pub_key %zu]\n", len);
    return am_set_priv_key(pk, pub, len);
}

static int am_get_priv_key(const EVP_PKEY *pk, unsigned char *priv, size_t *len)
{
    const TOY *t = toy_of(pk);

    printf("    [am get_priv_key %d]\n", priv != NULL);
    if (t == NULL)
        return 0;
    if (priv != NULL) {
        if (*len < t->len)
            return 0;
        memcpy(priv, t->k, t->len);
    }
    *len = t->len;
    return 1;
}

static int am_get_pub_key(const EVP_PKEY *pk, unsigned char *pub, size_t *len)
{
    printf("    [am get_pub_key]\n");
    return am_get_priv_key(pk, pub, len);
}

/* The key method's functions. */

static int pm_init(EVP_PKEY_CTX *ctx)
{
    static int count;

    printf("    [pm init]\n");
    EVP_PKEY_CTX_set_data(ctx, &count);
    return 1;
}

static int pm_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
{
    printf("    [pm copy %d]\n", EVP_PKEY_CTX_get_data(src) != NULL);
    EVP_PKEY_CTX_set_data(dst, EVP_PKEY_CTX_get_data(src));
    return 1;
}

static void pm_cleanup(EVP_PKEY_CTX *ctx)
{
    printf("    [pm cleanup %d]\n", EVP_PKEY_CTX_get_data(ctx) != NULL);
}

static int pm_paramgen_init(EVP_PKEY_CTX *ctx)
{
    printf("    [pm paramgen_init]\n");
    (void)ctx;
    return 1;
}

static int pm_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pk)
{
    printf("    [pm paramgen]\n");
    (void)ctx;
    return EVP_PKEY_assign(pk, toy_nid, toy_new("params"));
}

static int pm_keygen_init(EVP_PKEY_CTX *ctx)
{
    printf("    [pm keygen_init]\n");
    (void)ctx;
    return 1;
}

static int pm_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pk)
{
    printf("    [pm keygen %d]\n", EVP_PKEY_CTX_get0_pkey(ctx) != NULL);
    return EVP_PKEY_assign(pk, toy_nid, toy_new("generated"));
}

static int pm_sign_init(EVP_PKEY_CTX *ctx)
{
    printf("    [pm sign_init]\n");
    (void)ctx;
    return 1;
}

static int pm_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                   const unsigned char *tbs, size_t tbslen)
{
    const TOY *t = toy_of(EVP_PKEY_CTX_get0_pkey(ctx));
    size_t i;

    printf("    [pm sign %d %zu %zu]\n", sig != NULL, *siglen, tbslen);
    if (sig == NULL) {
        *siglen = tbslen;
        return 1;
    }
    if (t == NULL || *siglen < tbslen)
        return 0;
    for (i = 0; i < tbslen; i++)
        sig[i] = tbs[i] ^ t->k[i % t->len];
    *siglen = tbslen;
    return 1;
}

static int pm_verify_init(EVP_PKEY_CTX *ctx)
{
    printf("    [pm verify_init]\n");
    (void)ctx;
    return 1;
}

static int pm_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
                     const unsigned char *tbs, size_t tbslen)
{
    unsigned char buf[64];
    size_t len = sizeof(buf);

    printf("    [pm verify %zu %zu]\n", siglen, tbslen);
    if (tbslen > sizeof(buf) || pm_sign(ctx, buf, &len, tbs, tbslen) != 1)
        return 0;
    return len == siglen && memcmp(buf, sig, siglen) == 0;
}

static int pm_verify_recover_init(EVP_PKEY_CTX *ctx)
{
    printf("    [pm verify_recover_init]\n");
    (void)ctx;
    return 1;
}

static int pm_verify_recover(EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen,
                             const unsigned char *sig, size_t siglen)
{
    printf("    [pm verify_recover %d]\n", rout != NULL);
    return pm_sign(ctx, rout, routlen, sig, siglen);
}

static int pm_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    printf("    [pm signctx_init %s]\n", str(EVP_MD_get0_name(EVP_MD_CTX_get0_md(mctx))));
    (void)ctx;
    return 1;
}

static int pm_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                      EVP_MD_CTX *mctx)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;

    printf("    [pm signctx %d]\n", sig != NULL);
    if (sig == NULL) {
        *siglen = (size_t)EVP_MD_CTX_get_size(mctx);
        return 1;
    }
    if (!EVP_DigestFinal_ex(mctx, md, &mdlen))
        return 0;
    return pm_sign(ctx, sig, siglen, md, mdlen);
}

static int pm_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    printf("    [pm verifyctx_init]\n");
    (void)ctx;
    (void)mctx;
    return 1;
}

static int pm_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                        EVP_MD_CTX *mctx)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;

    printf("    [pm verifyctx %d]\n", siglen);
    if (!EVP_DigestFinal_ex(mctx, md, &mdlen))
        return 0;
    return pm_verify(ctx, sig, (size_t)siglen, md, mdlen);
}

static int pm_encrypt_init(EVP_PKEY_CTX *ctx)
{
    printf("    [pm encrypt_init]\n");
    (void)ctx;
    return 1;
}

static int pm_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                      const unsigned char *in, size_t inlen)
{
    printf("    [pm encrypt %d]\n", out != NULL);
    return pm_sign(ctx, out, outlen, in, inlen);
}

static int pm_decrypt_init(EVP_PKEY_CTX *ctx)
{
    printf("    [pm decrypt_init]\n");
    (void)ctx;
    return 1;
}

static int pm_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                      const unsigned char *in, size_t inlen)
{
    printf("    [pm decrypt %d]\n", out != NULL);
    return pm_sign(ctx, out, outlen, in, inlen);
}

static int pm_derive_init(EVP_PKEY_CTX *ctx)
{
    printf("    [pm derive_init]\n");
    (void)ctx;
    return 1;
}

static int pm_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    const TOY *a = toy_of(EVP_PKEY_CTX_get0_pkey(ctx));
    const TOY *b = toy_of(EVP_PKEY_CTX_get0_peerkey(ctx));
    size_t i;

    printf("    [pm derive %d]\n", key != NULL);
    if (a == NULL || b == NULL)
        return 0;
    if (key == NULL) {
        *keylen = a->len;
        return 1;
    }
    for (i = 0; i < a->len && i < *keylen; i++)
        key[i] = a->k[i] ^ b->k[i % b->len];
    *keylen = i;
    return 1;
}

static int pm_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    printf("    [pm ctrl %d %d %d]\n", type, p1, p2 != NULL);
    (void)ctx;
    switch (type) {
    case EVP_PKEY_CTRL_MD:
        printf("    [pm ctrl md %s]\n", p2 == NULL ? "NULL" : EVP_MD_get0_name(p2));
        return 1;
    case EVP_PKEY_CTRL_GET_MD:
        /* Parameters translated to this ctrl come with no place for the digest. */
        if (p2 == NULL)
            return 0;
        *(const EVP_MD **)p2 = EVP_sha384();
        return 1;
    case EVP_PKEY_CTRL_PEER_KEY:
        return 1;
    case EVP_PKEY_CTRL_DIGESTINIT:
        return 1;
    case EVP_PKEY_CTRL_SET1_ID:
        printf("    [pm ctrl id %.*s]\n", p1, (const char *)p2);
        return 1;
    case EVP_PKEY_CTRL_GET1_ID:
        if (p2 == NULL)
            return 0;
        *(const void **)p2 = "got";
        return 3;
    case EVP_PKEY_CTRL_SET_DIGEST_SIZE:
    case EVP_PKEY_ALG_CTRL + 1:
        return 1;
    case EVP_PKEY_ALG_CTRL + 2:
        printf("    [pm ctrl octets %.*s]\n", p1, (const char *)p2);
        return 1;
    }
    return -2;
}

static int pm_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
    printf("    [pm ctrl_str %s=%s]\n", type, value);
    if (strcmp(type, "str") == 0)
        return EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_ALG_CTRL + 2, value);
    if (strcmp(type, "hex") == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_ALG_CTRL + 2, value);
    if (strcmp(type, "md") == 0)
        return EVP_PKEY_CTX_md(ctx, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD, value);
    return -2;
}

static int pm_digestsign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen)
{
    printf("    [pm digestsign %d %zu]\n", sig != NULL, tbslen);
    return pm_sign(EVP_MD_CTX_get_pkey_ctx(ctx), sig, siglen, tbs, tbslen);
}

static int pm_digestverify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    printf("    [pm digestverify %zu]\n", tbslen);
    return pm_verify(EVP_MD_CTX_get_pkey_ctx(ctx), sig, siglen, tbs, tbslen);
}

static int pm_check(EVP_PKEY *pk)
{
    printf("    [pm check]\n");
    return toy_of(pk) != NULL;
}

static int pm_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    printf("    [pm digest_custom]\n");
    (void)ctx;
    return EVP_DigestUpdate(mctx, "Z", 1);
}

/* The tables ---------------------------------------------------------------------------- */

static void test_tables(void)
{
    int i, n = EVP_PKEY_asn1_get_count();
    size_t j, m = EVP_PKEY_meth_get_count();
    const EVP_PKEY_ASN1_METHOD *a;
    ENGINE *e = (ENGINE *)1;

    printf("  asn1 count %d\n", n);
    for (i = 0; i < n; i++) {
        int id = 0, base = 0, flags = 0;
        const char *info = NULL, *pem = NULL;

        EVP_PKEY_asn1_get0_info(&id, &base, &flags, &info, &pem, EVP_PKEY_asn1_get0(i));
        printf("  %d %d %#x %s %s\n", id, base, flags, str(info), str(pem));
    }
    check(EVP_PKEY_asn1_get0(-1) == NULL && EVP_PKEY_asn1_get0(n) == NULL, "get0 out of range");
    check(EVP_PKEY_asn1_get0_info(NULL, NULL, NULL, NULL, NULL, NULL) == 0, "get0_info NULL");
    a = EVP_PKEY_asn1_find(&e, EVP_PKEY_RSA2);
    check(a == EVP_PKEY_asn1_get0(0) && e == NULL, "find follows an alias");
    check(EVP_PKEY_asn1_find(NULL, EVP_PKEY_HMAC) == NULL, "no method for HMAC");
    e = (ENGINE *)1;
    printf("  find_str %d %d %d %d %d\n",
           EVP_PKEY_asn1_find_str(&e, "rsa", -1) == EVP_PKEY_asn1_get0(0),
           EVP_PKEY_asn1_find_str(NULL, "RSA-PSS", 3) == EVP_PKEY_asn1_get0(0),
           EVP_PKEY_asn1_find_str(NULL, "x9.42 dh", -1) != NULL,
           EVP_PKEY_asn1_find_str(NULL, "DHX", -1) != NULL, e == NULL);

    printf("  meth count %zu\n", m);
    for (j = 0; j < m; j++) {
        int id = 0, flags = 0;
        int (*sign)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
        int (*sinit)(EVP_PKEY_CTX *);
        int (*derive)(EVP_PKEY_CTX *, unsigned char *, size_t *);
        int (*dinit)(EVP_PKEY_CTX *);
        int (*ctrl)(EVP_PKEY_CTX *, int, int, void *);
        int (*ctrl_str)(EVP_PKEY_CTX *, const char *, const char *);
        int (*ds)(EVP_MD_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
        const EVP_PKEY_METHOD *pm = EVP_PKEY_meth_get0(j);

        EVP_PKEY_meth_get0_info(&id, &flags, pm);
        EVP_PKEY_meth_get_sign(pm, &sinit, &sign);
        EVP_PKEY_meth_get_derive(pm, &dinit, &derive);
        EVP_PKEY_meth_get_ctrl(pm, &ctrl, &ctrl_str);
        EVP_PKEY_meth_get_digestsign(pm, &ds);
        printf("  %d %#x sign %d %d derive %d %d ctrl %d %d digestsign %d find %d\n", id, flags,
               sinit != NULL, sign != NULL, dinit != NULL, derive != NULL, ctrl != NULL,
               ctrl_str != NULL, ds != NULL, EVP_PKEY_meth_find(id) == pm);
    }
    check(EVP_PKEY_meth_get0(m) == NULL, "meth get0 out of range");
    check(EVP_PKEY_meth_find(EVP_PKEY_HMAC) == NULL, "no key method for HMAC");
    /* Freeing a built-in method does nothing. */
    EVP_PKEY_asn1_free((EVP_PKEY_ASN1_METHOD *)EVP_PKEY_asn1_get0(0));
    EVP_PKEY_meth_free((EVP_PKEY_METHOD *)EVP_PKEY_meth_get0(0));
    check(EVP_PKEY_asn1_get0(0) != NULL && EVP_PKEY_meth_get0(0) != NULL, "built-ins stay");
}

static EVP_PKEY_ASN1_METHOD *am;
static EVP_PKEY_METHOD *pm;

static void test_asn1_method(void)
{
    EVP_PKEY_ASN1_METHOD *bad, *cp;
    int id = 0, base = 0, flags = 0;
    const char *info = NULL, *pem = NULL;

    am = EVP_PKEY_asn1_new(toy_nid, 0, "TOYALG", "toy ASN.1 method");
    check(am != NULL, "EVP_PKEY_asn1_new");
    EVP_PKEY_asn1_get0_info(&id, &base, &flags, &info, &pem, am);
    printf("  info %d %d %#x %s %s\n", id == toy_nid, base == toy_nid, flags, info, pem);
    EVP_PKEY_asn1_set_public(am, NULL, NULL, am_pub_cmp, NULL, am_size, am_bits);
    EVP_PKEY_asn1_set_private(am, NULL, NULL, NULL);
    EVP_PKEY_asn1_set_param(am, NULL, NULL, am_param_missing, am_param_copy, am_param_cmp, NULL);
    EVP_PKEY_asn1_set_free(am, am_free);
    EVP_PKEY_asn1_set_ctrl(am, am_ctrl);
    EVP_PKEY_asn1_set_security_bits(am, am_security_bits);
    EVP_PKEY_asn1_set_item(am, NULL, NULL);
    EVP_PKEY_asn1_set_siginf(am, NULL);
    EVP_PKEY_asn1_set_check(am, am_check);
    EVP_PKEY_asn1_set_public_check(am, am_public_check);
    EVP_PKEY_asn1_set_param_check(am, am_param_check);
    EVP_PKEY_asn1_set_set_priv_key(am, am_set_priv_key);
    EVP_PKEY_asn1_set_set_pub_key(am, am_set_pub_key);
    EVP_PKEY_asn1_set_get_priv_key(am, am_get_priv_key);
    EVP_PKEY_asn1_set_get_pub_key(am, am_get_pub_key);

    check(EVP_PKEY_asn1_find(NULL, toy_nid) == NULL, "not found before it's added");
    check(EVP_PKEY_asn1_add0(am) == 1, "EVP_PKEY_asn1_add0");
    check(EVP_PKEY_asn1_add0(am) == 0, "a second add0 fails");
    errors();
    bad = EVP_PKEY_asn1_new(toy_alias, ASN1_PKEY_ALIAS, "BAD", NULL);
    check(EVP_PKEY_asn1_add0(bad) == 0, "an alias with a PEM name is refused");
    errors();
    EVP_PKEY_asn1_free(bad);
    check(EVP_PKEY_asn1_add_alias(toy_nid, toy_alias) == 1, "EVP_PKEY_asn1_add_alias");
    printf("  count %d find %d %d type %d %d find_str %d\n", EVP_PKEY_asn1_get_count(),
           EVP_PKEY_asn1_find(NULL, toy_nid) == am, EVP_PKEY_asn1_find(NULL, toy_alias) == am,
           EVP_PKEY_type(toy_alias) == toy_nid, EVP_PKEY_type(toy_nid) == toy_nid,
           EVP_PKEY_asn1_find_str(NULL, "toyalg", -1) == am);
    cp = EVP_PKEY_asn1_new(toy_alias + 1000, 0, "COPY", "copy");
    EVP_PKEY_asn1_copy(cp, am);
    EVP_PKEY_asn1_get0_info(&id, NULL, NULL, &info, NULL, cp);
    printf("  copy keeps %d %s\n", id == toy_alias + 1000, info);
    EVP_PKEY_asn1_free(cp);
}

static void test_legacy_keys(void)
{
    EVP_PKEY *k = EVP_PKEY_new(), *k2 = EVP_PKEY_new(), *blank = EVP_PKEY_new(), *d;
    unsigned char buf[32], *enc = NULL;
    size_t len = sizeof(buf);
    int nid = 0;
    char name[64] = "";

    check(EVP_PKEY_assign(k, toy_nid, toy_new("alpha")) == 1, "EVP_PKEY_assign");
    printf("  id %d base %d asn1 %d desc %s type_name %s\n", EVP_PKEY_get_id(k) == toy_nid,
           EVP_PKEY_get_base_id(k) == toy_nid, EVP_PKEY_get0_asn1(k) == am,
           str(EVP_PKEY_get0_description(k)), str(EVP_PKEY_get0_type_name(k)));
    printf("  bits %d security %d size %d\n", EVP_PKEY_get_bits(k),
           EVP_PKEY_get_security_bits(k), EVP_PKEY_get_size(k));
    printf("  missing %d is_a %d %d\n", EVP_PKEY_missing_parameters(k),
           EVP_PKEY_is_a(k, "TOYALG"), EVP_PKEY_is_a(k, "RSA"));
    check(EVP_PKEY_assign(k2, toy_alias, toy_new("alpha")) == 1, "assign through the alias");
    printf("  alias id %d\n", EVP_PKEY_get_id(k2) == toy_alias);
    printf("  eq %d params_eq %d\n", EVP_PKEY_eq(k, k2), EVP_PKEY_parameters_eq(k, k2));
    printf("  reassign %d\n", EVP_PKEY_assign(k2, toy_nid, toy_new("beta")));
    printf("  eq %d\n", EVP_PKEY_eq(k, k2));
    printf("  copy_parameters %d\n", EVP_PKEY_copy_parameters(blank, k));
    printf("  blank id %d missing %d\n", EVP_PKEY_get_id(blank) == toy_nid,
           EVP_PKEY_missing_parameters(blank));
    errors();
    printf("  raw %d", EVP_PKEY_get_raw_private_key(k, buf, &len));
    hex("", buf, len);
    len = sizeof(buf);
    printf("  raw public %d %zu\n", EVP_PKEY_get_raw_public_key(k, NULL, &len), len);
    printf("  default nid %d sha256 %d\n", EVP_PKEY_get_default_digest_nid(k, &nid),
           nid == NID_sha256);
    printf("  default name %d %s\n", EVP_PKEY_get_default_digest_name(k, name, sizeof(name)),
           name);
    printf("  set encoded %d\n", EVP_PKEY_set1_encoded_public_key(k, (const unsigned char *)"x", 1));
    len = EVP_PKEY_get1_encoded_public_key(k, &enc);
    printf("  get encoded %zu %.*s\n", len, (int)len, (const char *)enc);
    OPENSSL_free(enc);
    d = EVP_PKEY_dup(k);
    printf("  dup %d\n", d != NULL);
    errors();
    EVP_PKEY_free(d);
    printf("  assign NULL %d id %d\n", EVP_PKEY_assign(k2, toy_nid, NULL),
           EVP_PKEY_get_id(k2) == toy_nid);
    printf("  assign unknown %d\n", EVP_PKEY_assign(blank, toy_alias + 2000, NULL));
    errors();
    EVP_PKEY_free(blank);
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k);
}

/* The key method --------------------------------------------------------------------------- */

static void test_pkey_method(void)
{
    EVP_PKEY_METHOD *cp = EVP_PKEY_meth_new(toy_alias, 0);
    int id = 0, flags = 0;
    int (*sinit)(EVP_PKEY_CTX *);
    int (*sign)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
    void (*cleanup)(EVP_PKEY_CTX *);
    int (*ds)(EVP_MD_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);

    pm = EVP_PKEY_meth_new(toy_nid, EVP_PKEY_FLAG_AUTOARGLEN);
    check(pm != NULL && cp != NULL, "EVP_PKEY_meth_new");
    EVP_PKEY_meth_get0_info(&id, &flags, pm);
    printf("  info %d %#x\n", id == toy_nid, flags);
    EVP_PKEY_meth_set_init(pm, pm_init);
    EVP_PKEY_meth_set_copy(pm, pm_copy);
    EVP_PKEY_meth_set_cleanup(pm, pm_cleanup);
    EVP_PKEY_meth_set_paramgen(pm, pm_paramgen_init, pm_paramgen);
    EVP_PKEY_meth_set_keygen(pm, pm_keygen_init, pm_keygen);
    EVP_PKEY_meth_set_sign(pm, pm_sign_init, pm_sign);
    EVP_PKEY_meth_set_verify(pm, pm_verify_init, pm_verify);
    EVP_PKEY_meth_set_verify_recover(pm, pm_verify_recover_init, pm_verify_recover);
    EVP_PKEY_meth_set_encrypt(pm, pm_encrypt_init, pm_encrypt);
    EVP_PKEY_meth_set_decrypt(pm, pm_decrypt_init, pm_decrypt);
    EVP_PKEY_meth_set_derive(pm, pm_derive_init, pm_derive);
    EVP_PKEY_meth_set_ctrl(pm, pm_ctrl, pm_ctrl_str);
    EVP_PKEY_meth_set_check(pm, pm_check);
    EVP_PKEY_meth_set_public_check(pm, NULL);
    EVP_PKEY_meth_set_param_check(pm, NULL);
    EVP_PKEY_meth_set_signctx(pm, NULL, NULL);
    EVP_PKEY_meth_set_verifyctx(pm, NULL, NULL);
    EVP_PKEY_meth_set_digestsign(pm, NULL);
    EVP_PKEY_meth_set_digestverify(pm, NULL);
    EVP_PKEY_meth_set_digest_custom(pm, NULL);
    EVP_PKEY_meth_get_sign(pm, &sinit, &sign);
    EVP_PKEY_meth_get_cleanup(pm, &cleanup);
    check(sinit == pm_sign_init && sign == pm_sign && cleanup == pm_cleanup, "the getters");
    EVP_PKEY_meth_copy(cp, pm);
    EVP_PKEY_meth_get0_info(&id, &flags, cp);
    EVP_PKEY_meth_get_sign(cp, &sinit, &sign);
    EVP_PKEY_meth_get_digestsign(cp, &ds);
    printf("  copy %d %#x %d %d %d\n", id == toy_alias, flags, sinit == pm_sign_init,
           sign == pm_sign, ds == NULL);
    {
        /* Every getter, on the copy. */
        int (*a)(EVP_PKEY_CTX *);
        int (*b)(EVP_PKEY_CTX *, const EVP_PKEY_CTX *);
        int (*g)(EVP_PKEY_CTX *, EVP_PKEY *);
        int (*v)(EVP_PKEY_CTX *, const unsigned char *, size_t, const unsigned char *, size_t);
        int (*vr)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
        int (*sc)(EVP_PKEY_CTX *, EVP_MD_CTX *);
        int (*s2)(EVP_PKEY_CTX *, unsigned char *, size_t *, EVP_MD_CTX *);
        int (*v2)(EVP_PKEY_CTX *, const unsigned char *, int, EVP_MD_CTX *);
        int (*d)(EVP_PKEY_CTX *, unsigned char *, size_t *);
        int (*c)(EVP_PKEY_CTX *, int, int, void *);
        int (*cs)(EVP_PKEY_CTX *, const char *, const char *);
        int (*dv)(EVP_MD_CTX *, const unsigned char *, size_t, const unsigned char *, size_t);
        int (*k)(EVP_PKEY *);
        int (*dc)(EVP_PKEY_CTX *, EVP_MD_CTX *);
        int n = 0;

        EVP_PKEY_meth_get_init(cp, &a);
        n += a == pm_init;
        EVP_PKEY_meth_get_copy(cp, &b);
        n += b == pm_copy;
        EVP_PKEY_meth_get_paramgen(cp, &a, &g);
        n += a == pm_paramgen_init && g == pm_paramgen;
        EVP_PKEY_meth_get_keygen(cp, &a, &g);
        n += a == pm_keygen_init && g == pm_keygen;
        EVP_PKEY_meth_get_verify(cp, &a, &v);
        n += a == pm_verify_init && v == pm_verify;
        EVP_PKEY_meth_get_verify_recover(cp, &a, &vr);
        n += a == pm_verify_recover_init && vr == pm_verify_recover;
        EVP_PKEY_meth_get_signctx(cp, &sc, &s2);
        n += sc == NULL && s2 == NULL;
        EVP_PKEY_meth_get_verifyctx(cp, &sc, &v2);
        n += sc == NULL && v2 == NULL;
        EVP_PKEY_meth_get_encrypt(cp, &a, &vr);
        n += a == pm_encrypt_init && vr == pm_encrypt;
        EVP_PKEY_meth_get_decrypt(cp, &a, &vr);
        n += a == pm_decrypt_init && vr == pm_decrypt;
        EVP_PKEY_meth_get_derive(cp, &a, &d);
        n += a == pm_derive_init && d == pm_derive;
        EVP_PKEY_meth_get_ctrl(cp, &c, &cs);
        n += c == pm_ctrl && cs == pm_ctrl_str;
        EVP_PKEY_meth_get_digestverify(cp, &dv);
        n += dv == NULL;
        EVP_PKEY_meth_get_check(cp, &k);
        n += k == pm_check;
        EVP_PKEY_meth_get_public_check(cp, &k);
        n += k == NULL;
        EVP_PKEY_meth_get_param_check(cp, &k);
        n += k == NULL;
        EVP_PKEY_meth_get_digest_custom(cp, &dc);
        n += dc == NULL;
        printf("  getters %d\n", n);
    }
    EVP_PKEY_meth_free(cp);
    check(EVP_PKEY_meth_find(toy_nid) == NULL, "not found before it's added");
    check(EVP_PKEY_meth_add0(pm) == 1, "EVP_PKEY_meth_add0");
    printf("  count %zu find %d get0 %d\n", EVP_PKEY_meth_get_count(),
           EVP_PKEY_meth_find(toy_nid) == pm,
           EVP_PKEY_meth_get0(EVP_PKEY_meth_get_count() - 1) == pm);
}

static void sign_verify(EVP_PKEY *k)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL), *d;
    unsigned char sig[64], out[64];
    size_t siglen = sizeof(sig), outlen = sizeof(out);
    int r;

    printf("  ctx op %d data %d\n", EVP_PKEY_CTX_get_operation(c), EVP_PKEY_CTX_get_data(c) != NULL);
    r = EVP_PKEY_sign_init(c);
    printf("  sign_init %d op %d\n", r, EVP_PKEY_CTX_get_operation(c));
    siglen = 0;
    r = EVP_PKEY_sign(c, NULL, &siglen, (const unsigned char *)"message", 7);
    printf("  sign size %d %zu\n", r, siglen);
    siglen = 2;
    r = EVP_PKEY_sign(c, sig, &siglen, (const unsigned char *)"message", 7);
    printf("  sign too small %d\n", r);
    errors();
    siglen = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &siglen, (const unsigned char *)"message", 7);
    printf("  sign %d", r);
    hex("", sig, siglen);
    d = EVP_PKEY_CTX_dup(c);
    printf("  dup %d op %d\n", d != NULL, EVP_PKEY_CTX_get_operation(d));
    EVP_PKEY_CTX_free(d);
    r = EVP_PKEY_verify_init(c);
    printf("  verify_init %d\n", r);
    r = EVP_PKEY_verify(c, sig, siglen, (const unsigned char *)"message", 7);
    printf("  verify %d\n", r);
    r = EVP_PKEY_verify(c, sig, siglen, (const unsigned char *)"massage", 7);
    printf("  verify wrong %d\n", r);
    r = EVP_PKEY_verify_recover_init(c);
    printf("  verify_recover_init %d\n", r);
    r = EVP_PKEY_verify_recover(c, out, &outlen, sig, siglen);
    printf("  recover %d %.*s\n", r, (int)outlen, out);
    r = EVP_PKEY_encrypt_init(c);
    printf("  encrypt_init %d\n", r);
    outlen = sizeof(out);
    r = EVP_PKEY_encrypt(c, out, &outlen, (const unsigned char *)"plain", 5);
    printf("  encrypt %d %zu\n", r, outlen);
    r = EVP_PKEY_decrypt_init(c);
    printf("  decrypt_init %d\n", r);
    siglen = 2;
    r = EVP_PKEY_decrypt(c, sig, &siglen, out, outlen);
    printf("  decrypt too small %d\n", r);
    errors();
    siglen = sizeof(sig);
    r = EVP_PKEY_decrypt(c, sig, &siglen, out, outlen);
    printf("  decrypt %d %.*s\n", r, (int)siglen, sig);
    r = EVP_PKEY_sign_message_init(c, NULL, NULL);
    printf("  sign_message_init %d op %d\n", r, EVP_PKEY_CTX_get_operation(c));
    errors();
    r = EVP_PKEY_encapsulate_init(c, NULL);
    printf("  encapsulate_init %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
}

static void test_contexts(void)
{
    EVP_PKEY_CTX *c, *d;
    EVP_PKEY *k = NULL, *p = NULL, *peer = EVP_PKEY_new();
    unsigned char key[32];
    size_t keylen = sizeof(key);
    const EVP_MD *md = NULL;
    int r;
    OSSL_PARAM params[2];
    char mdname[64] = "";

    c = EVP_PKEY_CTX_new_id(toy_nid, NULL);
    check(c != NULL, "EVP_PKEY_CTX_new_id of the key type");
    printf("  is_a %d provider %d\n", EVP_PKEY_CTX_is_a(c, "TOYALG"),
           EVP_PKEY_CTX_get0_provider(c) == NULL);
    r = EVP_PKEY_CTX_ctrl(c, -1, -1, EVP_PKEY_CTRL_SET_DIGEST_SIZE, 8, NULL);
    printf("  ctrl before init %d\n", r);
    errors();
    r = EVP_PKEY_paramgen_init(c);
    printf("  paramgen_init %d\n", r);
    r = EVP_PKEY_paramgen(c, &p);
    printf("  paramgen %d id %d\n", r, p != NULL && EVP_PKEY_get_id(p) == toy_nid);
    r = EVP_PKEY_keygen_init(c);
    printf("  keygen_init %d op %d\n", r, EVP_PKEY_CTX_get_operation(c));
    r = EVP_PKEY_keygen(c, &k);
    printf("  keygen %d id %d bits %d\n", r, k != NULL && EVP_PKEY_get_id(k) == toy_nid,
           EVP_PKEY_get_bits(k));
    r = EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_DIGEST_SIZE, 8, NULL);
    printf("  ctrl %d\n", r);
    r = EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_SIGN, EVP_PKEY_CTRL_SET_DIGEST_SIZE, 8, NULL);
    printf("  ctrl wrong op %d\n", r);
    errors();
    r = EVP_PKEY_CTX_ctrl(c, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_SET_DIGEST_SIZE, 8, NULL);
    printf("  ctrl other type %d\n", r);
    errors();
    r = EVP_PKEY_CTX_ctrl(c, -1, -1, 9999, 0, NULL);
    printf("  ctrl unknown %d\n", r);
    errors();
    r = EVP_PKEY_CTX_ctrl_str(c, "str", "abc");
    printf("  ctrl_str str %d\n", r);
    r = EVP_PKEY_CTX_ctrl_str(c, "hex", "616263");
    printf("  ctrl_str hex %d\n", r);
    r = EVP_PKEY_CTX_ctrl_str(c, "hex", "zz");
    printf("  ctrl_str bad hex %d\n", r);
    errors();
    r = EVP_PKEY_CTX_ctrl_str(c, "nope", "x");
    printf("  ctrl_str unknown %d\n", r);
    errors();
    r = EVP_PKEY_CTX_ctrl_uint64(c, -1, -1, EVP_PKEY_ALG_CTRL + 1, 5);
    printf("  ctrl_uint64 %d\n", r);
    d = EVP_PKEY_CTX_dup(c);
    printf("  dup %d\n", d != NULL);
    EVP_PKEY_CTX_free(d);
    EVP_PKEY_CTX_free(c);

    sign_verify(k);

    /* Parameters and typed setters go to the ctrls. */
    c = EVP_PKEY_CTX_new(k, NULL);
    r = EVP_PKEY_CTX_set1_id(c, "id!", 3);
    printf("  set1_id %d\n", r);
    r = EVP_PKEY_sign_init(c);
    printf("  sign_init with an ID %d\n", r);
    r = EVP_PKEY_CTX_set_signature_md(c, EVP_sha256());
    printf("  set_signature_md %d\n", r);
    r = EVP_PKEY_CTX_get_signature_md(c, &md);
    printf("  get_signature_md %d %s\n", r, md == NULL ? "NULL" : EVP_MD_get0_name(md));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, "SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_set_params(c, params);
    printf("  set_params %d\n", r);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, mdname,
                                                 sizeof(mdname));
    r = EVP_PKEY_CTX_get_params(c, params);
    printf("  get_params %d %s\n", r, mdname);
    params[0] = OSSL_PARAM_construct_utf8_string("nope", "x", 0);
    r = EVP_PKEY_CTX_set_params(c, params);
    printf("  set_params unknown %d\n", r);
    errors();
    {
        unsigned int size = 16;
        void *idp = NULL;
        size_t idlen = 0;

        params[0] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_SIZE, &size);
        r = EVP_PKEY_CTX_set_params(c, params);
        printf("  set_params digest size %d\n", r);
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DIST_ID, "xyz", 3);
        r = EVP_PKEY_CTX_set_params(c, params);
        printf("  set_params distid %d\n", r);
        params[0] = OSSL_PARAM_construct_octet_ptr(OSSL_PKEY_PARAM_DIST_ID, &idp, 0);
        r = EVP_PKEY_CTX_get_params(c, params);
        idlen = params[0].return_size;
        printf("  get_params distid %d %zu %.*s\n", r, idlen, (int)idlen,
               idp == NULL ? "" : (const char *)idp);
        errors();
    }
    printf("  gettable %d settable %d\n", EVP_PKEY_CTX_gettable_params(c) == NULL,
           EVP_PKEY_CTX_settable_params(c) == NULL);
    r = EVP_PKEY_CTX_ctrl_str(c, "digest", "SHA1");
    printf("  ctrl_str digest %d\n", r);
    r = EVP_PKEY_CTX_ctrl_str(c, "md", "SHA224");
    printf("  ctrl_str md %d\n", r);
    r = EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_PADDING);
    printf("  rsa padding %d\n", r);
    r = EVP_PKEY_CTX_set_rsa_keygen_bits(c, 2048);
    printf("  rsa bits %d\n", r);
    r = EVP_PKEY_CTX_set_dh_pad(c, 1);
    printf("  dh pad %d\n", r);
    errors();
    r = EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256());
    printf("  hkdf md on sign %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);

    /* Derivation with a peer. */
    c = EVP_PKEY_CTX_new(k, NULL);
    r = EVP_PKEY_derive_init(c);
    printf("  derive_init %d\n", r);
    r = EVP_PKEY_derive_set_peer(c, peer);
    printf("  set_peer blank %d\n", r);
    errors();
    r = EVP_PKEY_derive_set_peer(c, p);
    printf("  set_peer %d peer %d\n", r, EVP_PKEY_CTX_get0_peerkey(c) == p);
    r = EVP_PKEY_derive(c, NULL, &keylen);
    printf("  derive size %d %zu\n", r, keylen);
    keylen = sizeof(key);
    r = EVP_PKEY_derive(c, key, &keylen);
    printf("  derive %d", r);
    hex("", key, keylen);
    r = EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256());
    printf("  hkdf md %d\n", r);
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "salt", 4);
    r = EVP_PKEY_CTX_set_params(c, params);
    printf("  set_params salt %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);

    /* Checks: the key method's, then the ASN.1 method's. */
    c = EVP_PKEY_CTX_new(k, NULL);
    printf("  check %d public %d param %d private %d\n", EVP_PKEY_check(c),
           EVP_PKEY_public_check(c), EVP_PKEY_param_check(c), EVP_PKEY_private_check(c));
    errors();
    printf("  pairwise %d quick %d %d\n", EVP_PKEY_pairwise_check(c),
           EVP_PKEY_public_check_quick(c), EVP_PKEY_param_check_quick(c));
    errors();
    printf("  fromdata_init %d\n", EVP_PKEY_fromdata_init(c));
    errors();
    EVP_PKEY_CTX_free(c);

    /* A raw key goes through the ASN.1 method when a key method takes the type. */
    {
        EVP_PKEY *raw = EVP_PKEY_new_raw_private_key_ex(NULL, "TOYALG", NULL,
                                                        (const unsigned char *)"rawkey", 6);

        printf("  raw key %d id %d\n", raw != NULL, raw != NULL && EVP_PKEY_get_id(raw) == toy_nid);
        errors();
        EVP_PKEY_free(raw);
        raw = EVP_PKEY_new_raw_public_key(toy_nid, NULL, (const unsigned char *)"pub", 3);
        printf("  raw public key %d\n", raw != NULL);
        errors();
        EVP_PKEY_free(raw);
    }

    EVP_PKEY_free(peer);
    EVP_PKEY_free(p);
    EVP_PKEY_free(k);
}

static void test_digest_sign(void)
{
    EVP_PKEY *k = EVP_PKEY_new();
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char sig[64];
    size_t siglen = sizeof(sig);
    int r;

    EVP_PKEY_assign(k, toy_nid, toy_new("digestkey"));
    r = EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, k);
    printf("  init %d op %d\n", r, EVP_PKEY_CTX_get_operation(pctx));
    r = EVP_DigestSignUpdate(md, "Hello", 5);
    printf("  update %d\n", r);
    siglen = 0;
    r = EVP_DigestSignFinal(md, NULL, &siglen);
    printf("  size %d %zu\n", r, siglen);
    siglen = sizeof(sig);
    r = EVP_DigestSignFinal(md, sig, &siglen);
    printf("  final %d", r);
    hex("", sig, siglen);
    siglen = sizeof(sig);
    r = EVP_DigestSignFinal(md, sig, &siglen);
    printf("  again %d %zu\n", r, siglen);
    r = EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, k);
    printf("  verify init %d\n", r);
    r = EVP_DigestVerifyUpdate(md, "Hello", 5);
    r = EVP_DigestVerifyFinal(md, sig, siglen);
    printf("  verify %d\n", r);
    r = EVP_DigestSignInit(md, NULL, NULL, NULL, k);
    printf("  init default digest %d\n", r);
    errors();
    siglen = sizeof(sig);
    r = EVP_DigestSign(md, sig, &siglen, (const unsigned char *)"oneshot", 7);
    printf("  oneshot %d", r);
    hex("", sig, siglen);

    /* A method that signs the digest context itself, with a custom digest step. */
    EVP_PKEY_meth_set_signctx(pm, pm_signctx_init, pm_signctx);
    EVP_PKEY_meth_set_verifyctx(pm, pm_verifyctx_init, pm_verifyctx);
    EVP_PKEY_meth_set_digest_custom(pm, pm_digest_custom);
    r = EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, k);
    printf("  signctx init %d op %d\n", r, EVP_PKEY_CTX_get_operation(pctx));
    r = EVP_DigestSignUpdate(md, "Hello", 5);
    printf("  update %d\n", r);
    siglen = sizeof(sig);
    r = EVP_DigestSignFinal(md, sig, &siglen);
    printf("  signctx final %d", r);
    hex("", sig, siglen);
    r = EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, k);
    printf("  verifyctx init %d\n", r);
    r = EVP_DigestVerifyUpdate(md, "Hello", 5);
    r = EVP_DigestVerifyFinal(md, sig, siglen);
    printf("  verifyctx %d\n", r);
    EVP_PKEY_meth_set_signctx(pm, NULL, NULL);
    EVP_PKEY_meth_set_verifyctx(pm, NULL, NULL);
    EVP_PKEY_meth_set_digest_custom(pm, NULL);

    /* A one-shot method: updates fail. */
    EVP_PKEY_meth_set_digestsign(pm, pm_digestsign);
    EVP_PKEY_meth_set_digestverify(pm, pm_digestverify);
    r = EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, k);
    printf("  digestsign init %d op %d\n", r, EVP_PKEY_CTX_get_operation(pctx));
    r = EVP_DigestSignUpdate(md, "Hello", 5);
    printf("  update %d\n", r);
    errors();
    siglen = sizeof(sig);
    r = EVP_DigestSign(md, sig, &siglen, (const unsigned char *)"oneshot", 7);
    printf("  digestsign %d", r);
    hex("", sig, siglen);
    r = EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, k);
    r = EVP_DigestVerify(md, sig, siglen, (const unsigned char *)"oneshot", 7);
    printf("  digestverify %d\n", r);
    EVP_PKEY_meth_set_digestsign(pm, NULL);
    EVP_PKEY_meth_set_digestverify(pm, NULL);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(k);
}

static int hm_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pk)
{
    printf("    [hm keygen]\n");
    (void)ctx;
    (void)pk;
    return 0;
}

static void test_override(void)
{
    EVP_PKEY_METHOD *hm = EVP_PKEY_meth_new(EVP_PKEY_HMAC, 0);
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL;

    EVP_PKEY_meth_set_keygen(hm, NULL, hm_keygen);
    check(EVP_PKEY_meth_add0(hm) == 1, "a key method for HMAC");
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
    printf("  ctx %d provider %d\n", c != NULL, EVP_PKEY_CTX_get0_provider(c) == NULL);
    printf("  keygen_init %d keygen %d\n", EVP_PKEY_keygen_init(c), EVP_PKEY_keygen(c, &k));
    errors();
    EVP_PKEY_CTX_free(c);
    check(EVP_PKEY_meth_remove(hm) == 1, "EVP_PKEY_meth_remove");
    check(EVP_PKEY_meth_remove(hm) == 0, "a second remove fails");
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
    printf("  provider again %d\n", EVP_PKEY_CTX_get0_provider(c) == NULL);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_meth_free(hm);
    EVP_PKEY_free(k);
}

static void test_removed(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(toy_nid, NULL);

    check(EVP_PKEY_meth_remove(pm) == 1, "remove the key method");
    printf("  find %d\n", EVP_PKEY_meth_find(toy_nid) == NULL);
    printf("  keygen_init with the removed method %d\n", EVP_PKEY_keygen_init(c));
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new_id(toy_nid, NULL);
    printf("  new ctx %d\n", c != NULL);
    errors();
    EVP_PKEY_CTX_free(c);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    toy_nid = OBJ_create("1.3.6.1.4.1.99999.7", "TOYALG", "toy algorithm");
    toy_alias = OBJ_create("1.3.6.1.4.1.99999.8", "TOYALIAS", "toy alias");
    check(toy_nid != NID_undef && toy_alias != NID_undef, "OBJ_create");
    test_tables();
    test_asn1_method();
    test_legacy_keys();
    test_pkey_method();
    test_contexts();
    test_digest_sign();
    test_override();
    test_removed();
    EVP_PKEY_meth_free(pm);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
