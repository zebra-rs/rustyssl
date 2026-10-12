/*
 * Conformance test for signatures (EVP_SIGNATURE(3), EVP_PKEY_sign(3), EVP_DigestSignInit(3),
 * EVP_SignInit(3), EVP_PKEY_can_sign), in TAP format, over the default provider's MAC
 * signatures (HMAC, SIPHASH, POLY1305, CMAC): fetching and introspecting the algorithms,
 * signing through a digest context (digests by type, by name, and by default; updates in
 * pieces, finals that leave the context usable or finalize it, one-shot signing, copies,
 * restarting, and the redirects from EVP_DigestInit and EVP_DigestUpdate), the key context's
 * parameters during signing, the EVP_PKEY_sign family on keys whose algorithm can't sign that
 * way, application key contexts on digest contexts, and the errors.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
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

static void list(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" NULL");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static const char *str(const char *s)
{
    return s == NULL ? "(null)" : s;
}

static void name_cb(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static const unsigned char key20[20] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const unsigned char key16[17] = "0123456789abcdef";
static const unsigned char key32[33] = "0123456789abcdef0123456789ABCDEF";

/* Signature algorithms -------------------------------------------------------------------- */

static const char *const ours[] = { "HMAC", "SIPHASH", "POLY1305", "CMAC", NULL };

static void do_all_cb(EVP_SIGNATURE *sig, void *arg)
{
    int i;

    (void)arg;
    for (i = 0; ours[i] != NULL; i++)
        if (strcmp(EVP_SIGNATURE_get0_name(sig), ours[i]) == 0)
            printf(" %s", ours[i]);
}

static void test_methods(void)
{
    int i;
    EVP_SIGNATURE *sig;

    for (i = 0; ours[i] != NULL; i++) {
        char what[64];
        int r;

        sig = EVP_SIGNATURE_fetch(NULL, ours[i], NULL);
        snprintf(what, sizeof(what), "EVP_SIGNATURE_fetch %s", ours[i]);
        check(sig != NULL, what);
        if (sig == NULL) {
            errors();
            continue;
        }
        printf("  name %s desc %s prov %s is_a %d %d\n", EVP_SIGNATURE_get0_name(sig),
               str(EVP_SIGNATURE_get0_description(sig)),
               OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(sig)),
               EVP_SIGNATURE_is_a(sig, ours[i]), EVP_SIGNATURE_is_a(sig, "RSA"));
        printf("  names:");
        r = EVP_SIGNATURE_names_do_all(sig, name_cb, NULL);
        printf(" (%d)\n", r);
        list("gettable", EVP_SIGNATURE_gettable_ctx_params(sig));
        list("settable", EVP_SIGNATURE_settable_ctx_params(sig));
        printf("  up_ref %d\n", EVP_SIGNATURE_up_ref(sig));
        EVP_SIGNATURE_free(sig);
        EVP_SIGNATURE_free(sig);
    }
    sig = EVP_SIGNATURE_fetch(NULL, "NOPE", NULL);
    check(sig == NULL, "EVP_SIGNATURE_fetch of an unknown name fails");
    errors();
    sig = EVP_SIGNATURE_fetch(NULL, "HMAC", "provider=base");
    check(sig == NULL, "EVP_SIGNATURE_fetch from base fails");
    {
        /* The text names the algorithm's number, which every algorithm's names set. */
        const char *data = NULL;
        int flags = 0;

        ERR_peek_error_data(&data, &flags);
        printf("  data: %s\n", (flags & ERR_TXT_STRING) != 0 ? data : "(none)");
    }
    errors();
    printf("  do_all:");
    EVP_SIGNATURE_do_all_provided(NULL, do_all_cb, NULL);
    printf("\n");
    EVP_SIGNATURE_free(NULL);
    check(EVP_SIGNATURE_is_a(NULL, "HMAC") == 0, "EVP_SIGNATURE_is_a(NULL)");
}

/* Signing through a digest context -------------------------------------------------------- */

static void sign_final(const char *label, EVP_MD_CTX *md)
{
    unsigned char out[64];
    size_t len = 0;
    int r = EVP_DigestSignFinal(md, NULL, &len);

    printf("  %s: size %d %zu", label, r, len);
    len = sizeof(out);
    r = EVP_DigestSignFinal(md, out, &len);
    printf(" final %d", r);
    if (r == 1)
        hex("", out, len);
    else
        printf("\n");
}

static void test_digest_sign(void)
{
    EVP_PKEY *h = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key20, 20);
    EVP_PKEY *s = EVP_PKEY_new_raw_private_key(EVP_PKEY_SIPHASH, NULL, key16, 16);
    EVP_PKEY *p = EVP_PKEY_new_raw_private_key(EVP_PKEY_POLY1305, NULL, key32, 32);
    EVP_PKEY *c = EVP_PKEY_new_CMAC_key(NULL, key16, 16, EVP_aes_128_cbc());
    EVP_MD_CTX *md = EVP_MD_CTX_new(), *md2;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *got = NULL;
    unsigned char out[64];
    size_t len;
    OSSL_PARAM params[2];
    size_t size = 16;

    check(h != NULL && s != NULL && p != NULL && c != NULL, "keys");
    printf("  can_sign %d %d %d %d\n", EVP_PKEY_can_sign(h), EVP_PKEY_can_sign(s),
           EVP_PKEY_can_sign(p), EVP_PKEY_can_sign(c));

    /* HMAC-SHA256, RFC 4231 test case 1. */
    check(EVP_DigestSignInit(md, &pctx, EVP_sha256(), NULL, h) == 1, "EVP_DigestSignInit HMAC");
    printf("  pctx %d same %d op %d md %s prov %s\n", pctx != NULL,
           pctx == EVP_MD_CTX_get_pkey_ctx(md), EVP_PKEY_CTX_get_operation(pctx),
           EVP_MD_get0_name(EVP_MD_CTX_get0_md(md)),
           OSSL_PROVIDER_get0_name(EVP_PKEY_CTX_get0_provider(pctx)));
    list("ctx gettable", EVP_PKEY_CTX_gettable_params(pctx));
    list("ctx settable", EVP_PKEY_CTX_settable_params(pctx));
    list("md settable", EVP_MD_CTX_settable_params(md));
    list("md gettable", EVP_MD_CTX_gettable_params(md));
    params[0] = OSSL_PARAM_construct_end();
    printf("  ctx get_params %d md get_params %d md set_params %d\n",
           EVP_PKEY_CTX_get_params(pctx, params), EVP_MD_CTX_get_params(md, params),
           EVP_MD_CTX_set_params(md, params));
    printf("  get_signature_md %d %d\n", EVP_PKEY_CTX_get_signature_md(pctx, &got), got == NULL);
    errors();
    printf("  update %d %d\n", EVP_DigestSignUpdate(md, "Hi ", 3),
           EVP_DigestSignUpdate(md, "There", 5));
    sign_final("HMAC", md);
    sign_final("again", md);
    printf("  update after %d\n", EVP_DigestUpdate(md, "!", 1));
    sign_final("more", md);

    /* A copy signs on its own. */
    md2 = EVP_MD_CTX_new();
    check(EVP_MD_CTX_copy_ex(md2, md) == 1, "EVP_MD_CTX_copy_ex of a signing context");
    printf("  copy pctx %d differs %d\n", EVP_MD_CTX_get_pkey_ctx(md2) != NULL,
           EVP_MD_CTX_get_pkey_ctx(md2) != EVP_MD_CTX_get_pkey_ctx(md));
    EVP_DigestSignUpdate(md2, "?", 1);
    sign_final("copy", md2);
    sign_final("original", md);
    EVP_MD_CTX_free(md2);

    /* Restarting: by EVP_DigestSignInit without a key, and by EVP_DigestInit_ex. */
    check(EVP_DigestSignInit(md, NULL, NULL, NULL, NULL) == 1, "EVP_DigestSignInit again");
    printf("  md %s\n", str(EVP_MD_get0_name(EVP_MD_CTX_get0_md(md))));
    EVP_DigestSignUpdate(md, "Hi There", 8);
    sign_final("restarted", md);
    check(EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 1, "EVP_DigestInit_ex restarts signing");
    EVP_DigestUpdate(md, "Hi There", 8);
    sign_final("HMAC-SHA1", md);

    /* Finalizing for good. */
    EVP_MD_CTX_set_flags(md, EVP_MD_CTX_FLAG_FINALISE);
    check(EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, NULL) == 1, "restart with FINALISE");
    EVP_DigestSignUpdate(md, "Hi There", 8);
    sign_final("finalised", md);
    len = sizeof(out);
    printf("  final again %d update %d\n", EVP_DigestSignFinal(md, out, &len),
           EVP_DigestSignUpdate(md, "x", 1));
    errors();
    printf("  sign after %d\n", EVP_DigestSign(md, out, &len, (const unsigned char *)"x", 1));
    errors();
    EVP_MD_CTX_free(md);

    /* One shot, digests by name, and the default digest. */
    md = EVP_MD_CTX_new();
    check(EVP_DigestSignInit_ex(md, NULL, "SHA2-512", NULL, NULL, h, NULL) == 1,
          "EVP_DigestSignInit_ex SHA2-512");
    printf("  md %s\n", EVP_MD_get0_name(EVP_MD_CTX_get0_md(md)));
    len = 0;
    printf("  sign size %d %zu\n", EVP_DigestSign(md, NULL, &len, (const unsigned char *)"abc", 3),
           len);
    len = sizeof(out);
    printf("  sign %d\n", EVP_DigestSign(md, out, &len, (const unsigned char *)"abc", 3));
    hex("HMAC-SHA512", out, len);
    printf("  sign again %d\n", EVP_DigestSign(md, out, &len, (const unsigned char *)"abc", 3));
    errors();
    EVP_MD_CTX_free(md);

    md = EVP_MD_CTX_new();
    printf("  default digest %d\n", EVP_DigestSignInit_ex(md, NULL, NULL, NULL, NULL, h, NULL));
    errors();
    printf("  unknown digest %d\n", EVP_DigestSignInit_ex(md, NULL, "NOPE", NULL, NULL, h, NULL));
    errors();
    printf("  props %d\n",
           EVP_DigestSignInit_ex(md, NULL, "SHA256", NULL, "provider=default", h, NULL));
    printf("  base props %d\n",
           EVP_DigestSignInit_ex(md, NULL, "SHA256", NULL, "provider=base", h, NULL));
    errors();
    EVP_MD_CTX_free(md);

    /* SipHash, with its parameters through the key context. */
    md = EVP_MD_CTX_new();
    pctx = NULL;
    check(EVP_DigestSignInit(md, &pctx, NULL, NULL, s) == 1, "EVP_DigestSignInit SIPHASH");
    printf("  md %d\n", EVP_MD_CTX_get0_md(md) == NULL);
    EVP_DigestSignUpdate(md, "abc", 3);
    sign_final("SIPHASH", md);
    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    printf("  set size %d\n", EVP_PKEY_CTX_set_params(pctx, params));
    sign_final("SIPHASH-128", md);
    printf("  set_signature_md %d\n", EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256()));
    errors();
    EVP_MD_CTX_free(md);

    /* Poly1305 and CMAC. */
    md = EVP_MD_CTX_new();
    check(EVP_DigestSignInit(md, NULL, NULL, NULL, p) == 1, "EVP_DigestSignInit POLY1305");
    EVP_DigestSignUpdate(md, "abc", 3);
    sign_final("POLY1305", md);
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    check(EVP_DigestSignInit(md, NULL, NULL, NULL, c) == 1, "EVP_DigestSignInit CMAC");
    EVP_DigestSignUpdate(md, "abc", 3);
    sign_final("CMAC", md);
    EVP_MD_CTX_free(md);

    printf("  supports %d %d %d\n", EVP_PKEY_digestsign_supports_digest(h, NULL, "SHA256", NULL),
           EVP_PKEY_digestsign_supports_digest(h, NULL, "NOPE", NULL),
           EVP_PKEY_digestsign_supports_digest(s, NULL, NULL, NULL));
    errors();

    /* MAC signatures don't verify. */
    md = EVP_MD_CTX_new();
    printf("  verify init %d\n", EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, h));
    errors();
    printf("  verify %d\n", EVP_DigestVerify(md, out, 32, (const unsigned char *)"x", 1));
    errors();
    printf("  verify final %d\n", EVP_DigestVerifyFinal(md, out, 32));
    errors();
    EVP_MD_CTX_free(md);
    /*
     * By digest name: the context is left with the digest but no digest state, which the
     * reference then crashes on if given data; it's only freed.
     */
    md = EVP_MD_CTX_new();
    printf("  verify init_ex %d\n",
           EVP_DigestVerifyInit_ex(md, NULL, "SHA256", NULL, NULL, h, NULL));
    errors();
    EVP_MD_CTX_free(md);

    /* A plain digest context. */
    md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), NULL);
    printf("  plain verify update %d\n", EVP_DigestVerifyUpdate(md, "abc", 3));
    printf("  plain update %d final %d\n", EVP_DigestSignUpdate(md, "abc", 3),
           EVP_DigestSignFinal(md, out, &len));
    errors();
    printf("  plain sign %d\n", EVP_DigestSign(md, out, &len, (const unsigned char *)"x", 1));
    errors();
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    printf("  no context sign %d verify %d\n",
           EVP_DigestSign(md, out, &len, (const unsigned char *)"x", 1),
           EVP_DigestVerify(md, out, 32, (const unsigned char *)"x", 1));
    errors();

    /* A blank key, and a key without a private key. */
    {
        EVP_PKEY *b = EVP_PKEY_new(), *pg = NULL;
        EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(NULL, "SIPHASH", NULL);

        printf("  blank %d\n", EVP_DigestSignInit(md, NULL, NULL, NULL, b));
        errors();
        EVP_PKEY_free(b);
        EVP_PKEY_paramgen_init(g);
        EVP_PKEY_paramgen(g, &pg);
        EVP_PKEY_CTX_free(g);
        EVP_MD_CTX_free(md);
        md = EVP_MD_CTX_new();
        printf("  keyless %d\n", EVP_DigestSignInit(md, NULL, NULL, NULL, pg));
        errors();
        EVP_PKEY_free(pg);
    }
    EVP_MD_CTX_free(md);

    EVP_PKEY_free(h);
    EVP_PKEY_free(s);
    EVP_PKEY_free(p);
    EVP_PKEY_free(c);
}

/* The EVP_PKEY_sign family ---------------------------------------------------------------- */

static void test_pkey_sign(void)
{
    EVP_PKEY *h = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key20, 20);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(h, NULL), *d;
    EVP_SIGNATURE *hmac = EVP_SIGNATURE_fetch(NULL, "HMAC", NULL);
    EVP_SIGNATURE *sip = EVP_SIGNATURE_fetch(NULL, "SIPHASH", NULL);
    unsigned char out[64];
    size_t len = sizeof(out);
    const EVP_MD *got = NULL;

    printf("  sign uninit %d\n", EVP_PKEY_sign(ctx, out, &len, key16, 16));
    errors();
    printf("  verify uninit %d recover %d\n", EVP_PKEY_verify(ctx, out, 16, key16, 16),
           EVP_PKEY_verify_recover(ctx, out, &len, key16, 16));
    errors();
    printf("  message uninit %d %d %d %d\n", EVP_PKEY_sign_message_update(ctx, key16, 1),
           EVP_PKEY_sign_message_final(ctx, out, &len),
           EVP_PKEY_verify_message_update(ctx, key16, 1), EVP_PKEY_verify_message_final(ctx));
    errors();
    printf("  set_signature undef %d\n", EVP_PKEY_CTX_set_signature(ctx, key16, 16));
    errors();
    printf("  signature_md undef %d %d\n", EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()),
           EVP_PKEY_CTX_get_signature_md(ctx, &got));
    errors();

    printf("  sign_init %d op %d\n", EVP_PKEY_sign_init(ctx), EVP_PKEY_CTX_get_operation(ctx));
    errors();
    printf("  sign_init_ex %d\n", EVP_PKEY_sign_init_ex(ctx, NULL));
    errors();
    printf("  verify_init %d\n", EVP_PKEY_verify_init(ctx));
    errors();
    printf("  verify_init_ex %d\n", EVP_PKEY_verify_init_ex(ctx, NULL));
    errors();
    printf("  verify_recover_init %d %d\n", EVP_PKEY_verify_recover_init(ctx),
           EVP_PKEY_verify_recover_init_ex(ctx, NULL));
    errors();
    printf("  sign_message_init %d verify_message_init %d\n",
           EVP_PKEY_sign_message_init(ctx, NULL, NULL),
           EVP_PKEY_verify_message_init(ctx, NULL, NULL));
    errors();
    printf("  ex2 %d %d %d\n", EVP_PKEY_sign_init_ex2(ctx, hmac, NULL),
           EVP_PKEY_verify_init_ex2(ctx, hmac, NULL),
           EVP_PKEY_verify_recover_init_ex2(ctx, hmac, NULL));
    errors();

    /* An algorithm of another key type: the operation stays, without an algorithm. */
    printf("  incompatible %d op %d\n", EVP_PKEY_sign_init_ex2(ctx, sip, NULL),
           EVP_PKEY_CTX_get_operation(ctx));
    errors();
    printf("  sign %d\n", EVP_PKEY_sign(ctx, out, &len, key16, 16));
    errors();
    printf("  signature_md %d %d\n", EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()),
           EVP_PKEY_CTX_get_signature_md(ctx, &got));
    errors();
    printf("  provider %d\n", EVP_PKEY_CTX_get0_provider(ctx) == NULL);
    d = EVP_PKEY_CTX_dup(ctx);
    printf("  dup %d\n", d == NULL);
    EVP_PKEY_CTX_free(d);
    printf("  verify incompatible %d op %d\n", EVP_PKEY_verify_init_ex2(ctx, sip, NULL),
           EVP_PKEY_CTX_get_operation(ctx));
    errors();
    printf("  verify %d\n", EVP_PKEY_verify(ctx, out, 16, key16, 16));
    errors();
    printf("  recover incompatible %d\n", EVP_PKEY_verify_recover_init_ex2(ctx, sip, NULL));
    errors();
    printf("  recover %d\n", EVP_PKEY_verify_recover(ctx, out, &len, key16, 16));
    errors();
    EVP_PKEY_CTX_free(ctx);

    /* Without a key. */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "HMAC", NULL);
    printf("  no key %d %d\n", EVP_PKEY_sign_init(ctx), EVP_PKEY_sign_init_ex2(ctx, hmac, NULL));
    errors();
    EVP_PKEY_CTX_free(ctx);
    printf("  NULL %d %d %d\n", EVP_PKEY_sign_init(NULL), EVP_PKEY_sign(NULL, out, &len, key16, 1),
           EVP_PKEY_CTX_set_signature(NULL, key16, 1));
    errors();

    /* EVP_SignFinal and EVP_VerifyFinal. */
    {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        unsigned int slen = 99;

        EVP_SignInit(md, EVP_sha256());
        EVP_SignUpdate(md, "abc", 3);
        printf("  SignFinal %d %u\n", EVP_SignFinal(md, out, &slen, h), slen);
        errors();
        printf("  SignFinal_ex %d\n", EVP_SignFinal_ex(md, out, &slen, h, NULL, "provider=default"));
        errors();
        EVP_VerifyInit(md, EVP_sha256());
        EVP_VerifyUpdate(md, "abc", 3);
        printf("  VerifyFinal %d\n", EVP_VerifyFinal(md, out, 32, h));
        errors();
        printf("  VerifyFinal_ex %d\n", EVP_VerifyFinal_ex(md, out, 32, h, NULL, NULL));
        errors();
        EVP_MD_CTX_set_flags(md, EVP_MD_CTX_FLAG_FINALISE);
        printf("  VerifyFinal finalised %d\n", EVP_VerifyFinal(md, out, 32, h));
        errors();
        printf("  VerifyFinal again %d\n", EVP_VerifyFinal(md, out, 32, h));
        errors();
        EVP_MD_CTX_free(md);
    }

    /* Typed keys. */
    {
        EVP_PKEY *t = EVP_PKEY_new();

        printf("  can_sign blank %d", EVP_PKEY_can_sign(t));
        EVP_PKEY_set_type(t, EVP_PKEY_RSA);
        printf(" RSA %d", EVP_PKEY_can_sign(t));
        EVP_PKEY_set_type(t, EVP_PKEY_DH);
        printf(" DH %d", EVP_PKEY_can_sign(t));
        EVP_PKEY_set_type(t, EVP_PKEY_ED25519);
        printf(" ED25519 %d\n", EVP_PKEY_can_sign(t));
        EVP_PKEY_free(t);
    }

    EVP_SIGNATURE_free(hmac);
    EVP_SIGNATURE_free(sip);
    EVP_PKEY_free(h);
}

/* Application key contexts on digest contexts --------------------------------------------- */

static void test_pkey_ctx_on_md(void)
{
    EVP_PKEY *h = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key20, 20);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, h, NULL);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char out[64];
    unsigned int n = 0;

    EVP_MD_CTX_set_pkey_ctx(md, pctx);
    printf("  set %d keep %d\n", EVP_MD_CTX_get_pkey_ctx(md) == pctx,
           EVP_MD_CTX_test_flags(md, 0x0400) != 0);
    printf("  digest %d", EVP_DigestInit_ex(md, EVP_sha256(), NULL));
    printf(" %d", EVP_DigestUpdate(md, "abc", 3));
    printf(" %d\n", EVP_DigestFinal_ex(md, out, &n));
    hex("sha256", out, n);
    check(EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, NULL) == 1,
          "EVP_DigestSignInit with the application's key context");
    printf("  op %d\n", EVP_PKEY_CTX_get_operation(pctx));
    EVP_DigestSignUpdate(md, "Hi There", 8);
    sign_final("app pctx", md);
    EVP_MD_CTX_free(md);
    printf("  pctx kept op %d\n", EVP_PKEY_CTX_get_operation(pctx));

    /* A legacy digest init tells the key context, which has no operation. */
    md = EVP_MD_CTX_new();
    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, h, NULL);
    EVP_MD_CTX_set_pkey_ctx(md, pctx);
    EVP_MD_CTX_set_flags(md, EVP_MD_CTX_FLAG_NO_INIT);
    printf("  no_init %d\n", EVP_DigestInit_ex(md, EVP_sha256(), NULL));
    errors();
    EVP_PKEY_keygen_init(pctx);
    printf("  no_init keygen %d\n", EVP_DigestInit_ex(md, EVP_sha256(), NULL));
    errors();
    EVP_MD_CTX_set_pkey_ctx(md, NULL);
    printf("  cleared %d keep %d\n", EVP_MD_CTX_get_pkey_ctx(md) == NULL,
           EVP_MD_CTX_test_flags(md, 0x0400) != 0);
    EVP_MD_CTX_free(md);
    EVP_PKEY_CTX_free(pctx);

    /* A digest context's own key context, replaced. */
    md = EVP_MD_CTX_new();
    EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, h);
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, h, NULL);
    EVP_MD_CTX_set_pkey_ctx(md, pctx);
    printf("  replaced %d\n", EVP_MD_CTX_get_pkey_ctx(md) == pctx);
    EVP_MD_CTX_free(md);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(h);
    check(1, "key contexts on digest contexts");
}

/* The numbers names get, which fetch errors print: the name map's first use pre-fills it with
 * the legacy ciphers' and digests' names, and providers' tables add theirs in order. */
static void fetch_text(const char *label)
{
    const char *data = NULL;
    int flags = 0;

    ERR_peek_error_data(&data, &flags);
    printf("  %s: %s\n", label, (flags & ERR_TXT_STRING) != 0 ? data : "(none)");
    ERR_clear_error();
}

static void test_numbers(void)
{
    EVP_CIPHER_free(EVP_CIPHER_fetch(NULL, "RC4", NULL));
    fetch_text("RC4");
    EVP_CIPHER_free(EVP_CIPHER_fetch(NULL, "CAMELLIA-256-CFB1", "provider=base"));
    fetch_text("CAMELLIA-256-CFB1");
    EVP_CIPHER_free(EVP_CIPHER_fetch(NULL, "ChaCha20", "provider=base"));
    fetch_text("ChaCha20");
    check(1, "name numbers");
}

int main(void)
{
    test_numbers();
    test_methods();
    test_digest_sign();
    test_pkey_sign();
    test_pkey_ctx_on_md();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
