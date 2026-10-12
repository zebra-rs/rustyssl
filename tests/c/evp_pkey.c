/*
 * Conformance test for keys and key management (EVP_KEYMGMT(3), EVP_PKEY_new(3),
 * EVP_PKEY_fromdata(3), EVP_PKEY_keygen(3), EVP_PKEY_check(3), ...), in TAP format, over the
 * key types the default provider manages for MACs and KDFs (HMAC, SIPHASH, POLY1305, CMAC,
 * HKDF, TLS1-PRF, SCRYPT): fetching and introspecting key managers, blank and typed keys and
 * the ASN.1 methods' type table, raw keys, parameters, export, comparison and copies, key
 * contexts by id, name, and key, generation (with its quirks), making keys from parameters,
 * the checks, application data, and the errors.
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
        printf(" %s/%u/%zu", p->key, p->data_type, p->data_size);
    printf("\n");
}

static void show_param_values(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" NULL");
    for (; p != NULL && p->key != NULL; p++) {
        printf(" %s=", p->key);
        if (p->data_type == OSSL_PARAM_OCTET_STRING) {
            const unsigned char *d = p->data;
            size_t i;

            for (i = 0; i < p->data_size; i++)
                printf("%02x", d[i]);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            printf("%s", (const char *)p->data);
        } else {
            printf("?%u", p->data_type);
        }
    }
    printf("\n");
}

static void name_cb(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static void names(const char *label, const EVP_KEYMGMT *km)
{
    int r;

    printf("  %s:", label);
    r = EVP_KEYMGMT_names_do_all(km, name_cb, NULL);
    printf(" (%d)\n", r);
}

static void type_names(const char *label, const EVP_PKEY *k)
{
    int r;

    printf("  %s:", label);
    r = EVP_PKEY_type_names_do_all(k, name_cb, NULL);
    printf(" (%d)\n", r);
}

static const char *str(const char *s)
{
    return s == NULL ? "(null)" : s;
}

static void describe(const char *label, const EVP_PKEY *k)
{
    const OSSL_PROVIDER *prov = EVP_PKEY_get0_provider(k);

    printf("  %s: id %d base %d name %s desc %s prov %s\n", label,
           EVP_PKEY_get_id(k), EVP_PKEY_get_base_id(k),
           str(EVP_PKEY_get0_type_name(k)), str(EVP_PKEY_get0_description(k)),
           prov == NULL ? "(null)" : OSSL_PROVIDER_get0_name(prov));
}

static void sizes(const char *label, const EVP_PKEY *k)
{
    int b = EVP_PKEY_get_bits(k), s = EVP_PKEY_get_security_bits(k);
    int z = EVP_PKEY_get_size(k);

    printf("  %s: bits %d security %d size %d\n", label, b, s, z);
    errors();
}

static void raw_priv(const char *label, const EVP_PKEY *k)
{
    unsigned char buf[64];
    size_t len = sizeof(buf);
    int r = EVP_PKEY_get_raw_private_key(k, buf, &len);

    printf("  %s: %d", label, r);
    if (r == 1)
        hex("", buf, len);
    else
        printf("\n");
}

/* Key managers --------------------------------------------------------------------------- */

static void keymgmt_one(const char *name)
{
    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, name, NULL);
    char what[96];

    snprintf(what, sizeof(what), "EVP_KEYMGMT_fetch %s", name);
    check(km != NULL, what);
    if (km == NULL) {
        errors();
        return;
    }
    printf("  name %s desc %s prov %s\n", EVP_KEYMGMT_get0_name(km),
           str(EVP_KEYMGMT_get0_description(km)),
           OSSL_PROVIDER_get0_name(EVP_KEYMGMT_get0_provider(km)));
    printf("  is_a self %d lower %d other %d null %d\n",
           EVP_KEYMGMT_is_a(km, name), EVP_KEYMGMT_is_a(km, "hmac"),
           EVP_KEYMGMT_is_a(km, "RSA"), EVP_KEYMGMT_is_a(NULL, name));
    names("names", km);
    list("gettable", EVP_KEYMGMT_gettable_params(km));
    list("settable", EVP_KEYMGMT_settable_params(km));
    list("gen_settable", EVP_KEYMGMT_gen_settable_params(km));
    list("gen_gettable", EVP_KEYMGMT_gen_gettable_params(km));
    printf("  up_ref %d\n", EVP_KEYMGMT_up_ref(km));
    EVP_KEYMGMT_free(km);
    EVP_KEYMGMT_free(km);
}

static const char *const ours[] = {
    "TLS1-PRF", "HKDF", "SCRYPT", "HMAC", "SIPHASH", "POLY1305", "CMAC", NULL
};

static void do_all_cb(EVP_KEYMGMT *km, void *arg)
{
    int i;

    (void)arg;
    for (i = 0; ours[i] != NULL; i++)
        if (strcmp(EVP_KEYMGMT_get0_name(km), ours[i]) == 0)
            printf(" %s", ours[i]);
}

static void test_keymgmt(void)
{
    EVP_KEYMGMT *km;

    keymgmt_one("HMAC");
    keymgmt_one("SIPHASH");
    keymgmt_one("POLY1305");
    keymgmt_one("CMAC");
    keymgmt_one("HKDF");
    keymgmt_one("TLS1-PRF");
    keymgmt_one("SCRYPT");
    keymgmt_one("id-scrypt");
    keymgmt_one("1.3.6.1.4.1.11591.4.11");

    km = EVP_KEYMGMT_fetch(NULL, "NOPE", NULL);
    check(km == NULL, "EVP_KEYMGMT_fetch of an unknown name fails");
    errors();
    km = EVP_KEYMGMT_fetch(NULL, "HMAC", "provider=base");
    check(km == NULL, "EVP_KEYMGMT_fetch from base fails");
    errors();
    km = EVP_KEYMGMT_fetch(NULL, "HMAC", "provider=default");
    check(km != NULL, "EVP_KEYMGMT_fetch with properties");
    EVP_KEYMGMT_free(km);

    printf("  do_all:");
    EVP_KEYMGMT_do_all_provided(NULL, do_all_cb, NULL);
    printf("\n");
    check(1, "EVP_KEYMGMT_do_all_provided");

    EVP_KEYMGMT_free(NULL);
    check(1, "EVP_KEYMGMT_free(NULL)");
}

/* Types ---------------------------------------------------------------------------------- */

static void test_types(void)
{
    static const int ids[] = {
        EVP_PKEY_RSA, EVP_PKEY_RSA2, EVP_PKEY_RSA_PSS, EVP_PKEY_DSA, EVP_PKEY_DSA1,
        EVP_PKEY_DSA2, EVP_PKEY_DSA3, EVP_PKEY_DSA4, EVP_PKEY_DH, EVP_PKEY_DHX, EVP_PKEY_EC,
        EVP_PKEY_SM2, EVP_PKEY_X25519, EVP_PKEY_X448, EVP_PKEY_ED25519, EVP_PKEY_ED448,
        EVP_PKEY_HMAC, EVP_PKEY_CMAC, EVP_PKEY_SIPHASH, EVP_PKEY_POLY1305, EVP_PKEY_HKDF,
        EVP_PKEY_TLS1_PRF, EVP_PKEY_SCRYPT, EVP_PKEY_NONE, -1, 99999
    };
    size_t i;

    printf("  EVP_PKEY_type:");
    for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++)
        printf(" %d->%d", ids[i], EVP_PKEY_type(ids[i]));
    printf("\n");
    check(EVP_PKEY_type(EVP_PKEY_RSA2) == EVP_PKEY_RSA, "EVP_PKEY_type follows aliases");
}

/* Blank and typed keys ------------------------------------------------------------------- */

static int ex_index = -1;

static void ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl,
                    void *argp)
{
    (void)parent;
    (void)ad;
    (void)argl;
    (void)argp;
    if (idx == ex_index && ptr != NULL)
        printf("  ex_free %s\n", (const char *)ptr);
}

static int ex_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from, void **from_d, int idx,
                  long argl, void *argp)
{
    (void)to;
    (void)from;
    (void)argl;
    (void)argp;
    printf("  ex_dup %d %s\n", idx == ex_index, *from_d == NULL ? "(null)" : (char *)*from_d);
    *from_d = "duplicated";
    return 1;
}

static void test_blank(void)
{
    EVP_PKEY *k = EVP_PKEY_new();
    EVP_PKEY *t;
    char buf[32];

    check(k != NULL, "EVP_PKEY_new");
    describe("blank", k);
    sizes("blank", k);
    type_names("blank names", k);
    printf("  is_a RSA %d foo %d\n", EVP_PKEY_is_a(k, "RSA"), EVP_PKEY_is_a(k, "foo"));
    printf("  missing %d get0 %d engine %d set1_engine %d\n",
           EVP_PKEY_missing_parameters(k), EVP_PKEY_get0(k) == NULL,
           EVP_PKEY_get0_engine(k) == NULL, EVP_PKEY_set1_engine(k, NULL));
    printf("  save_parameters %d\n", EVP_PKEY_save_parameters(k, 0));
    printf("  get_params %d\n", EVP_PKEY_get_int_param(k, "bits", NULL));
    errors();
    printf("  set_params %d\n", EVP_PKEY_set_int_param(k, "bits", 1));
    errors();
    list("gettable", EVP_PKEY_gettable_params(k));
    list("settable", EVP_PKEY_settable_params(k));
    printf("  set1_encoded %d get1_encoded %zu\n",
           EVP_PKEY_set1_encoded_public_key(k, (const unsigned char *)"x", 1),
           EVP_PKEY_get1_encoded_public_key(k, NULL));
    errors();
    printf("  raw priv %d\n", EVP_PKEY_get_raw_private_key(k, NULL, NULL));
    errors();
    printf("  group %d\n", EVP_PKEY_get_group_name(k, buf, sizeof(buf), NULL));
    errors();

    printf("  up_ref %d\n", EVP_PKEY_up_ref(k));
    EVP_PKEY_free(k);

    /* Application data, and its copy. */
    ex_index = EVP_PKEY_get_ex_new_index(0, NULL, NULL, ex_dup, ex_free);
    check(ex_index > 0, "EVP_PKEY_get_ex_new_index");
    check(EVP_PKEY_set_ex_data(k, ex_index, "data") == 1, "EVP_PKEY_set_ex_data");
    check(strcmp(EVP_PKEY_get_ex_data(k, ex_index), "data") == 0, "EVP_PKEY_get_ex_data");
    t = EVP_PKEY_dup(k);
    check(t != NULL, "EVP_PKEY_dup of a blank key");
    describe("dup", t);
    printf("  dup ex_data %s\n", str(EVP_PKEY_get_ex_data(t, ex_index)));
    printf("  eq blank blank %d\n", EVP_PKEY_eq(k, t));
    errors();
    EVP_PKEY_free(t);
    EVP_PKEY_free(k);

    printf("  eq NULL NULL %d\n", EVP_PKEY_eq(NULL, NULL));
    EVP_PKEY_free(NULL);
    check(1, "EVP_PKEY_free(NULL)");
}

static void test_typed(void)
{
    EVP_PKEY *k = EVP_PKEY_new();

    check(EVP_PKEY_set_type(k, EVP_PKEY_RSA) == 1, "EVP_PKEY_set_type RSA");
    describe("RSA", k);
    type_names("RSA names", k);
    printf("  is_a RSA %d rsaEncryption %d EC %d\n", EVP_PKEY_is_a(k, "RSA"),
           EVP_PKEY_is_a(k, "rsaEncryption"), EVP_PKEY_is_a(k, "EC"));
    /* RSA's ASN.1 method has no raw keys and no parameters. */
    printf("  raw priv %d missing %d\n", EVP_PKEY_get_raw_private_key(k, NULL, NULL),
           EVP_PKEY_missing_parameters(k));
    errors();
    check(EVP_PKEY_set_type(k, EVP_PKEY_HMAC) == 0, "EVP_PKEY_set_type HMAC fails");
    errors();
    describe("after", k);
    check(EVP_PKEY_set_type(k, EVP_PKEY_RSA2) == 1, "EVP_PKEY_set_type RSA2");
    describe("RSA2", k);
    check(EVP_PKEY_set_type(k, EVP_PKEY_EC) == 1, "EVP_PKEY_set_type EC");
    printf("  save_parameters %d %d %d %d\n", EVP_PKEY_save_parameters(k, 0),
           EVP_PKEY_save_parameters(k, -1), EVP_PKEY_save_parameters(k, 5),
           EVP_PKEY_save_parameters(k, -1));
    check(EVP_PKEY_set_type(k, EVP_PKEY_SM2) == 1, "EVP_PKEY_set_type SM2");
    describe("SM2", k);
    printf("  is_a SM2 %d EC %d sm2 %d\n", EVP_PKEY_is_a(k, "SM2"), EVP_PKEY_is_a(k, "EC"),
           EVP_PKEY_is_a(k, "sm2"));
    type_names("SM2 names", k);
    check(EVP_PKEY_set_type(k, 0) == 0, "EVP_PKEY_set_type NONE fails");
    errors();
    check(EVP_PKEY_set_type(k, EVP_PKEY_DSA3) == 0, "EVP_PKEY_set_type of a broken alias fails");
    errors();

    check(EVP_PKEY_set_type_str(k, "x9.42 dh", -1) == 1, "EVP_PKEY_set_type_str x9.42 dh");
    describe("DHX", k);
    /* Once typed by name, a key keeps its type when typed by name again. */
    check(EVP_PKEY_set_type_str(k, "RSAxx", 3) == 1, "EVP_PKEY_set_type_str RSA/3");
    describe("still", k);
    check(EVP_PKEY_set_type(k, EVP_PKEY_ED448) == 1, "EVP_PKEY_set_type ED448");
    check(EVP_PKEY_set_type_str(k, "rsaxx", 3) == 1, "EVP_PKEY_set_type_str rsa/3");
    describe("RSA by name", k);
    check(EVP_PKEY_set_type_str(k, "nope", -1) == 1, "EVP_PKEY_set_type_str after a name");
    errors();
    EVP_PKEY_free(k);

    k = EVP_PKEY_new();
    check(EVP_PKEY_set_type_str(k, "nope", -1) == 0, "EVP_PKEY_set_type_str unknown fails");
    errors();
    check(EVP_PKEY_set_type_str(k, "DH", 1) == 0, "EVP_PKEY_set_type_str D/1 fails");
    errors();
    check(EVP_PKEY_set_type_str(k, "DH", 2) == 1, "EVP_PKEY_set_type_str DH/2");
    describe("DH", k);
    check(EVP_PKEY_set_type_str(k, "DHX", -1) == 1, "EVP_PKEY_set_type_str DHX keeps DH");
    describe("DHX", k);
    EVP_PKEY_free(k);
}

/* Raw MAC keys --------------------------------------------------------------------------- */

static const unsigned char key16[17] = "0123456789abcdef";
static const unsigned char key32[33] = "0123456789abcdef0123456789ABCDEF";

static void test_raw(void)
{
    EVP_PKEY *h, *h2, *h15, *s, *p, *d, *e, *x;
    unsigned char buf[64];
    size_t len;
    char md[80];
    int nid = 7;

    h = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key16, 16);
    check(h != NULL, "EVP_PKEY_new_raw_private_key HMAC");
    describe("HMAC", h);
    sizes("HMAC", h);
    type_names("HMAC names", h);
    printf("  is_a HMAC %d hmac %d SIPHASH %d\n", EVP_PKEY_is_a(h, "HMAC"),
           EVP_PKEY_is_a(h, "hmac"), EVP_PKEY_is_a(h, "SIPHASH"));
    raw_priv("raw", h);
    len = 0;
    printf("  raw size %d %zu\n", EVP_PKEY_get_raw_private_key(h, NULL, &len), len);
    len = 3;
    printf("  raw short %d %zu\n", EVP_PKEY_get_raw_private_key(h, buf, &len), len);
    errors();
    len = sizeof(buf);
    printf("  raw pub %d %zu\n", EVP_PKEY_get_raw_public_key(h, buf, &len), len);
    errors();
    printf("  get0_siphash %d\n", EVP_PKEY_get0_siphash(h, &len) == NULL);
    errors();
    printf("  get0_hmac %d\n", EVP_PKEY_get0_hmac(h, &len) == NULL);
    errors();
    printf("  get0_poly1305 %d\n", EVP_PKEY_get0_poly1305(h, &len) == NULL);
    errors();
    printf("  missing %d\n", EVP_PKEY_missing_parameters(h));
    printf("  default digest %d nid %d %d\n", EVP_PKEY_get_default_digest_name(h, md, sizeof(md)),
           EVP_PKEY_get_default_digest_nid(h, &nid), nid);
    errors();

    h2 = EVP_PKEY_new_raw_private_key_ex(NULL, "HMAC", NULL, key16, 16);
    h15 = EVP_PKEY_new_raw_private_key_ex(NULL, "hmac", "provider=default", key16, 15);
    s = EVP_PKEY_new_raw_private_key_ex(NULL, "SIPHASH", NULL, key16, 16);
    p = EVP_PKEY_new_raw_private_key(EVP_PKEY_POLY1305, NULL, key32, 32);
    check(h2 != NULL && h15 != NULL && s != NULL && p != NULL, "more raw keys");
    describe("SIPHASH", s);
    describe("POLY1305", p);
    printf("  eq same %d shorter %d types %d\n", EVP_PKEY_eq(h, h2), EVP_PKEY_eq(h, h15),
           EVP_PKEY_eq(h, s));
    errors();
    printf("  cmp %d %d\n", EVP_PKEY_cmp(h, h2), EVP_PKEY_cmp(h, h15));
    printf("  parameters_eq %d %d types %d\n", EVP_PKEY_parameters_eq(h, h2),
           EVP_PKEY_parameters_eq(h, h15), EVP_PKEY_parameters_eq(h, p));
    errors();
    printf("  cmp_parameters %d\n", EVP_PKEY_cmp_parameters(h, h15));
    printf("  eq NULL %d %d self %d\n", EVP_PKEY_eq(h, NULL), EVP_PKEY_eq(NULL, h),
           EVP_PKEY_eq(h, h));

    e = EVP_PKEY_new();
    printf("  eq blank %d %d\n", EVP_PKEY_eq(h, e), EVP_PKEY_eq(e, h));
    errors();
    EVP_PKEY_set_type(e, EVP_PKEY_RSA);
    printf("  eq typed %d %d\n", EVP_PKEY_eq(h, e), EVP_PKEY_parameters_eq(e, h));
    errors();
    EVP_PKEY_free(e);

    d = EVP_PKEY_dup(h);
    check(d != NULL, "EVP_PKEY_dup of an HMAC key");
    describe("dup", d);
    printf("  dup eq %d\n", EVP_PKEY_eq(h, d));
    raw_priv("dup raw", d);

    e = EVP_PKEY_new();
    printf("  copy_parameters %d\n", EVP_PKEY_copy_parameters(e, h));
    errors();
    describe("copied into", e);
    printf("  copy_parameters again %d\n", EVP_PKEY_copy_parameters(e, h));
    errors();
    printf("  copy_parameters other %d\n", EVP_PKEY_copy_parameters(e, s));
    errors();
    printf("  copy_parameters to key %d\n", EVP_PKEY_copy_parameters(h2, h));
    errors();
    EVP_PKEY_free(e);

    x = EVP_PKEY_new_raw_public_key(EVP_PKEY_HMAC, NULL, key16, 16);
    check(x == NULL, "EVP_PKEY_new_raw_public_key HMAC fails");
    errors();
    x = EVP_PKEY_new_raw_public_key_ex(NULL, "SIPHASH", NULL, key16, 16);
    check(x == NULL, "EVP_PKEY_new_raw_public_key_ex SIPHASH fails");
    errors();
    x = EVP_PKEY_new_raw_private_key_ex(NULL, "HKDF", NULL, key16, 16);
    check(x == NULL, "EVP_PKEY_new_raw_private_key_ex HKDF fails");
    errors();
    x = EVP_PKEY_new_raw_private_key(99999, NULL, key16, 16);
    check(x == NULL, "EVP_PKEY_new_raw_private_key of an unknown type fails");
    errors();
    x = EVP_PKEY_new_raw_private_key_ex(NULL, "NOPE", NULL, key16, 16);
    check(x == NULL, "EVP_PKEY_new_raw_private_key_ex of an unknown name fails");
    errors();
    x = EVP_PKEY_new_raw_private_key_ex(NULL, "HMAC", "provider=base", key16, 16);
    check(x == NULL, "EVP_PKEY_new_raw_private_key_ex from base fails");
    errors();
    x = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key16, 0);
    check(x != NULL, "an empty HMAC key");
    raw_priv("empty", x);
    EVP_PKEY_free(x);

    EVP_PKEY_free(h);
    EVP_PKEY_free(h2);
    EVP_PKEY_free(h15);
    EVP_PKEY_free(s);
    EVP_PKEY_free(p);
    EVP_PKEY_free(d);
}

/* Parameters and export ------------------------------------------------------------------ */

static int export_cb(const OSSL_PARAM params[], void *arg)
{
    show_param_values((const char *)arg, params);
    return 1;
}

static int refuse_cb(const OSSL_PARAM params[], void *arg)
{
    (void)params;
    (void)arg;
    return 0;
}

static void test_params(void)
{
    EVP_PKEY *h = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key16, 16);
    EVP_PKEY *c = EVP_PKEY_new_CMAC_key(NULL, key16, 16, EVP_aes_128_cbc());
    EVP_PKEY *c2;
    OSSL_PARAM *out = NULL;
    OSSL_PARAM params[3];
    unsigned char buf[64];
    char name[64];
    size_t len = 0, sz = 0;
    int i = 0;
    BIGNUM *bn = NULL;

    check(h != NULL && c != NULL, "keys for parameters");
    list("HMAC gettable", EVP_PKEY_gettable_params(h));
    list("HMAC settable", EVP_PKEY_settable_params(h));
    list("CMAC gettable", EVP_PKEY_gettable_params(c));
    describe("CMAC", c);
    sizes("CMAC", c);

    printf("  octet size %d %zu\n",
           EVP_PKEY_get_octet_string_param(h, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &len), len);
    printf("  octet %d %zu\n",
           EVP_PKEY_get_octet_string_param(h, OSSL_PKEY_PARAM_PRIV_KEY, buf, sizeof(buf), &len),
           len);
    hex("priv", buf, len);
    printf("  octet short %d\n",
           EVP_PKEY_get_octet_string_param(h, OSSL_PKEY_PARAM_PRIV_KEY, buf, 4, &len));
    errors();
    printf("  utf8 cipher %d", EVP_PKEY_get_utf8_string_param(c, OSSL_PKEY_PARAM_CIPHER, name,
                                                               sizeof(name), &len));
    printf(" %s %zu\n", name, len);
    printf("  utf8 exact %d %zu\n",
           EVP_PKEY_get_utf8_string_param(c, OSSL_PKEY_PARAM_CIPHER, name, 11, &len), len);
    printf("  utf8 short %d\n",
           EVP_PKEY_get_utf8_string_param(c, OSSL_PKEY_PARAM_CIPHER, name, 5, &len));
    errors();
    printf("  utf8 on HMAC %d\n",
           EVP_PKEY_get_utf8_string_param(h, OSSL_PKEY_PARAM_CIPHER, name, sizeof(name), &len));
    printf("  int %d size_t %d bn %d group %d\n", EVP_PKEY_get_int_param(h, "bits", &i),
           EVP_PKEY_get_size_t_param(h, "bits", &sz), EVP_PKEY_get_bn_param(h, "priv", &bn),
           EVP_PKEY_get_group_name(h, name, sizeof(name), &len));
    errors();
    {
        unsigned char pbuf[32];
        OSSL_PARAM gp[3];

        gp[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, pbuf, sizeof(pbuf));
        gp[1] = OSSL_PARAM_construct_int("bits", &i);
        gp[2] = OSSL_PARAM_construct_end();
        printf("  get_params %d modified %d %d size %zu\n", EVP_PKEY_get_params(h, gp),
               OSSL_PARAM_modified(&gp[0]), OSSL_PARAM_modified(&gp[1]), gp[0].return_size);
    }
    printf("  NULL names %d %d\n", EVP_PKEY_get_int_param(h, NULL, &i),
           EVP_PKEY_set_int_param(h, NULL, 1));

    /* Setting the private key replaces it; other parameters are ignored. */
    printf("  set priv %d\n", EVP_PKEY_set_octet_string_param(h, OSSL_PKEY_PARAM_PRIV_KEY,
                                                              key32, 20));
    raw_priv("after", h);
    printf("  set others %d %d %d %d\n", EVP_PKEY_set_int_param(h, "bits", 1),
           EVP_PKEY_set_size_t_param(h, "size", 2),
           EVP_PKEY_set_utf8_string_param(h, "properties", "x"),
           EVP_PKEY_set1_encoded_public_key(h, key16, 4));
    bn = BN_new();
    BN_set_word(bn, 0x123456);
    printf("  set bn %d\n", EVP_PKEY_set_bn_param(h, "priv", bn));
    raw_priv("after bn", h);
    printf("  set bn NULL %d\n", EVP_PKEY_set_bn_param(h, "priv", NULL));
    BN_free(bn);
    printf("  set priv utf8 %d\n", EVP_PKEY_set_utf8_string_param(h, "priv", "abc"));
    errors();
    raw_priv("unchanged", h);
    printf("  get1_encoded %zu\n", EVP_PKEY_get1_encoded_public_key(h, NULL));

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)key16, 8);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER, "AES-256-CBC", 0);
    params[2] = OSSL_PARAM_construct_end();
    printf("  set_params CMAC %d\n", EVP_PKEY_set_params(c, params));
    printf("  cipher now %d %s\n",
           EVP_PKEY_get_utf8_string_param(c, OSSL_PKEY_PARAM_CIPHER, name, sizeof(name), NULL),
           name);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER, "NOPE", 0);
    printf("  set_params bad cipher %d\n", EVP_PKEY_set_params(c, params));
    errors();

    /* Export. */
    printf("  todata %d\n", EVP_PKEY_todata(h, EVP_PKEY_KEYPAIR, &out));
    show_param_values("todata", out);
    OSSL_PARAM_free(out);
    out = NULL;
    printf("  todata public %d %d\n", EVP_PKEY_todata(h, EVP_PKEY_PUBLIC_KEY, &out),
           out == NULL);
    printf("  todata NULL %d\n", EVP_PKEY_todata(h, EVP_PKEY_KEYPAIR, NULL));
    printf("  todata CMAC %d\n", EVP_PKEY_todata(c, OSSL_KEYMGMT_SELECT_ALL, &out));
    show_param_values("todata CMAC", out);
    OSSL_PARAM_free(out);
    printf("  export %d\n", EVP_PKEY_export(h, EVP_PKEY_KEYPAIR, export_cb, "export"));
    printf("  export refused %d\n", EVP_PKEY_export(h, EVP_PKEY_KEYPAIR, refuse_cb, NULL));
    printf("  export NULL %d\n", EVP_PKEY_export(NULL, EVP_PKEY_KEYPAIR, export_cb, "x"));
    errors();

    /* CMAC keys compare their ciphers too. */
    c2 = EVP_PKEY_new_CMAC_key(NULL, key16, 8, EVP_aes_256_cbc());
    printf("  CMAC eq %d\n", EVP_PKEY_eq(c, c2));
    EVP_PKEY_free(c2);
    c2 = EVP_PKEY_new_CMAC_key(NULL, key16, 8, EVP_aes_128_cbc());
    printf("  CMAC eq cipher %d\n", EVP_PKEY_eq(c, c2));
    EVP_PKEY_free(c2);
    c2 = EVP_PKEY_new_CMAC_key(NULL, key16, 16, NULL);
    check(c2 == NULL, "EVP_PKEY_new_CMAC_key without a cipher fails");
    errors();
    c2 = EVP_PKEY_new_CMAC_key(NULL, key16, 16, EVP_rc4());
    printf("  CMAC rc4 %d\n", c2 != NULL);
    errors();
    EVP_PKEY_free(c2);

    EVP_PKEY_free(h);
    EVP_PKEY_free(c);
}

/* Contexts and generation ---------------------------------------------------------------- */

static int gencb_calls = 0;

static int gencb(EVP_PKEY_CTX *ctx)
{
    (void)ctx;
    gencb_calls++;
    return 1;
}

static void ctx_state(const char *label, EVP_PKEY_CTX *ctx)
{
    const OSSL_PROVIDER *prov = EVP_PKEY_CTX_get0_provider(ctx);

    printf("  %s: op %d libctx %d propq %s prov %s pkey %d info %d\n", label,
           EVP_PKEY_CTX_get_operation(ctx), EVP_PKEY_CTX_get0_libctx(ctx) == NULL,
           str(EVP_PKEY_CTX_get0_propq(ctx)),
           prov == NULL ? "(null)" : OSSL_PROVIDER_get0_name(prov),
           EVP_PKEY_CTX_get0_pkey(ctx) != NULL, EVP_PKEY_CTX_get_keygen_info(ctx, -1));
}

static void test_ctx(void)
{
    EVP_PKEY_CTX *c, *d;
    EVP_PKEY *k = NULL, *k2, *h;
    int info[3] = { 5, 6, 7 };
    OSSL_PARAM params[2];

    c = EVP_PKEY_CTX_new_from_name(NULL, "HMAC", NULL);
    check(c != NULL, "EVP_PKEY_CTX_new_from_name HMAC");
    ctx_state("new", c);
    printf("  peerkey %d\n", EVP_PKEY_CTX_get0_peerkey(c) == NULL);
    printf("  is_a HMAC %d hmac %d CMAC %d\n", EVP_PKEY_CTX_is_a(c, "HMAC"),
           EVP_PKEY_CTX_is_a(c, "hmac"), EVP_PKEY_CTX_is_a(c, "CMAC"));
    list("gettable", EVP_PKEY_CTX_gettable_params(c));
    list("settable", EVP_PKEY_CTX_settable_params(c));
    params[0] = OSSL_PARAM_construct_octet_string("priv", (void *)key16, 16);
    params[1] = OSSL_PARAM_construct_end();
    printf("  set_params undef %d get_params %d\n", EVP_PKEY_CTX_set_params(c, params),
           EVP_PKEY_CTX_get_params(c, params));
    printf("  set_mac_key undef %d\n", EVP_PKEY_CTX_set_mac_key(c, key16, 16));
    errors();
    printf("  keygen uninit %d\n", EVP_PKEY_keygen(c, &k));
    errors();
    printf("  generate uninit %d\n", EVP_PKEY_generate(c, &k));
    errors();

    EVP_PKEY_CTX_set_app_data(c, "app");
    EVP_PKEY_CTX_set_data(c, "data");
    EVP_PKEY_CTX_set_cb(c, gencb);
    printf("  app %s data %s cb %d\n", (char *)EVP_PKEY_CTX_get_app_data(c),
           (char *)EVP_PKEY_CTX_get_data(c), EVP_PKEY_CTX_get_cb(c) == gencb);
    d = EVP_PKEY_CTX_dup(c);
    check(d != NULL, "EVP_PKEY_CTX_dup without an operation");
    ctx_state("dup", d);
    printf("  dup app %d data %d cb %d\n", EVP_PKEY_CTX_get_app_data(d) == NULL,
           EVP_PKEY_CTX_get_data(d) == NULL, EVP_PKEY_CTX_get_cb(d) == NULL);
    EVP_PKEY_CTX_free(d);

    check(EVP_PKEY_keygen_init(c) == 1, "EVP_PKEY_keygen_init");
    ctx_state("keygen", c);
    list("gettable", EVP_PKEY_CTX_gettable_params(c));
    list("settable", EVP_PKEY_CTX_settable_params(c));
    printf("  get_params %d\n", EVP_PKEY_CTX_get_params(c, params));
    d = EVP_PKEY_CTX_dup(c);
    check(d == NULL, "EVP_PKEY_CTX_dup during generation fails");
    errors();
    printf("  keygen without a key %d %d\n", EVP_PKEY_keygen(c, &k), k == NULL);
    errors();
    printf("  paramgen on keygen %d\n", EVP_PKEY_paramgen(c, &k));
    errors();
    printf("  set_mac_key -1 %d\n", EVP_PKEY_CTX_set_mac_key(c, key16, -1));
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string("priv", "abc", 0);
    printf("  set_params utf8 %d\n", EVP_PKEY_CTX_set_params(c, params));
    errors();
    printf("  set_mac_key %d\n", EVP_PKEY_CTX_set_mac_key(c, key16, 16));
    printf("  keygen NULL %d\n", EVP_PKEY_keygen(c, NULL));
    printf("  keygen %d\n", EVP_PKEY_keygen(c, &k));
    describe("generated", k);
    sizes("generated", k);
    raw_priv("generated", k);
    printf("  callback calls %d info %d\n", gencb_calls, EVP_PKEY_CTX_get_keygen_info(c, -1));
    printf("  keygen again %d\n", EVP_PKEY_keygen(c, &k));
    errors();

    /* Into an existing key. */
    k2 = EVP_PKEY_new_raw_private_key(EVP_PKEY_SIPHASH, NULL, key16, 16);
    printf("  set_mac_key %d keygen into %d\n", EVP_PKEY_CTX_set_mac_key(c, key32, 32),
           EVP_PKEY_keygen(c, &k2));
    describe("replaced", k2);
    raw_priv("replaced", k2);
    EVP_PKEY_free(k2);

    check(EVP_PKEY_paramgen_init(c) == 1, "EVP_PKEY_paramgen_init");
    ctx_state("paramgen", c);
    k2 = NULL;
    printf("  paramgen %d\n", EVP_PKEY_paramgen(c, &k2));
    describe("parameters", k2);
    raw_priv("parameters", k2);
    errors();
    printf("  eq parameters key %d %d\n", EVP_PKEY_eq(k, k2), EVP_PKEY_parameters_eq(k, k2));
    printf("  missing %d\n", EVP_PKEY_missing_parameters(k2));
    EVP_PKEY_free(k2);

    EVP_PKEY_CTX_set0_keygen_info(c, info, 3);
    printf("  keygen_info %d %d %d %d %d\n", EVP_PKEY_CTX_get_keygen_info(c, -1),
           EVP_PKEY_CTX_get_keygen_info(c, 0), EVP_PKEY_CTX_get_keygen_info(c, 2),
           EVP_PKEY_CTX_get_keygen_info(c, -2), EVP_PKEY_CTX_get_keygen_info(c, 9));
    EVP_PKEY_CTX_free(c);

    /* By id: the keys are typed by the id. */
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
    check(c != NULL, "EVP_PKEY_CTX_new_id HMAC");
    ctx_state("by id", c);
    k2 = NULL;
    if (EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_CTX_set_mac_key(c, key16, 16) == 1)
        printf("  keygen %d\n", EVP_PKEY_keygen(c, &k2));
    describe("by id", k2);
    printf("  get0_hmac %d\n", EVP_PKEY_get0_hmac(k2, NULL) == NULL);
    errors();
    printf("  eq raw %d\n", EVP_PKEY_eq(k, k2));
    EVP_PKEY_free(k2);
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new_from_name(NULL, "HMAC", "provider=default");
    ctx_state("with properties", c);
    EVP_PKEY_CTX_free(c);

    /* From a key: generation takes it as a template. */
    c = EVP_PKEY_CTX_new(k, NULL);
    check(c != NULL, "EVP_PKEY_CTX_new from a key");
    ctx_state("from key", c);
    printf("  pkey same %d\n", EVP_PKEY_CTX_get0_pkey(c) == k);
    printf("  checks %d %d %d %d %d %d %d\n", EVP_PKEY_check(c), EVP_PKEY_public_check(c),
           EVP_PKEY_public_check_quick(c), EVP_PKEY_param_check(c),
           EVP_PKEY_param_check_quick(c), EVP_PKEY_private_check(c),
           EVP_PKEY_pairwise_check(c));
    d = EVP_PKEY_CTX_dup(c);
    check(d != NULL, "EVP_PKEY_CTX_dup with a key");
    printf("  dup pkey same %d\n", EVP_PKEY_CTX_get0_pkey(d) == k);
    EVP_PKEY_CTX_free(d);
    k2 = NULL;
    if (EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_CTX_set_mac_key(c, key32, 8) == 1)
        printf("  keygen with a template %d\n", EVP_PKEY_keygen(c, &k2));
    raw_priv("templated", k2);
    EVP_PKEY_free(k2);
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, "provider=default");
    ctx_state("from pkey", c);
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new_from_name(NULL, "SIPHASH", NULL);
    printf("  checks without a key %d %d %d %d\n", EVP_PKEY_check(c), EVP_PKEY_public_check(c),
           EVP_PKEY_param_check(c), EVP_PKEY_private_check(c));
    errors();
    EVP_PKEY_CTX_free(c);

    /* Failures. */
    c = EVP_PKEY_CTX_new_from_name(NULL, "NOPE", NULL);
    check(c == NULL, "EVP_PKEY_CTX_new_from_name of an unknown name fails");
    errors();
    c = EVP_PKEY_CTX_new_id(99999, NULL);
    check(c == NULL, "EVP_PKEY_CTX_new_id of an unknown id fails");
    errors();
    h = EVP_PKEY_new();
    c = EVP_PKEY_CTX_new(h, NULL);
    check(c == NULL, "EVP_PKEY_CTX_new of a blank key fails");
    errors();
    EVP_PKEY_free(h);
    c = EVP_PKEY_CTX_new_from_name(NULL, "HMAC", "provider=base");
    check(c == NULL, "EVP_PKEY_CTX_new_from_name from base fails");
    errors();
    EVP_PKEY_CTX_free(NULL);

    /* KDF key types: no generation, no import. */
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    check(c != NULL, "EVP_PKEY_CTX_new_id HKDF");
    ctx_state("HKDF", c);
    printf("  keygen_init %d op %d\n", EVP_PKEY_keygen_init(c), EVP_PKEY_CTX_get_operation(c));
    errors();
    printf("  paramgen_init %d\n", EVP_PKEY_paramgen_init(c));
    errors();
    printf("  fromdata_init %d\n", EVP_PKEY_fromdata_init(c));
    params[0] = OSSL_PARAM_construct_end();
    k2 = NULL;
    printf("  fromdata %d %d\n", EVP_PKEY_fromdata(c, &k2, EVP_PKEY_KEYPAIR, params), k2 == NULL);
    errors();
    list("fromdata_settable", EVP_PKEY_fromdata_settable(c, EVP_PKEY_KEYPAIR));
    EVP_PKEY_CTX_free(c);

    /* EVP_PKEY_new_mac_key. */
    k2 = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key16, 16);
    describe("new_mac_key HMAC", k2);
    raw_priv("new_mac_key", k2);
    EVP_PKEY_free(k2);
    k2 = EVP_PKEY_new_mac_key(EVP_PKEY_SIPHASH, NULL, key16, 16);
    describe("new_mac_key SIPHASH", k2);
    EVP_PKEY_free(k2);
    k2 = EVP_PKEY_new_mac_key(EVP_PKEY_CMAC, NULL, key16, 16);
    describe("new_mac_key CMAC", k2);
    printf("  CMAC cipher %d\n", EVP_PKEY_get_utf8_string_param(k2, "cipher", NULL, 0, NULL));
    EVP_PKEY_free(k2);
    k2 = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key16, 0);
    check(k2 == NULL, "EVP_PKEY_new_mac_key with an empty key fails");
    errors();
    k2 = EVP_PKEY_new_mac_key(EVP_PKEY_HKDF, NULL, key16, 16);
    check(k2 == NULL, "EVP_PKEY_new_mac_key HKDF fails");
    errors();

    /* EVP_PKEY_Q_keygen. */
    k2 = EVP_PKEY_Q_keygen(NULL, NULL, "HMAC");
    check(k2 == NULL, "EVP_PKEY_Q_keygen HMAC fails");
    errors();
    k2 = EVP_PKEY_Q_keygen(NULL, NULL, "HKDF");
    check(k2 == NULL, "EVP_PKEY_Q_keygen HKDF fails");
    errors();
    k2 = EVP_PKEY_Q_keygen(NULL, NULL, "NOPE");
    check(k2 == NULL, "EVP_PKEY_Q_keygen of an unknown type fails");
    errors();

    EVP_PKEY_free(k);
}

/* Making keys from parameters ------------------------------------------------------------ */

static void test_fromdata(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "CMAC", NULL);
    EVP_PKEY *k = NULL, *k2 = NULL;
    OSSL_PARAM params[4];
    char name[64];

    check(c != NULL, "a CMAC context");
    printf("  fromdata uninit %d\n", EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, NULL));
    errors();
    list("fromdata_settable", EVP_PKEY_fromdata_settable(c, EVP_PKEY_KEYPAIR));
    list("fromdata_settable public", EVP_PKEY_fromdata_settable(c, EVP_PKEY_PUBLIC_KEY));
    printf("  fromdata_init %d op %d\n", EVP_PKEY_fromdata_init(c), EVP_PKEY_CTX_get_operation(c));
    list("settable", EVP_PKEY_fromdata_settable(c, EVP_PKEY_PRIVATE_KEY));
    printf("  op after settable %d\n", EVP_PKEY_CTX_get_operation(c));
    printf("  fromdata_init %d\n", EVP_PKEY_fromdata_init(c));
    printf("  fromdata NULL %d\n", EVP_PKEY_fromdata(c, NULL, EVP_PKEY_KEYPAIR, NULL));

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)key16, 16);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER, "AES-192-CBC", 0);
    params[2] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, "provider=default", 0);
    params[3] = OSSL_PARAM_construct_end();
    printf("  fromdata %d\n", EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, params));
    describe("CMAC", k);
    printf("  cipher %d %s\n",
           EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_CIPHER, name, sizeof(name), NULL),
           name);
    raw_priv("CMAC", k);
    printf("  fromdata public %d\n", EVP_PKEY_fromdata(c, &k2, EVP_PKEY_PUBLIC_KEY, params));
    printf("  fromdata params only %d\n",
           EVP_PKEY_fromdata(c, &k2, EVP_PKEY_KEY_PARAMETERS, params));
    params[0] = OSSL_PARAM_construct_end();
    printf("  fromdata without a key %d\n", EVP_PKEY_fromdata(c, &k2, EVP_PKEY_KEYPAIR, params));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PRIV_KEY, "abc", 0);
    printf("  fromdata utf8 key %d\n", EVP_PKEY_fromdata(c, &k2, EVP_PKEY_KEYPAIR, params));
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)key16, 16);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER, "NOPE", 0);
    params[2] = OSSL_PARAM_construct_end();
    printf("  fromdata bad cipher %d\n", EVP_PKEY_fromdata(c, &k2, EVP_PKEY_KEYPAIR, params));
    errors();
    params[1] = OSSL_PARAM_construct_end();
    printf("  fromdata no cipher %d\n", EVP_PKEY_fromdata(c, &k2, EVP_PKEY_KEYPAIR, params));
    describe("no cipher", k2);
    /* Into an existing key. */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)key32, 32);
    printf("  fromdata into %d\n", EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, params));
    raw_priv("replaced", k);
    printf("  cipher %d\n",
           EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_CIPHER, name, sizeof(name), NULL));
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);

    /* A key typed by its key manager, without data. */
    {
        EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, "POLY1305", NULL);
        EVP_PKEY *t = EVP_PKEY_new();

        printf("  set_type_by_keymgmt %d\n", EVP_PKEY_set_type_by_keymgmt(t, km));
        EVP_KEYMGMT_free(km);
        describe("typed", t);
        raw_priv("typed", t);
        printf("  missing %d\n", EVP_PKEY_missing_parameters(t));
        printf("  get_params %d\n", EVP_PKEY_get_octet_string_param(t, "priv", NULL, 0, NULL));
        type_names("typed names", t);
        printf("  set_type HMAC %d\n", EVP_PKEY_set_type(t, EVP_PKEY_HMAC));
        errors();
        printf("  set_type DH %d\n", EVP_PKEY_set_type(t, EVP_PKEY_DH));
        describe("retyped", t);
        EVP_PKEY_free(t);
    }
}

int main(void)
{
    test_keymgmt();
    test_types();
    test_blank();
    test_typed();
    test_raw();
    test_params();
    test_ctx();
    test_fromdata();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
