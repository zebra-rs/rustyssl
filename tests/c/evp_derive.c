/*
 * Conformance test for key derivation through key contexts (EVP_KEYEXCH(3), EVP_PKEY_derive(3),
 * EVP_PKEY_CTX_ctrl(3), EVP_PKEY_CTX_set_hkdf_md(3), EVP_PKEY_CTX_set_tls1_prf_md(3),
 * EVP_PKEY_CTX_set_scrypt_N(3)), in TAP format, over the default provider's KDF exchanges
 * (TLS1-PRF, HKDF, SCRYPT): fetching and introspecting the exchanges, deriving with the typed
 * setters (RFC 5869 and RFC 7914 vectors), the ctrl and ctrl_str translations to parameters
 * (and their quirks), the typed setters of the other key types on contexts that don't take
 * them, the distinguishing ID kept for later operations, and the asymmetric cipher, KEM, and
 * exchange operations on key types without them.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
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

/* The text of the newest error, then the errors. */
static void error_data(void)
{
    const char *data = NULL;
    int flags = 0;

    ERR_peek_last_error_data(&data, &flags);
    printf("  data: %s\n", (flags & ERR_TXT_STRING) != 0 ? data : "(none)");
    errors();
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

/* Derives `n` octets (or asks the size for n == 0) and prints them. */
static void derive(const char *label, EVP_PKEY_CTX *c, size_t n)
{
    unsigned char out[128];
    size_t len = n;
    int r;

    if (n == 0) {
        r = EVP_PKEY_derive(c, NULL, &len);
        printf("  %s: size %d %zu\n", label, r, len);
        return;
    }
    r = EVP_PKEY_derive(c, out, &len);
    printf("  %s: %d %zu", label, r, len);
    if (r > 0)
        hex("", out, len);
    else
        printf("\n");
}

/* RFC 5869, test case 1. */
static const unsigned char ikm[22] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const unsigned char salt[13] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
};
static const unsigned char info[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
};

/* Exchanges ------------------------------------------------------------------------------- */

static const char *const ours[] = { "TLS1-PRF", "HKDF", "SCRYPT", NULL };

static void do_all_cb(EVP_KEYEXCH *exch, void *arg)
{
    int i;

    (void)arg;
    for (i = 0; ours[i] != NULL; i++)
        if (strcmp(EVP_KEYEXCH_get0_name(exch), ours[i]) == 0)
            printf(" %s", ours[i]);
}

static void test_methods(void)
{
    int i;
    EVP_KEYEXCH *exch;

    for (i = 0; ours[i] != NULL; i++) {
        char what[64];
        int r;

        exch = EVP_KEYEXCH_fetch(NULL, ours[i], NULL);
        snprintf(what, sizeof(what), "EVP_KEYEXCH_fetch %s", ours[i]);
        check(exch != NULL, what);
        if (exch == NULL) {
            errors();
            continue;
        }
        printf("  name %s desc %s prov %s is_a %d %d\n", EVP_KEYEXCH_get0_name(exch),
               str(EVP_KEYEXCH_get0_description(exch)),
               OSSL_PROVIDER_get0_name(EVP_KEYEXCH_get0_provider(exch)),
               EVP_KEYEXCH_is_a(exch, ours[i]), EVP_KEYEXCH_is_a(exch, "DH"));
        printf("  names:");
        r = EVP_KEYEXCH_names_do_all(exch, name_cb, NULL);
        printf(" (%d)\n", r);
        list("gettable", EVP_KEYEXCH_gettable_ctx_params(exch));
        list("settable", EVP_KEYEXCH_settable_ctx_params(exch));
        printf("  up_ref %d\n", EVP_KEYEXCH_up_ref(exch));
        EVP_KEYEXCH_free(exch);
        EVP_KEYEXCH_free(exch);
    }
    exch = EVP_KEYEXCH_fetch(NULL, "NOPE", NULL);
    check(exch == NULL, "EVP_KEYEXCH_fetch of an unknown name fails");
    errors();
    exch = EVP_KEYEXCH_fetch(NULL, "HKDF", "provider=base");
    check(exch == NULL, "EVP_KEYEXCH_fetch from base fails");
    errors();
    printf("  do_all:");
    EVP_KEYEXCH_do_all_provided(NULL, do_all_cb, NULL);
    printf("\n");
    EVP_KEYEXCH_free(NULL);
    check(EVP_KEYEXCH_is_a(NULL, "HKDF") == 0, "EVP_KEYEXCH_is_a(NULL)");

    check(EVP_ASYM_CIPHER_fetch(NULL, "NOPE", NULL) == NULL, "EVP_ASYM_CIPHER_fetch NOPE");
    errors();
    EVP_ASYM_CIPHER_free(NULL);
    check(EVP_KEM_fetch(NULL, "NOPE", NULL) == NULL, "EVP_KEM_fetch NOPE");
    errors();
    EVP_KEM_free(NULL);
}

/* HKDF ------------------------------------------------------------------------------------ */

static void test_hkdf(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL), *d;
    EVP_PKEY *k;
    OSSL_PARAM params[2];
    size_t size = 0;
    int mode = 0;

    check(c != NULL, "EVP_PKEY_CTX_new_id HKDF");
    printf("  pkey before %d op %d\n", EVP_PKEY_CTX_get0_pkey(c) != NULL,
           EVP_PKEY_CTX_get_operation(c));
    printf("  set_hkdf_md before init %d\n", EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()));
    errors();
    check(EVP_PKEY_derive_init(c) == 1, "EVP_PKEY_derive_init");
    k = EVP_PKEY_CTX_get0_pkey(c);
    printf("  pkey after %d id %d type %s op %d prov %s\n", k != NULL, EVP_PKEY_get_id(k),
           str(EVP_PKEY_get0_type_name(k)), EVP_PKEY_CTX_get_operation(c),
           OSSL_PROVIDER_get0_name(EVP_PKEY_CTX_get0_provider(c)));
    list("ctx gettable", EVP_PKEY_CTX_gettable_params(c));
    list("ctx settable", EVP_PKEY_CTX_settable_params(c));
    printf("  set %d %d %d %d %d %d\n", EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()),
           EVP_PKEY_CTX_set1_hkdf_salt(c, salt, sizeof(salt)),
           EVP_PKEY_CTX_set1_hkdf_key(c, ikm, sizeof(ikm)),
           EVP_PKEY_CTX_add1_hkdf_info(c, info, 4),
           EVP_PKEY_CTX_add1_hkdf_info(c, info + 4, 6),
           EVP_PKEY_CTX_add1_hkdf_info(c, info, 0));
    errors();
    printf("  negative %d %d\n", EVP_PKEY_CTX_add1_hkdf_info(c, info, -1),
           EVP_PKEY_CTX_set1_hkdf_salt(c, salt, -1));
    errors();
    params[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    printf("  get_params %d size %zu\n", EVP_PKEY_CTX_get_params(c, params), size);
    derive("size", c, 0);
    derive("okm", c, 42);
    derive("again", c, 42);
    d = EVP_PKEY_CTX_dup(c);
    check(d != NULL, "EVP_PKEY_CTX_dup during derivation");
    printf("  dup op %d pkey %d peer %d\n", EVP_PKEY_CTX_get_operation(d),
           EVP_PKEY_CTX_get0_pkey(d) == k, EVP_PKEY_CTX_get0_peerkey(d) != NULL);
    derive("dup", d, 42);
    printf("  mode %d\n", EVP_PKEY_CTX_set_hkdf_mode(c, EVP_KDF_HKDF_MODE_EXTRACT_ONLY));
    derive("extract size", c, 0);
    derive("prk", c, 32);
    derive("too small", c, 16);
    errors();
    printf("  bad mode %d\n", EVP_PKEY_CTX_set_hkdf_mode(c, -1));
    errors();
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    printf("  set_params %d\n", EVP_PKEY_CTX_set_params(c, params));
    derive("dup unchanged", d, 42);
    printf("  set_peer %d\n", EVP_PKEY_derive_set_peer(c, k));
    errors();
    printf("  set_peer_ex %d\n", EVP_PKEY_derive_set_peer_ex(c, k, 0));
    errors();
    EVP_PKEY_CTX_free(d);
    EVP_PKEY_CTX_free(c);
}

/* TLS1-PRF and SCRYPT ---------------------------------------------------------------------- */

static void test_tls1_prf(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "TLS1-PRF", NULL);
    static const unsigned char secret[17] = "0123456789abcdef";

    check(c != NULL && EVP_PKEY_derive_init_ex(c, NULL) == 1, "TLS1-PRF derive init");
    printf("  set %d %d %d %d\n", EVP_PKEY_CTX_set_tls1_prf_md(c, EVP_sha256()),
           EVP_PKEY_CTX_set1_tls1_prf_secret(c, secret, sizeof(secret)),
           EVP_PKEY_CTX_add1_tls1_prf_seed(c, (const unsigned char *)"label", 5),
           EVP_PKEY_CTX_add1_tls1_prf_seed(c, (const unsigned char *)"seed", 4));
    errors();
    derive("size", c, 0);
    derive("out", c, 24);
    printf("  md NULL %d\n", EVP_PKEY_CTX_set_tls1_prf_md(c, NULL));
    errors();
    derive("no md", c, 24);
    errors();
    printf("  hkdf md on tls %d\n", EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha1()));
    derive("sha1", c, 24);
    EVP_PKEY_CTX_free(c);
}

static void test_scrypt(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

    check(c != NULL && EVP_PKEY_derive_init(c) == 1, "SCRYPT derive init");
    /* RFC 7914, section 12, the first vector. */
    printf("  set %d %d %d %d %d %d\n", EVP_PKEY_CTX_set1_pbe_pass(c, "", 0),
           EVP_PKEY_CTX_set1_scrypt_salt(c, (const unsigned char *)"", 0),
           EVP_PKEY_CTX_set_scrypt_N(c, 16), EVP_PKEY_CTX_set_scrypt_r(c, 1),
           EVP_PKEY_CTX_set_scrypt_p(c, 1), EVP_PKEY_CTX_set_scrypt_maxmem_bytes(c, 1 << 20));
    errors();
    derive("size", c, 0);
    derive("out", c, 64);
    printf("  N 3 %d\n", EVP_PKEY_CTX_set_scrypt_N(c, 3));
    errors();
    printf("  pass %d salt %d\n", EVP_PKEY_CTX_set1_pbe_pass(c, "password", 8),
           EVP_PKEY_CTX_set1_scrypt_salt(c, (const unsigned char *)"NaCl", 4));
    derive("password", c, 16);
    printf("  negative %d\n", EVP_PKEY_CTX_set1_pbe_pass(c, "x", -1));
    errors();
    EVP_PKEY_CTX_free(c);
}

/* The ctrl translations ------------------------------------------------------------------- */

static void ctrl_str(EVP_PKEY_CTX *c, const char *name, const char *value)
{
    printf("  ctrl_str %s=%s: %d\n", name, value, EVP_PKEY_CTX_ctrl_str(c, name, value));
    error_data();
}

static void test_ctrl(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "HKDF", NULL);
    int r;

    r = EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MD, 0,
                          (void *)EVP_sha256());
    printf("  ctrl before init %d\n", r);
    errors();
    ctrl_str(c, "md", "SHA256");
    printf("  ctrl NULL %d\n", EVP_PKEY_CTX_ctrl(NULL, -1, -1, EVP_PKEY_CTRL_HKDF_MD, 0, NULL));
    errors();
    /*
     * A 64-bit ctrl that reaches a translation passes the value's address as a BIGNUM in the
     * reference (docs/DEVIATIONS.md); these stop before that.
     */
    printf("  ctrl_uint64 before init %d NULL %d\n",
           EVP_PKEY_CTX_ctrl_uint64(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_N, 16),
           EVP_PKEY_CTX_ctrl_uint64(NULL, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_N, 16));
    errors();
    check(EVP_PKEY_derive_init(c) == 1, "derive init");
    printf("  wrong optype %d\n",
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_SIGN, EVP_PKEY_CTRL_HKDF_MD, 0,
                             (void *)EVP_sha256()));
    errors();
    printf("  md %d salt %d key %d info %d\n",
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MD, 0,
                             (void *)EVP_sha256()),
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_SALT,
                             sizeof(salt), (void *)salt),
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_KEY,
                             sizeof(ikm), (void *)ikm),
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_INFO,
                             sizeof(info), (void *)info));
    errors();
    derive("ctrl okm", c, 42);
    /* The mode's ctrl passes the length of the mode's name as the mode. */
    printf("  mode ctrl %d\n", EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE,
                                                 EVP_PKEY_CTRL_HKDF_MODE,
                                                 EVP_KDF_HKDF_MODE_EXPAND_ONLY, NULL));
    errors();
    printf("  unknown mode ctrl %d\n", EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE,
                                                         EVP_PKEY_CTRL_HKDF_MODE, 7, NULL));
    errors();
    printf("  tls md on hkdf %d\n", EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE,
                                                      EVP_PKEY_CTRL_TLS_MD, 0,
                                                      (void *)EVP_sha1()));
    derive("sha1 okm", c, 20);
    printf("  md by nid %d\n", EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE,
                                                 EVP_PKEY_CTRL_HKDF_MD, NID_sha256, NULL));
    derive("sha256 okm", c, 20);
    printf("  rsa padding %d\n", EVP_PKEY_CTX_ctrl(c, -1, -1, EVP_PKEY_CTRL_RSA_PADDING,
                                                   RSA_PKCS1_PADDING, NULL));
    errors();
    printf("  unknown cmd %d\n", EVP_PKEY_CTX_ctrl(c, -1, -1, 9999, 0, NULL));
    errors();
    printf("  unknown cmd uint64 %d\n", EVP_PKEY_CTX_ctrl_uint64(c, -1, -1, 9999, 1));
    errors();
    printf("  md helper %d\n", EVP_PKEY_CTX_md(c, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MD,
                                               "SHA384"));
    derive("sha384 okm", c, 20);
    printf("  md helper nope %d\n", EVP_PKEY_CTX_md(c, EVP_PKEY_OP_DERIVE,
                                                    EVP_PKEY_CTRL_HKDF_MD, "nope"));
    errors();
    printf("  md helper NULL %d\n", EVP_PKEY_CTX_md(c, EVP_PKEY_OP_DERIVE,
                                                    EVP_PKEY_CTRL_HKDF_MD, NULL));
    errors();

    ctrl_str(c, "md", "SHA256");
    ctrl_str(c, "salt", "salty");
    ctrl_str(c, "hexsalt", "000102030405060708090a0b0c");
    ctrl_str(c, "hexkey", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    ctrl_str(c, "HEXINFO", "f0f1f2f3f4f5f6f7f8f9");
    ctrl_str(c, "mode", "EXTRACT_AND_EXPAND");
    derive("ctrl_str okm", c, 42);
    ctrl_str(c, "mode", "EXTRACT_ONLY");
    derive("ctrl_str prk", c, 32);
    ctrl_str(c, "mode", "SIDEWAYS");
    ctrl_str(c, "digest", "SHA1");
    ctrl_str(c, "properties", "");
    ctrl_str(c, "foo", "bar");
    ctrl_str(c, "N", "16");
    ctrl_str(c, "hexsalt", "xyz");
    ctrl_str(c, "distid", "abc");
    printf("  get1_id_len %d\n", EVP_PKEY_CTX_get1_id_len(c, NULL));
    errors();
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);
    EVP_PKEY_derive_init(c);
    printf("  scrypt ctrls %d %d %d\n",
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_PASS, 8,
                             (void *)"password"),
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_SALT, 4,
                             (void *)"NaCl"),
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_N, 16, NULL));
    errors();
    ctrl_str(c, "r", "1");
    ctrl_str(c, "p", "1");
    ctrl_str(c, "maxmem_bytes", "1048576");
    ctrl_str(c, "N", "sixteen");
    derive("scrypt ctrl", c, 16);
    ctrl_str(c, "hexpass", "70617373776f7264");
    ctrl_str(c, "pass", "password");
    derive("scrypt ctrl_str", c, 16);
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    EVP_PKEY_derive_init(c);
    ctrl_str(c, "md", "SHA256");
    ctrl_str(c, "secret", "0123456789abcdef");
    ctrl_str(c, "seed", "labelseed");
    derive("tls ctrl_str", c, 24);
    ctrl_str(c, "hexseed", "6c6162656c73656564");
    ctrl_str(c, "hexsecret", "30313233343536373839616263646566");
    derive("tls hex", c, 24);
    printf("  tls ctrls %d %d %d\n",
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_MD, 0,
                             (void *)EVP_sha256()),
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_SECRET, 16,
                             (void *)"0123456789abcdef"),
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_SEED, 9,
                             (void *)"labelseed"));
    derive("tls ctrl", c, 24);
    EVP_PKEY_CTX_free(c);
}

/* Other key types' setters ----------------------------------------------------------------- */

static void test_foreign_setters(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
    const EVP_MD *md = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *ukm = OPENSSL_malloc(4), *got = NULL;
    BIGNUM *e = BN_new();
    char name[64] = "";
    int len = 0, pad = 0;

    EVP_PKEY_derive_init(c);
    check(EVP_PKEY_keygen_init(g) == 1, "HMAC keygen init");
    memcpy(ukm, "ukm!", 4);
    BN_set_word(e, 65537);

    printf("  dh derive: pad %d kdf_type %d get %d md %d get %d\n",
           EVP_PKEY_CTX_set_dh_pad(c, 1), EVP_PKEY_CTX_set_dh_kdf_type(c, EVP_PKEY_DH_KDF_X9_42),
           EVP_PKEY_CTX_get_dh_kdf_type(c), EVP_PKEY_CTX_set_dh_kdf_md(c, EVP_sha256()),
           EVP_PKEY_CTX_get_dh_kdf_md(c, &md));
    errors();
    printf("  dh outlen %d zero %d get %d\n", EVP_PKEY_CTX_set_dh_kdf_outlen(c, 16),
           EVP_PKEY_CTX_set_dh_kdf_outlen(c, 0), EVP_PKEY_CTX_get_dh_kdf_outlen(c, &len));
    errors();
    printf("  dh ukm %d negative %d get %d\n", EVP_PKEY_CTX_set0_dh_kdf_ukm(c, ukm, 4),
           EVP_PKEY_CTX_set0_dh_kdf_ukm(c, ukm, -1), EVP_PKEY_CTX_get0_dh_kdf_ukm(c, &got));
    errors();
    printf("  dh oid %d get %d\n",
           EVP_PKEY_CTX_set0_dh_kdf_oid(c, OBJ_nid2obj(NID_id_smime_alg_CMS3DESwrap)),
           EVP_PKEY_CTX_get0_dh_kdf_oid(c, &oid));
    errors();
    printf("  dh paramgen on derive %d %d %d %d %d %d\n",
           EVP_PKEY_CTX_set_dh_paramgen_prime_len(c, 2048),
           EVP_PKEY_CTX_set_dh_paramgen_subprime_len(c, 224),
           EVP_PKEY_CTX_set_dh_paramgen_generator(c, 2),
           EVP_PKEY_CTX_set_dh_paramgen_type(c, 1),
           EVP_PKEY_CTX_set_dh_paramgen_gindex(c, 1),
           EVP_PKEY_CTX_set_dh_paramgen_seed(c, (const unsigned char *)"seed", 4));
    errors();
    printf("  dh paramgen on keygen %d %d %d %d %d %d\n",
           EVP_PKEY_CTX_set_dh_paramgen_prime_len(g, 2048),
           EVP_PKEY_CTX_set_dh_paramgen_subprime_len(g, 224),
           EVP_PKEY_CTX_set_dh_paramgen_generator(g, 2),
           EVP_PKEY_CTX_set_dh_paramgen_type(g, 1),
           EVP_PKEY_CTX_set_dh_paramgen_gindex(g, 1),
           EVP_PKEY_CTX_set_dh_paramgen_seed(g, (const unsigned char *)"seed", 4));
    errors();
    printf("  dh nid %d rfc5114 %d dhx %d\n", EVP_PKEY_CTX_set_dh_nid(g, NID_ffdhe2048),
           EVP_PKEY_CTX_set_dh_rfc5114(g, 2), EVP_PKEY_CTX_set_dhx_rfc5114(g, 2));
    errors();
    printf("  dh pad on keygen %d\n", EVP_PKEY_CTX_set_dh_pad(g, 1));
    errors();

    printf("  dsa %d %d %d %d %d %d %d\n", EVP_PKEY_CTX_set_dsa_paramgen_bits(g, 2048),
           EVP_PKEY_CTX_set_dsa_paramgen_q_bits(g, 224),
           EVP_PKEY_CTX_set_dsa_paramgen_md(g, EVP_sha256()),
           EVP_PKEY_CTX_set_dsa_paramgen_md_props(g, "SHA256", "provider=default"),
           EVP_PKEY_CTX_set_dsa_paramgen_gindex(g, 1),
           EVP_PKEY_CTX_set_dsa_paramgen_seed(g, (const unsigned char *)"seed", 4),
           EVP_PKEY_CTX_set_dsa_paramgen_type(g, "fips186_4"));
    errors();
    printf("  dsa on derive %d\n", EVP_PKEY_CTX_set_dsa_paramgen_bits(c, 2048));
    errors();

    printf("  ec derive: cofactor %d bad %d get %d kdf_type %d get %d md %d get %d\n",
           EVP_PKEY_CTX_set_ecdh_cofactor_mode(c, 1), EVP_PKEY_CTX_set_ecdh_cofactor_mode(c, 5),
           EVP_PKEY_CTX_get_ecdh_cofactor_mode(c),
           EVP_PKEY_CTX_set_ecdh_kdf_type(c, EVP_PKEY_ECDH_KDF_X9_63),
           EVP_PKEY_CTX_get_ecdh_kdf_type(c), EVP_PKEY_CTX_set_ecdh_kdf_md(c, EVP_sha256()),
           EVP_PKEY_CTX_get_ecdh_kdf_md(c, &md));
    errors();
    printf("  ec outlen %d zero %d get %d ukm %d get %d\n",
           EVP_PKEY_CTX_set_ecdh_kdf_outlen(c, 16), EVP_PKEY_CTX_set_ecdh_kdf_outlen(c, 0),
           EVP_PKEY_CTX_get_ecdh_kdf_outlen(c, &len), EVP_PKEY_CTX_set0_ecdh_kdf_ukm(c, ukm, 4),
           EVP_PKEY_CTX_get0_ecdh_kdf_ukm(c, &got));
    errors();
    printf("  ec gen on derive %d %d\n",
           EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, NID_X9_62_prime256v1),
           EVP_PKEY_CTX_set_ec_param_enc(c, OPENSSL_EC_NAMED_CURVE));
    errors();
    printf("  ec gen on keygen %d %d %d sm2 %d\n",
           EVP_PKEY_CTX_set_ec_paramgen_curve_nid(g, NID_X9_62_prime256v1),
           EVP_PKEY_CTX_set_ec_param_enc(g, OPENSSL_EC_NAMED_CURVE),
           EVP_PKEY_CTX_set_ec_param_enc(g, 7),
           EVP_PKEY_CTX_set_ec_paramgen_curve_nid(g, NID_sm2));
    errors();
    printf("  ec on keygen %d %d\n", EVP_PKEY_CTX_set_ecdh_cofactor_mode(g, 1),
           EVP_PKEY_CTX_get_ecdh_kdf_type(g));
    errors();

    printf("  rsa keygen: bits %d primes %d pubexp %d set1 %d\n",
           EVP_PKEY_CTX_set_rsa_keygen_bits(g, 2048), EVP_PKEY_CTX_set_rsa_keygen_primes(g, 2),
           EVP_PKEY_CTX_set_rsa_keygen_pubexp(g, e), EVP_PKEY_CTX_set1_rsa_keygen_pubexp(g, e));
    errors();
    printf("  rsa pss keygen: md %d name %d mgf1 %d name %d saltlen %d\n",
           EVP_PKEY_CTX_set_rsa_pss_keygen_md(g, EVP_sha256()),
           EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(g, "SHA256", NULL),
           EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(g, EVP_sha256()),
           EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(g, "SHA256"),
           EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(g, 20));
    errors();
    printf("  rsa: padding %d get %d saltlen %d get %d mgf1 %d get %d\n",
           EVP_PKEY_CTX_set_rsa_padding(g, RSA_PKCS1_PADDING),
           EVP_PKEY_CTX_get_rsa_padding(g, &pad), EVP_PKEY_CTX_set_rsa_pss_saltlen(g, 20),
           EVP_PKEY_CTX_get_rsa_pss_saltlen(g, &len), EVP_PKEY_CTX_set_rsa_mgf1_md(g, EVP_sha1()),
           EVP_PKEY_CTX_get_rsa_mgf1_md(g, &md));
    errors();
    printf("  rsa names: mgf1 %d get %d oaep %d get %d\n",
           EVP_PKEY_CTX_set_rsa_mgf1_md_name(g, "SHA1", NULL),
           EVP_PKEY_CTX_get_rsa_mgf1_md_name(g, name, sizeof(name)),
           EVP_PKEY_CTX_set_rsa_oaep_md_name(g, "SHA1", NULL),
           EVP_PKEY_CTX_get_rsa_oaep_md_name(g, name, sizeof(name)));
    errors();
    printf("  rsa oaep: md %d get %d label %d get %d\n",
           EVP_PKEY_CTX_set_rsa_oaep_md(g, EVP_sha1()), EVP_PKEY_CTX_get_rsa_oaep_md(g, &md),
           EVP_PKEY_CTX_set0_rsa_oaep_label(g, NULL, 0),
           EVP_PKEY_CTX_get0_rsa_oaep_label(g, &got));
    errors();
    printf("  rsa on derive: padding %d mgf1 name %d\n",
           EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_PADDING),
           EVP_PKEY_CTX_set_rsa_mgf1_md_name(c, NULL, NULL));
    errors();

    printf("  group %d get %d\n", EVP_PKEY_CTX_set_group_name(g, "P-256"),
           EVP_PKEY_CTX_get_group_name(g, name, sizeof(name)));
    errors();
    printf("  group on derive %d get %d NULL %d\n", EVP_PKEY_CTX_set_group_name(c, "P-256"),
           EVP_PKEY_CTX_get_group_name(c, name, sizeof(name)),
           EVP_PKEY_CTX_set_group_name(g, NULL));
    errors();
    printf("  kem op %d NULL %d\n", EVP_PKEY_CTX_set_kem_op(g, "DHKEM"),
           EVP_PKEY_CTX_set_kem_op(g, NULL));
    errors();
    printf("  mac key on derive %d\n", EVP_PKEY_CTX_set_mac_key(c, (const unsigned char *)"k", 1));
    errors();
    printf("  generic ctrls: digest size %d cipher %d mac key %d\n",
           EVP_PKEY_CTX_ctrl(g, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_DIGEST_SIZE, 8, NULL),
           EVP_PKEY_CTX_ctrl(g, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_CIPHER, 0,
                             (void *)EVP_aes_128_cbc()),
           EVP_PKEY_CTX_ctrl(g, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_MAC_KEY, 3,
                             (void *)"key"));
    errors();
    ctrl_str(g, "key", "abc");
    ctrl_str(g, "hexkey", "616263");
    ctrl_str(g, "digestsize", "8");
    {
        EVP_PKEY *k = NULL;

        printf("  keygen %d", EVP_PKEY_keygen(g, &k));
        if (k != NULL) {
            unsigned char raw[16];
            size_t rawlen = sizeof(raw);

            if (EVP_PKEY_get_raw_private_key(k, raw, &rawlen) == 1)
                hex("key", raw, rawlen);
            else
                printf("\n");
        } else {
            printf("\n");
        }
        EVP_PKEY_free(k);
    }

    OPENSSL_free(ukm);
    BN_free(e);
    ASN1_OBJECT_free(oid);
    EVP_PKEY_CTX_free(g);
    EVP_PKEY_CTX_free(c);
}

/* The distinguishing ID and the algorithm identifier -------------------------------------- */

static const unsigned char hmac_key[21] = "01234567890123456789";

static void test_id_and_algor(void)
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, hmac_key, 20);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char id[16] = { 0 };
    size_t idlen = 0;
    X509_ALGOR *alg = NULL;
    static const unsigned char der[] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00
    };
    const unsigned char *p = der;
    const EVP_MD *got = NULL;
    X509_ALGOR *given = d2i_X509_ALGOR(NULL, &p, sizeof(der));

    printf("  set1_id %d get1_id %d len %d\n", EVP_PKEY_CTX_set1_id(c, "id!", 3),
           EVP_PKEY_CTX_get1_id(c, id), EVP_PKEY_CTX_get1_id_len(c, &idlen));
    errors();
    /* The ID is kept for the operation the context is initialized for. */
    EVP_MD_CTX_set_pkey_ctx(md, c);
    printf("  sign init with an ID %d op %d\n",
           EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, k), EVP_PKEY_CTX_get_operation(c));
    errors();
    EVP_MD_CTX_set_pkey_ctx(md, NULL);
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new(k, NULL);
    check(EVP_DigestSignInit(md, &c, EVP_sha256(), NULL, k) == 1, "HMAC sign init");
    printf("  set1_id %d get1_id %d len %d\n", EVP_PKEY_CTX_set1_id(c, "id!", 3),
           EVP_PKEY_CTX_get1_id(c, id), EVP_PKEY_CTX_get1_id_len(c, &idlen));
    errors();
    ctrl_str(c, "hexdistid", "696421");
    ctrl_str(c, "digestsize", "8");
    printf("  algor params %d get %d algor %d\n", EVP_PKEY_CTX_set_algor_params(c, given),
           EVP_PKEY_CTX_get_algor_params(c, given), EVP_PKEY_CTX_get_algor(c, &alg));
    errors();
    printf("  algor NULL out %d\n", EVP_PKEY_CTX_get_algor(c, NULL));
    errors();
    printf("  signature md: set %d\n", EVP_PKEY_CTX_set_signature_md(c, EVP_sha256()));
    printf("  ctrl md %d get %d\n",
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD, 0,
                             (void *)EVP_sha256()),
           EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_GET_MD, 0,
                             (void *)&got));
    printf("  got %s\n", got == NULL ? "NULL" : EVP_MD_get0_name(got));
    errors();
    EVP_MD_CTX_free(md);
    X509_ALGOR_free(given);
    X509_ALGOR_free(alg);
    EVP_PKEY_free(k);
}

/* Operations the key types don't have ----------------------------------------------------- */

static void test_unsupported(void)
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, hmac_key, 20);
    EVP_PKEY *rsa = EVP_PKEY_new();
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL);
    EVP_PKEY_CTX *h = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    unsigned char out[64], sec[64];
    size_t outlen = sizeof(out), seclen = sizeof(sec);

    printf("  encrypt init %d op %d encrypt %d\n", EVP_PKEY_encrypt_init(c),
           EVP_PKEY_CTX_get_operation(c), EVP_PKEY_encrypt(c, out, &outlen, out, 1));
    errors();
    printf("  set_params %d get_params %d\n", EVP_PKEY_CTX_set_params(c, NULL),
           EVP_PKEY_CTX_get_params(c, NULL));
    printf("  decrypt init %d op %d decrypt %d encrypt %d\n", EVP_PKEY_decrypt_init_ex(c, NULL),
           EVP_PKEY_CTX_get_operation(c), EVP_PKEY_decrypt(c, out, &outlen, out, 1),
           EVP_PKEY_encrypt(c, out, &outlen, out, 1));
    errors();
    printf("  encrypt_init_ex %d\n", EVP_PKEY_encrypt_init_ex(c, NULL));
    {
        EVP_PKEY_CTX *d = EVP_PKEY_CTX_dup(c);

        printf("  dup %d\n", d != NULL);
        EVP_PKEY_CTX_free(d);
    }
    errors();
    printf("  NULL: %d %d %d %d %d %d\n", EVP_PKEY_encrypt_init(NULL),
           EVP_PKEY_decrypt_init(NULL), EVP_PKEY_encrypt(NULL, out, &outlen, out, 1),
           EVP_PKEY_decrypt(NULL, out, &outlen, out, 1), EVP_PKEY_derive_init(NULL),
           EVP_PKEY_derive_init_ex(NULL, NULL));
    errors();
    printf("  no key: encrypt %d decrypt %d op %d\n", EVP_PKEY_encrypt_init(h),
           EVP_PKEY_decrypt_init(h), EVP_PKEY_CTX_get_operation(h));
    errors();
    printf("  encapsulate init %d op %d encapsulate %d\n", EVP_PKEY_encapsulate_init(c, NULL),
           EVP_PKEY_CTX_get_operation(c),
           EVP_PKEY_encapsulate(c, out, &outlen, sec, &seclen));
    errors();
    printf("  decapsulate init %d auth %d %d decapsulate %d\n",
           EVP_PKEY_decapsulate_init(c, NULL), EVP_PKEY_auth_encapsulate_init(c, NULL, NULL),
           EVP_PKEY_auth_decapsulate_init(c, NULL, NULL),
           EVP_PKEY_decapsulate(c, sec, &seclen, out, 1));
    errors();
    printf("  auth with a key %d %d\n", EVP_PKEY_auth_encapsulate_init(c, k, NULL),
           EVP_PKEY_auth_decapsulate_init(c, rsa, NULL));
    errors();
    printf("  kem no key %d op %d\n", EVP_PKEY_encapsulate_init(h, NULL),
           EVP_PKEY_CTX_get_operation(h));
    errors();
    printf("  kem NULL: %d %d %d %d %d\n", EVP_PKEY_encapsulate_init(NULL, NULL),
           EVP_PKEY_decapsulate_init(NULL, NULL),
           EVP_PKEY_encapsulate(NULL, out, &outlen, sec, &seclen),
           EVP_PKEY_decapsulate(NULL, sec, &seclen, out, 1),
           EVP_PKEY_decapsulate(c, sec, &seclen, NULL, 1));
    errors();
    printf("  derive init %d op %d derive %d set_peer %d\n", EVP_PKEY_derive_init(c),
           EVP_PKEY_CTX_get_operation(c), EVP_PKEY_derive(c, out, &outlen),
           EVP_PKEY_derive_set_peer(c, k));
    errors();
    printf("  derive NULL %d %d %d\n", EVP_PKEY_derive(NULL, out, &outlen),
           EVP_PKEY_derive(c, out, NULL), EVP_PKEY_derive_set_peer(NULL, k));
    errors();
    EVP_PKEY_CTX_free(h);
    h = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    printf("  derive before init %d\n", EVP_PKEY_derive(h, out, &outlen));
    errors();
    printf("  encapsulate before init %d decapsulate %d\n",
           EVP_PKEY_encapsulate(h, out, &outlen, sec, &seclen),
           EVP_PKEY_decapsulate(h, sec, &seclen, out, 1));
    errors();
    EVP_PKEY_derive_init(h);
    printf("  encrypt after derive %d op %d\n", EVP_PKEY_encrypt_init(h),
           EVP_PKEY_CTX_get_operation(h));
    errors();

    EVP_PKEY_set_type(rsa, EVP_PKEY_RSA);
    printf("  old: hmac %d %d rsa %d %d\n", EVP_PKEY_encrypt_old(out, sec, 16, k),
           EVP_PKEY_decrypt_old(out, sec, 16, k), EVP_PKEY_encrypt_old(out, sec, 16, rsa),
           EVP_PKEY_decrypt_old(out, sec, 16, rsa));
    errors();
    EVP_PKEY_CTX_free(h);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(k);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    test_methods();
    test_hkdf();
    test_tls1_prf();
    test_scrypt();
    test_ctrl();
    test_foreign_setters();
    test_id_and_algor();
    test_unsupported();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
