/*
 * Conformance test for the DH key exchange (EVP_KEYEXCH-DH(7), EVP_PKEY_derive(3)) and the
 * legacy DH key method (EVP_PKEY_meth_find(3) for EVP_PKEY_DH and EVP_PKEY_DHX; OpenSSL's
 * dh_pmeth.c), in TAP format: the provider's exchange (its names and parameter lists, the
 * secret both ways, padded and not, the size query, too little room, missing and mismatched
 * keys, its context parameters, X9.42's KDF with and without keying material, copies of a
 * context, and the typed setters and getters); then a DH with an application's DH_METHOD,
 * which stays a legacy key, so its derivations go through the built-in method (plain, padded,
 * X9.42's KDF, the ctrls and ctrl strings with their errors); and parameter and key generation
 * through an application's copy of the built-in method (a named group, RFC 5114's, safe
 * primes, FIPS 186 parameters, and the errors).
 *
 * Keys are generated on a known DRBG, so secrets are printed (as a hash) and must match the
 * reference's.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/rand.h>

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

/* A CTR-DRBG under a TEST-RAND parent with known entropy and nonce. */
static EVP_RAND_CTX *known_drbg(unsigned char seed)
{
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "TEST-RAND", NULL);
    EVP_RAND_CTX *parent = EVP_RAND_CTX_new(rand, NULL), *ctx;
    unsigned char entropy[64], nonce[32];
    unsigned int strength = 256;
    OSSL_PARAM params[4];

    EVP_RAND_free(rand);
    memset(entropy, seed, sizeof(entropy));
    memset(nonce, seed ^ 0x5a, sizeof(nonce));
    params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, entropy,
                                                  sizeof(entropy));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, nonce,
                                                  sizeof(nonce));
    params[3] = OSSL_PARAM_construct_end();
    EVP_RAND_instantiate(parent, 256, 0, NULL, 0, params);
    rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    ctx = EVP_RAND_CTX_new(rand, parent);
    EVP_RAND_free(rand);
    EVP_RAND_CTX_free(parent);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, params)) {
        EVP_RAND_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static void known_rand(unsigned char seed)
{
    RAND_set0_public(NULL, known_drbg(seed));
    RAND_set0_private(NULL, known_drbg(seed + 1));
}

/* Octets as their length, first octets, and the start of their SHA-256. */
static void octets(const char *label, const unsigned char *p, size_t n)
{
    unsigned char d[32];
    unsigned int dl = 0;
    size_t i;

    EVP_Digest(p, n, d, &dl, EVP_sha256(), NULL);
    printf("  %s (%zu):", label, n);
    for (i = 0; i < n && i < 8; i++)
        printf("%02x", p[i]);
    printf(" sha256 ");
    for (i = 0; i < 8; i++)
        printf("%02x", d[i]);
    printf("\n");
}

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static void print_names(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

/* A key of a group (by name), or of a DH's parameters, generated through the provider. */
static EVP_PKEY *gen_group(const char *type, const char *group)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    OSSL_PARAM ps[2];
    EVP_PKEY *k = NULL;

    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0);
    ps[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_keygen_init(c);
    EVP_PKEY_CTX_set_params(c, ps);
    EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

/* Derives with a context made for `k` and `peer`; prints the result and the secret. */
static void derive(const char *label, EVP_PKEY_CTX *c, size_t room)
{
    unsigned char out[1100];
    size_t n = 0;
    int r;

    r = EVP_PKEY_derive(c, NULL, &n);
    printf("  %s: size %d %zu", label, r, n);
    n = room;
    r = EVP_PKEY_derive(c, out, &n);
    printf(" derive %d %zu\n", r, n);
    if (r > 0)
        octets("secret", out, n);
    errors();
}

static EVP_PKEY_CTX *derive_ctx(EVP_PKEY *k, EVP_PKEY *peer, const OSSL_PARAM *ps)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    int r1, r2;

    r1 = EVP_PKEY_derive_init_ex(c, ps);
    r2 = peer != NULL ? EVP_PKEY_derive_set_peer(c, peer) : -9;
    printf("  init %d peer %d\n", r1, r2);
    errors();
    return c;
}

static void get_ctx(EVP_PKEY_CTX *c)
{
    char type[80] = "?", md[80] = "?", cek[80] = "?";
    size_t outlen = 99;
    unsigned char *ukm = NULL;
    OSSL_PARAM ps[6];
    int r;

    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, type, sizeof(type));
    ps[1] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, md, sizeof(md));
    ps[2] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &outlen);
    ps[3] = OSSL_PARAM_construct_octet_ptr(OSSL_EXCHANGE_PARAM_KDF_UKM, (void **)&ukm, 0);
    ps[4] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, cek, sizeof(cek));
    ps[5] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(c, ps);
    printf("  get %d: type '%s' digest '%s' outlen %zu ukm %zu cek '%s'\n", r, type, md,
           outlen, ps[3].return_size, cek);
    if (ukm != NULL && ps[3].return_size > 0)
        octets("ukm", ukm, ps[3].return_size);
    errors();
}

static void test_exchange(void)
{
    EVP_KEYEXCH *x = EVP_KEYEXCH_fetch(NULL, "DH", NULL);
    EVP_PKEY *a, *b, *c3, *dx;
    EVP_PKEY_CTX *c, *c2;

    check(x != NULL, "the DH exchange");
    printf("  names:");
    EVP_KEYEXCH_names_do_all(x, print_names, NULL);
    printf("\n  description: %s\n", EVP_KEYEXCH_get0_description(x));
    names("settable", EVP_KEYEXCH_settable_ctx_params(x));
    names("gettable", EVP_KEYEXCH_gettable_ctx_params(x));
    EVP_KEYEXCH_free(x);

    known_rand(21);
    a = gen_group("DH", "ffdhe2048");
    b = gen_group("DH", "ffdhe2048");
    c3 = gen_group("DH", "ffdhe3072");
    dx = gen_group("DHX", "ffdhe2048");
    check(a != NULL && b != NULL && c3 != NULL && dx != NULL, "keys");

    c = derive_ctx(a, b, NULL);
    derive("a with b", c, 256);
    derive("into 255", c, 255);
    derive("into 300", c, 300);
    get_ctx(c);
    c2 = EVP_PKEY_CTX_dup(c);
    derive("the copy", c2, 256);
    EVP_PKEY_CTX_free(c2);
    printf("  pad %d", EVP_PKEY_CTX_set_dh_pad(c, 1));
    errors();
    derive("padded", c, 256);
    EVP_PKEY_CTX_free(c);
    c = derive_ctx(b, a, NULL);
    derive("b with a", c, 256);
    EVP_PKEY_CTX_free(c);

    printf(" peers:\n");
    c = derive_ctx(a, c3, NULL);
    derive("another group", c, 256);
    EVP_PKEY_CTX_free(c);
    c = derive_ctx(a, dx, NULL);
    derive("a DHX key", c, 256);
    EVP_PKEY_CTX_free(c);
    c = derive_ctx(dx, a, NULL);
    derive("from the DHX key", c, 256);
    EVP_PKEY_CTX_free(c);
    c = derive_ctx(a, NULL, NULL);
    derive("no peer", c, 256);
    EVP_PKEY_CTX_free(c);

    printf(" X9.42's KDF:\n");
    {
        OSSL_PARAM ps[6];
        size_t outlen = 32;
        unsigned char ukm[] = "some user keying material";
        unsigned int pad = 1;

        ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
                                                 OSSL_KDF_NAME_X942KDF_ASN1, 0);
        ps[1] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, "SHA256", 0);
        ps[2] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &outlen);
        ps[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, "id-aes128-wrap", 0);
        ps[4] = OSSL_PARAM_construct_end();
        c = derive_ctx(a, b, ps);
        get_ctx(c);
        derive("kdf", c, 32);
        derive("kdf into 31", c, 31);
        derive("kdf into 64", c, 64);
        ps[0] = OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, ukm,
                                                  sizeof(ukm) - 1);
        ps[1] = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad);
        ps[2] = OSSL_PARAM_construct_end();
        printf("  set %d\n", EVP_PKEY_CTX_set_params(c, ps));
        get_ctx(c);
        derive("kdf with ukm", c, 32);
        c2 = EVP_PKEY_CTX_dup(c);
        derive("its copy", c2, 32);
        EVP_PKEY_CTX_free(c2);
        ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, "", 0);
        ps[1] = OSSL_PARAM_construct_end();
        printf("  no cek %d\n", EVP_PKEY_CTX_set_params(c, ps));
        derive("kdf without an algorithm", c, 32);
        ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, "nonsense", 0);
        printf("  bad cek %d\n", EVP_PKEY_CTX_set_params(c, ps));
        derive("kdf with a bad algorithm", c, 32);
        ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, "SHAKE256", 0);
        printf("  xof %d", EVP_PKEY_CTX_set_params(c, ps));
        errors();
        ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, "nope", 0);
        printf("  unknown digest %d", EVP_PKEY_CTX_set_params(c, ps));
        errors();
        get_ctx(c);
        ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, "X963KDF", 0);
        printf("  bad type %d", EVP_PKEY_CTX_set_params(c, ps));
        errors();
        ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, "", 0);
        printf("  no type %d", EVP_PKEY_CTX_set_params(c, ps));
        errors();
        derive("plain again", c, 256);
        EVP_PKEY_CTX_free(c);
    }

    printf(" the typed setters and getters:\n");
    {
        ASN1_OBJECT *oid = OBJ_nid2obj(NID_id_aes256_wrap), *got = NULL;
        unsigned char *ukm = OPENSSL_malloc(5), *gu = NULL;
        const EVP_MD *md = NULL;
        int outlen = 0;

        memcpy(ukm, "hello", 5);
        c = derive_ctx(a, b, NULL);
        printf("  type %d", EVP_PKEY_CTX_set_dh_kdf_type(c, EVP_PKEY_DH_KDF_X9_42));
        printf(" get %d", EVP_PKEY_CTX_get_dh_kdf_type(c));
        printf(" md %d", EVP_PKEY_CTX_set_dh_kdf_md(c, EVP_sha384()));
        printf(" outlen %d", EVP_PKEY_CTX_set_dh_kdf_outlen(c, 40));
        printf(" ukm %d", EVP_PKEY_CTX_set0_dh_kdf_ukm(c, ukm, 5));
        printf(" oid %d\n", EVP_PKEY_CTX_set0_dh_kdf_oid(c, OBJ_dup(oid)));
        errors();
        printf("  get md %d %s", EVP_PKEY_CTX_get_dh_kdf_md(c, &md),
               md != NULL ? EVP_MD_get0_name(md) : "(none)");
        printf(" outlen %d %d", EVP_PKEY_CTX_get_dh_kdf_outlen(c, &outlen), outlen);
        printf(" ukm %d", EVP_PKEY_CTX_get0_dh_kdf_ukm(c, &gu));
        printf(" oid %d %d\n", EVP_PKEY_CTX_get0_dh_kdf_oid(c, &got), OBJ_obj2nid(got));
        errors();
        get_ctx(c);
        derive("set by the setters", c, 40);
        printf("  bad type %d", EVP_PKEY_CTX_set_dh_kdf_type(c, 7));
        printf(" bad outlen %d\n", EVP_PKEY_CTX_set_dh_kdf_outlen(c, 0));
        errors();
        ASN1_OBJECT_free(got);
        EVP_PKEY_CTX_free(c);
    }
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    EVP_PKEY_free(c3);
    EVP_PKEY_free(dx);
}

/* A DH method that counts the computations it does. */
static int (*orig_compute)(unsigned char *, const BIGNUM *, DH *);
static int computed = 0;

static int count_compute(unsigned char *key, const BIGNUM *pub, DH *dh)
{
    computed++;
    return orig_compute(key, pub, dh);
}

static EVP_PKEY *legacy_key(int nid, const DH_METHOD *meth)
{
    DH *dh = DH_new_by_nid(nid);
    EVP_PKEY *k = EVP_PKEY_new();

    DH_set_method(dh, meth);
    DH_generate_key(dh);
    EVP_PKEY_set1_DH(k, dh);
    DH_free(dh);
    return k;
}

static void test_legacy(void)
{
    DH_METHOD *meth = DH_meth_dup(DH_OpenSSL());
    EVP_PKEY *a, *b, *pa, *pb;
    EVP_PKEY_CTX *c;

    orig_compute = DH_meth_get_compute_key(meth);
    DH_meth_set_compute_key(meth, count_compute);
    known_rand(31);
    a = legacy_key(NID_ffdhe2048, meth);
    b = legacy_key(NID_ffdhe2048, meth);
    check(a != NULL && b != NULL, "legacy keys");
    printf("  ids %d %d\n", EVP_PKEY_get_id(a), EVP_PKEY_get_id(b));

    c = derive_ctx(a, b, NULL);
    derive("legacy", c, 256);
    /* Not into less room: OpenSSL's writes the whole secret (docs/DEVIATIONS.md). */
    printf("  pad %d", EVP_PKEY_CTX_set_dh_pad(c, 1));
    derive("padded", c, 256);
    printf("  computed %d\n", computed);
    {
        const EVP_MD *md = NULL;
        unsigned char *ukm = OPENSSL_malloc(3), *gu = NULL;
        ASN1_OBJECT *got = NULL;
        int outlen = -1;

#define CTRL(cmd, p1, p2) EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_DERIVE, cmd, p1, p2)
        memcpy(ukm, "abc", 3);
        printf("  typed setter %d", EVP_PKEY_CTX_set_dh_kdf_type(c, EVP_PKEY_DH_KDF_X9_42));
        errors();
        printf("  type %d", CTRL(EVP_PKEY_CTRL_DH_KDF_TYPE, EVP_PKEY_DH_KDF_X9_42, NULL));
        printf(" get %d", CTRL(EVP_PKEY_CTRL_DH_KDF_TYPE, -2, NULL));
        printf(" bad %d", CTRL(EVP_PKEY_CTRL_DH_KDF_TYPE, 5, NULL));
        errors();
        derive("kdf without its settings", c, 32);
        printf("  md %d", CTRL(EVP_PKEY_CTRL_DH_KDF_MD, 0, (void *)EVP_sha256()));
        printf(" outlen %d", CTRL(EVP_PKEY_CTRL_DH_KDF_OUTLEN, 32, NULL));
        printf(" bad %d", CTRL(EVP_PKEY_CTRL_DH_KDF_OUTLEN, 0, NULL));
        derive("kdf without an OID", c, 32);
        printf("  oid %d", CTRL(EVP_PKEY_CTRL_DH_KDF_OID, 0, OBJ_dup(OBJ_nid2obj(NID_id_aes128_wrap))));
        printf(" ukm %d\n", CTRL(EVP_PKEY_CTRL_DH_KDF_UKM, 3, ukm));
        errors();
        printf("  get md %d %s", CTRL(EVP_PKEY_CTRL_GET_DH_KDF_MD, 0, &md),
               md != NULL ? EVP_MD_get0_name(md) : "(none)");
        printf(" outlen %d %d", CTRL(EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, 0, &outlen), outlen);
        printf(" ukm %d", CTRL(EVP_PKEY_CTRL_GET_DH_KDF_UKM, 0, &gu));
        if (gu != NULL)
            printf(" %.3s", gu);
        printf(" oid %d %d\n", CTRL(EVP_PKEY_CTRL_GET_DH_KDF_OID, 0, &got), OBJ_obj2nid(got));
        errors();
        derive("kdf", c, 32);
        derive("kdf into 33", c, 33);
        derive("kdf into 31", c, 31);
        printf("  no ukm %d", CTRL(EVP_PKEY_CTRL_DH_KDF_UKM, 0, NULL));
        derive("kdf without ukm", c, 32);
        printf("  other ctrls: peer %d nonsense %d pad %d", CTRL(EVP_PKEY_CTRL_PEER_KEY, 0, NULL),
               CTRL(EVP_PKEY_ALG_CTRL + 100, 0, NULL), CTRL(EVP_PKEY_CTRL_DH_PAD, 1, NULL));
        printf(" plain %d\n", CTRL(EVP_PKEY_CTRL_DH_KDF_TYPE, EVP_PKEY_DH_KDF_NONE, NULL));
        errors();
        derive("plain again", c, 256);
        printf("  ctrl str pad %d", EVP_PKEY_CTX_ctrl_str(c, "dh_pad", "0"));
        printf(" nonsense %d\n", EVP_PKEY_CTX_ctrl_str(c, "nonsense", "1"));
        errors();
#undef CTRL
    }
    EVP_PKEY_CTX_free(c);

    /* The same keys' numbers as provided keys: the same secret. */
    pa = EVP_PKEY_dup(a);
    pb = EVP_PKEY_dup(b);
    {
        DH *d = EVP_PKEY_get1_DH(a);
        EVP_PKEY *p2 = EVP_PKEY_new();
        DH *d2 = DH_new_by_nid(NID_ffdhe2048);

        DH_set0_key(d2, BN_dup(DH_get0_pub_key(d)), BN_dup(DH_get0_priv_key(d)));
        EVP_PKEY_set1_DH(p2, d2);
        c = derive_ctx(p2, b, NULL);
        derive("a's numbers with an OpenSSL DH", c, 256);
        EVP_PKEY_CTX_free(c);
        EVP_PKEY_free(p2);
        DH_free(d2);
        DH_free(d);
    }
    printf("  computed %d\n", computed);
    EVP_PKEY_free(pa);
    EVP_PKEY_free(pb);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    DH_meth_free(meth);
}

static void gen_with(int type, const char *label, int (*set)(EVP_PKEY_CTX *))
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(type, NULL), *kc;
    EVP_PKEY *p = NULL, *k = NULL;
    int r1, r2, r3;

    r1 = EVP_PKEY_paramgen_init(c);
    /* Small primes, for the generations a refused setting falls back to. */
    EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, 512, NULL);
    r2 = set != NULL ? set(c) : -9;
    r3 = EVP_PKEY_paramgen(c, &p);
    printf("  %s: %d %d %d", label, r1, r2, r3);
    if (p != NULL) {
        const DH *d = EVP_PKEY_get0_DH(p);

        printf(" id %d bits %d q %d nid %d length %ld", EVP_PKEY_get_id(p), EVP_PKEY_get_bits(p),
               DH_get0_q(d) != NULL ? BN_num_bits(DH_get0_q(d)) : -1, DH_get_nid(d),
               DH_get_length(d));
        {
            unsigned char buf[1100];
            int n = BN_bn2bin(DH_get0_p(d), buf);

            printf("\n");
            octets("p", buf, (size_t)n);
        }
        kc = EVP_PKEY_CTX_new(p, NULL);
        printf("  keygen %d", EVP_PKEY_keygen_init(kc));
        printf(" %d", EVP_PKEY_keygen(kc, &k));
        if (k != NULL)
            printf(" id %d check %d", EVP_PKEY_get_id(k),
                   DH_check_pub_key_ex(EVP_PKEY_get0_DH(k), DH_get0_pub_key(EVP_PKEY_get0_DH(k))));
        printf("\n");
        EVP_PKEY_CTX_free(kc);
    } else {
        printf("\n");
    }
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);
    EVP_PKEY_CTX_free(c);
}

static int set_nid(EVP_PKEY_CTX *c)
{
    return EVP_PKEY_CTX_set_dh_nid(c, NID_ffdhe3072);
}

static int set_5114(EVP_PKEY_CTX *c)
{
    return EVP_PKEY_CTX_set_dh_rfc5114(c, 2);
}

static int set_safe(EVP_PKEY_CTX *c)
{
    return EVP_PKEY_CTX_set_dh_paramgen_prime_len(c, 512) * 10
           + EVP_PKEY_CTX_set_dh_paramgen_generator(c, 5);
}

#define GCTRL(cmd, p1) EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_PARAMGEN, cmd, p1, NULL)

static int set_fips(EVP_PKEY_CTX *c)
{
    return GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, DH_PARAMGEN_TYPE_FIPS_186_4) * 100
           + GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, 1024) * 10
           + GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, 160);
}

static int set_fips2(EVP_PKEY_CTX *c)
{
    return GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, DH_PARAMGEN_TYPE_FIPS_186_2) * 100
           + GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, 1024) * 10
           + GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, 5);
}

static int set_fips_default_q(EVP_PKEY_CTX *c)
{
    return GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, DH_PARAMGEN_TYPE_FIPS_186_4) * 10
           + GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, 1024);
}

static int set_bad(EVP_PKEY_CTX *c)
{
    return GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, 3) * 1000
           + GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, 100) * 100
           + GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, 160) * 10
           + GCTRL(EVP_PKEY_CTRL_DH_RFC5114, 4);
}

static int set_ctrl_nids(EVP_PKEY_CTX *c)
{
    return GCTRL(EVP_PKEY_CTRL_DH_RFC5114, 3) * 100 + GCTRL(EVP_PKEY_CTRL_DH_NID, NID_ffdhe2048) * 10
           + GCTRL(EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, 3);
}

static int set_strs(EVP_PKEY_CTX *c)
{
    return EVP_PKEY_CTX_ctrl_str(c, "dh_param", "ffdhe2048") * 100
           + EVP_PKEY_CTX_ctrl_str(c, "dh_rfc5114", "1") * 10
           + EVP_PKEY_CTX_ctrl_str(c, "dh_paramgen_type", "1");
}

static int set_bad_name(EVP_PKEY_CTX *c)
{
    return EVP_PKEY_CTX_ctrl_str(c, "dh_param", "nope");
}

static void test_gen(void)
{
    EVP_PKEY_METHOD *m = EVP_PKEY_meth_new(EVP_PKEY_DH, 0);
    EVP_PKEY_METHOD *mx = EVP_PKEY_meth_new(EVP_PKEY_DHX, 0);
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL;

    EVP_PKEY_meth_copy(m, EVP_PKEY_meth_find(EVP_PKEY_DH));
    EVP_PKEY_meth_copy(mx, EVP_PKEY_meth_find(EVP_PKEY_DHX));
    check(EVP_PKEY_meth_add0(m) == 1 && EVP_PKEY_meth_add0(mx) == 1,
          "applications' copies of the DH methods");
    known_rand(41);
    gen_with(EVP_PKEY_DH, "named", set_nid);
    gen_with(EVP_PKEY_DH, "rfc5114", set_5114);
    gen_with(EVP_PKEY_DHX, "dhx named", set_nid);
    gen_with(EVP_PKEY_DH, "safe prime", set_safe);
    gen_with(EVP_PKEY_DHX, "fips186_4", set_fips);
    gen_with(EVP_PKEY_DHX, "fips186_2", set_fips2);
    gen_with(EVP_PKEY_DHX, "fips186_4 default q", set_fips_default_q);
    gen_with(EVP_PKEY_DH, "bad", set_bad);
    gen_with(EVP_PKEY_DH, "rfc5114 by ctrl", set_ctrl_nids);
    gen_with(EVP_PKEY_DH, "strings", set_strs);
    gen_with(EVP_PKEY_DH, "bad name", set_bad_name);

    c = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    printf("  keygen without parameters %d", EVP_PKEY_keygen_init(c));
    printf(" %d", EVP_PKEY_keygen(c, &k));
    errors();
    printf("  dup %d\n", EVP_PKEY_CTX_dup(c) != NULL);
    errors();
    printf("  nid %d", EVP_PKEY_CTX_set_dh_nid(c, NID_ffdhe2048));
    printf(" again %d", EVP_PKEY_CTX_set_dh_nid(c, NID_ffdhe3072));
    printf(" keygen %d", EVP_PKEY_keygen(c, &k));
    if (k != NULL)
        printf(" bits %d", EVP_PKEY_get_bits(k));
    printf("\n");
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

int main(void)
{
    test_exchange();
    test_legacy();
    test_gen();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
