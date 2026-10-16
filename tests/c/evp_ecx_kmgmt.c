/*
 * Conformance test for the default provider's X25519 and ED25519 key managers
 * (EVP_PKEY-X25519(7), EVP_PKEY-ED25519(7), provider-keymgmt(7)), in TAP format: their names and
 * parameter lists; raw keys (private and public, of every length); keys from data (each part
 * alone, both, mismatched, of the wrong length); every gettable parameter; exports; the
 * encoded public key and properties set; the checks (the pair, public, private); generation
 * (random, from an RFC 9180 DHKEM input key for X25519, with a group name); comparison and
 * copies.
 *
 * The fixed keys are RFC 7748's and RFC 8032's; generated keys are random, so only what they
 * have and whether they check is printed.
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

static void dump(const OSSL_PARAM *p, int got)
{
    for (; p != NULL && p->key != NULL; p++) {
        size_t n = got ? p->return_size : p->data_size;

        if (got && p->return_size == OSSL_PARAM_UNMODIFIED)
            continue;
        printf("  %s:", p->key);
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: {
            int v = 0;

            OSSL_PARAM_get_int(p, &v);
            printf(" int %d\n", v);
            break;
        }
        case OSSL_PARAM_UTF8_STRING:
            printf(" utf8 [%.*s]\n", (int)n, (const char *)p->data);
            break;
        case OSSL_PARAM_OCTET_STRING:
            printf("\n");
            hex("octets", p->data, n);
            break;
        default:
            printf(" type %u\n", p->data_type);
        }
    }
}

static unsigned char *octets(const char *h, size_t *len)
{
    long n = 0;
    unsigned char *p = OPENSSL_hexstr2buf(h, &n);

    *len = (size_t)n;
    return p;
}

static void get_all(EVP_PKEY *k)
{
    const OSSL_PARAM *g = EVP_PKEY_gettable_params(k);
    static long long bufs[16][16];
    OSSL_PARAM ps[16];
    size_t n;

    for (n = 0; g != NULL && g[n].key != NULL && n < 15; n++) {
        ps[n] = g[n];
        ps[n].data = bufs[n];
        ps[n].data_size = ps[n].data_type == OSSL_PARAM_INTEGER ? sizeof(int) : sizeof(bufs[n]);
        ps[n].return_size = OSSL_PARAM_UNMODIFIED;
    }
    ps[n] = OSSL_PARAM_construct_end();
    printf("  get_params: %d\n", EVP_PKEY_get_params(k, ps));
    errors();
    dump(ps, 1);
}

static void checks(EVP_PKEY *k, const char *what)
{
    EVP_PKEY_CTX *v = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

    printf("  %s: check %d", what, EVP_PKEY_check(v));
    printf(" public %d", EVP_PKEY_public_check(v));
    printf(" private %d", EVP_PKEY_private_check(v));
    printf(" pairwise %d", EVP_PKEY_pairwise_check(v));
    printf(" params %d\n", EVP_PKEY_param_check(v));
    errors();
    EVP_PKEY_CTX_free(v);
}

/* A key from data: the private and public keys (either may be NULL). */
static EVP_PKEY *fromdata(const char *type, int selection, const char *priv, const char *pub)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    OSSL_PARAM ps[3], *p = ps;
    unsigned char *d = NULL, *q = NULL;
    size_t dl = 0, ql = 0;
    EVP_PKEY *k = NULL;
    int r;

    if (priv != NULL) {
        d = octets(priv, &dl);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, d, dl);
    }
    if (pub != NULL) {
        q = octets(pub, &ql);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, q, ql);
    }
    *p = OSSL_PARAM_construct_end();
    r = EVP_PKEY_fromdata_init(c);
    r = r * 10 + EVP_PKEY_fromdata(c, &k, selection, ps);
    printf("  fromdata %s %x priv %zu pub %zu: %d\n", type, (unsigned)selection, dl, ql, r);
    errors();
    OPENSSL_free(d);
    OPENSSL_free(q);
    EVP_PKEY_CTX_free(c);
    return k;
}

/* RFC 7748 6.1's Alice and RFC 8032 7.1 TEST 2. */
static const char X_PRIV[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char X_PUB[] = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
static const char E_PRIV[] = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
static const char E_PUB[] = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

static void test_keymgmt(const char *type)
{
    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, type, NULL);

    check(km != NULL, type);
    if (km == NULL) {
        errors();
        return;
    }
    printf("  names:");
    EVP_KEYMGMT_names_do_all(km, print_name, NULL);
    printf("\n  description: %s\n", EVP_KEYMGMT_get0_description(km));
    names("gettable", EVP_KEYMGMT_gettable_params(km));
    names("settable", EVP_KEYMGMT_settable_params(km));
    names("gen settable", EVP_KEYMGMT_gen_settable_params(km));
    EVP_KEYMGMT_free(km);
}

static void test_raw(const char *type, int id, const char *priv, const char *pub)
{
    size_t dl, ql, n;
    unsigned char *d = octets(priv, &dl), *q = octets(pub, &ql);
    unsigned char out[64];
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(id, NULL, d, dl);
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key_ex(NULL, type, NULL, q, ql);
    EVP_PKEY *bad;
    char md[20] = "?";
    int r;

    check(k != NULL && p != NULL, "raw keys");
    errors();
    n = sizeof(out);
    r = EVP_PKEY_get_raw_public_key(k, out, &n);
    printf("  public from the private key %d", r);
    hex("", out, n);
    n = sizeof(out);
    r = EVP_PKEY_get_raw_private_key(p, out, &n);
    printf("  private of a public key %d\n", r);
    errors();
    printf("  id %d type %s bits %d security %d size %d eq %d\n", EVP_PKEY_get_id(k),
           EVP_PKEY_get0_type_name(k), EVP_PKEY_get_bits(k), EVP_PKEY_get_security_bits(k),
           EVP_PKEY_get_size(k), EVP_PKEY_eq(k, p));
    r = EVP_PKEY_get_default_digest_name(k, md, sizeof(md));
    printf("  default digest %d [%s]\n", r, md);
    errors();
    get_all(k);
    get_all(p);
    checks(k, "private");
    checks(p, "public");
    bad = EVP_PKEY_new_raw_private_key(id, NULL, d, dl - 1);
    printf("  a short private key %s\n", bad == NULL ? "refused" : "taken");
    errors();
    EVP_PKEY_free(bad);
    bad = EVP_PKEY_new_raw_public_key(id, NULL, q, ql + 1);
    printf("  a long public key %s\n", bad == NULL ? "refused" : "taken");
    errors();
    EVP_PKEY_free(bad);
    {
        EVP_PKEY *dup = EVP_PKEY_dup(k);

        printf("  dup %d eq %d\n", dup != NULL, EVP_PKEY_eq(k, dup));
        EVP_PKEY_free(dup);
    }
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);
    OPENSSL_free(d);
    OPENSSL_free(q);
}

static void test_fromdata(const char *type, const char *priv, const char *pub)
{
    EVP_PKEY *both = fromdata(type, EVP_PKEY_KEYPAIR, priv, pub);
    EVP_PKEY *priv_only = fromdata(type, EVP_PKEY_KEYPAIR, priv, NULL);
    EVP_PKEY *pub_only = fromdata(type, EVP_PKEY_PUBLIC_KEY, NULL, pub);
    EVP_PKEY *wrong = fromdata(type, EVP_PKEY_KEYPAIR, priv, X_PUB[0] == pub[0] ? E_PUB : X_PUB);
    EVP_PKEY *k;
    OSSL_PARAM *out = NULL;

    k = fromdata(type, EVP_PKEY_KEYPAIR, NULL, NULL);
    EVP_PKEY_free(k);
    k = fromdata(type, EVP_PKEY_PUBLIC_KEY, priv, NULL);
    EVP_PKEY_free(k);
    k = fromdata(type, EVP_PKEY_KEY_PARAMETERS, priv, pub);
    EVP_PKEY_free(k);
    k = fromdata(type, EVP_PKEY_KEYPAIR, "0102", NULL);
    EVP_PKEY_free(k);
    k = fromdata(type, EVP_PKEY_KEYPAIR, NULL, "0102");
    EVP_PKEY_free(k);
    if (both != NULL) {
        printf("  todata %d\n", EVP_PKEY_todata(both, EVP_PKEY_KEYPAIR, &out));
        dump(out, 0);
        OSSL_PARAM_free(out);
        out = NULL;
        printf("  todata public %d\n", EVP_PKEY_todata(both, EVP_PKEY_PUBLIC_KEY, &out));
        dump(out, 0);
        OSSL_PARAM_free(out);
        out = NULL;
        printf("  todata parameters %d\n", EVP_PKEY_todata(both, EVP_PKEY_KEY_PARAMETERS, &out));
        errors();
        OSSL_PARAM_free(out);
        out = NULL;
    }
    if (priv_only != NULL)
        printf("  derived public key eq %d\n", EVP_PKEY_eq(both, priv_only));
    if (pub_only != NULL) {
        printf("  public eq %d parameters eq %d\n", EVP_PKEY_eq(both, pub_only),
               EVP_PKEY_parameters_eq(both, pub_only));
        checks(pub_only, "public only");
    }
    if (wrong != NULL)
        checks(wrong, "mismatched");
    {
        unsigned char q[40];
        size_t ql;
        unsigned char *qq = octets(X_PUB, &ql);
        OSSL_PARAM s[3];
        int r;

        memcpy(q, qq, ql);
        OPENSSL_free(qq);
        s[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, q, ql);
        s[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, "provider=default", 0);
        s[2] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_set_params(both, s);
        printf("  set encoded public key and properties %d\n", r);
        errors();
        checks(both, "after the set");
        s[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, q, 31);
        s[1] = OSSL_PARAM_construct_end();
        printf("  31 octets %d\n", EVP_PKEY_set_params(both, s));
        errors();
    }
    EVP_PKEY_free(both);
    EVP_PKEY_free(priv_only);
    EVP_PKEY_free(pub_only);
    EVP_PKEY_free(wrong);
}

static void test_gen(const char *type)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *k = NULL;
    int r;

    r = EVP_PKEY_keygen_init(c);
    r = r * 10 + EVP_PKEY_keygen(c, &k);
    check(r == 11 && k != NULL, "a generated key");
    errors();
    if (k != NULL)
        checks(k, "generated");
    EVP_PKEY_free(k);
    k = NULL;
    r = EVP_PKEY_paramgen_init(c);
    r = r * 10 + EVP_PKEY_paramgen(c, &k);
    printf("  paramgen %d", r);
    if (k != NULL) {
        size_t n = 0;

        printf(" has public %d", EVP_PKEY_get_raw_public_key(k, NULL, &n));
    }
    printf("\n");
    errors();
    EVP_PKEY_free(k);
    k = NULL;
    {
        static const char *const groups[] = { "x25519", "X25519", "x448", "P-256" };
        size_t i;

        for (i = 0; i < 4; i++) {
            OSSL_PARAM p[2];

            p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                    (char *)groups[i], 0);
            p[1] = OSSL_PARAM_construct_end();
            r = EVP_PKEY_keygen_init(c);
            r = r * 10 + EVP_PKEY_CTX_set_params(c, p);
            printf("  group %s: %d\n", groups[i], r);
            errors();
        }
    }
    {
        /* RFC 9180 A.1.1's ikmE, and one too short. */
        size_t il;
        unsigned char *ikm =
            octets("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234", &il);
        size_t lens[2];
        size_t i;

        lens[0] = il;
        lens[1] = il - 1;
        for (i = 0; i < 2; i++) {
            OSSL_PARAM p[2];

            p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM, ikm, lens[i]);
            p[1] = OSSL_PARAM_construct_end();
            r = EVP_PKEY_keygen_init(c);
            r = r * 10 + EVP_PKEY_CTX_set_params(c, p);
            r = r * 10 + EVP_PKEY_keygen(c, &k);
            printf("  DHKEM from %zu octets: %d\n", lens[i], r);
            errors();
            if (k != NULL) {
                OSSL_PARAM *out = NULL;

                EVP_PKEY_todata(k, EVP_PKEY_KEYPAIR, &out);
                dump(out, 0);
                OSSL_PARAM_free(out);
            }
            EVP_PKEY_free(k);
            k = NULL;
        }
        OPENSSL_free(ikm);
    }
    EVP_PKEY_CTX_free(c);
}

int main(void)
{
    test_keymgmt("X25519");
    test_keymgmt("ED25519");
    test_raw("X25519", EVP_PKEY_X25519, X_PRIV, X_PUB);
    test_raw("ED25519", EVP_PKEY_ED25519, E_PRIV, E_PUB);
    test_fromdata("X25519", X_PRIV, X_PUB);
    test_fromdata("ED25519", E_PRIV, E_PUB);
    test_gen("X25519");
    test_gen("ED25519");
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
