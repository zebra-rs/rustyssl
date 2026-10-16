/*
 * Conformance test for the legacy ECX key methods (EVP_PKEY_meth_find(3) and
 * EVP_PKEY_asn1_find(3) for X25519 and ED25519; OpenSSL's ecx_meth.c), in TAP format. The
 * built-in methods' functions are called directly on contexts of provided keys (which they
 * see through the keys' legacy copies): Ed25519 signing and verifying with RFC 8032's vectors,
 * X25519 deriving with RFC 7748's, and the ctrls. (A derive into less room than the secret, which
 * OpenSSL overruns, is refused here: docs/DEVIATIONS.md.) Then an application's copies of the methods
 * generate legacy keys, whose raw keys, sizes, default digest, printouts, copies, comparisons,
 * signatures, and shared secrets match those of provided keys made from the same octets.
 *
 * The legacy keys are generated with an application's RAND_METHOD that counts, so they're
 * the same every run.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
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

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
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

static EVP_PKEY *raw(int id, const char *h, int priv)
{
    long n = 0;
    unsigned char *b = OPENSSL_hexstr2buf(h, &n);
    EVP_PKEY *k = priv ? EVP_PKEY_new_raw_private_key(id, NULL, b, (size_t)n)
                       : EVP_PKEY_new_raw_public_key(id, NULL, b, (size_t)n);

    OPENSSL_free(b);
    return k;
}

static const char A_PRIV[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char B_PUB[] = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
static const char T2_PRIV[] = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

typedef int (*digestsign_fn)(EVP_MD_CTX *, unsigned char *, size_t *, const unsigned char *,
                             size_t);
typedef int (*digestverify_fn)(EVP_MD_CTX *, const unsigned char *, size_t,
                               const unsigned char *, size_t);
typedef int (*ctrl_fn)(EVP_PKEY_CTX *, int, int, void *);
typedef int (*ctrl_str_fn)(EVP_PKEY_CTX *, const char *, const char *);
typedef int (*derive_fn)(EVP_PKEY_CTX *, unsigned char *, size_t *);
typedef int (*init_fn)(EVP_PKEY_CTX *);
typedef int (*keygen_fn)(EVP_PKEY_CTX *, EVP_PKEY *);

static void test_ed25519_method(void)
{
    const EVP_PKEY_METHOD *m = EVP_PKEY_meth_find(EVP_PKEY_ED25519);
    digestsign_fn ds = NULL;
    digestverify_fn dv = NULL;
    ctrl_fn ctrl = NULL;
    ctrl_str_fn ctrl_str = NULL;
    keygen_fn kg = NULL;
    init_fn kgi = NULL;
    EVP_PKEY *k = raw(EVP_PKEY_ED25519, T2_PRIV, 1);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    unsigned char sig[100], msg[1] = { 0x72 };
    size_t len;
    int id = 0, flags = 0, r;

    EVP_PKEY_meth_get0_info(&id, &flags, m);
    printf("  id %d flags %d\n", id, flags);
    EVP_PKEY_meth_get_digestsign(m, &ds);
    EVP_PKEY_meth_get_digestverify(m, &dv);
    EVP_PKEY_meth_get_ctrl(m, &ctrl, &ctrl_str);
    EVP_PKEY_meth_get_keygen(m, &kgi, &kg);
    printf("  functions: digestsign %d digestverify %d ctrl %d ctrl_str %d keygen %d %d\n",
           ds != NULL, dv != NULL, ctrl != NULL, ctrl_str != NULL, kgi != NULL, kg != NULL);
    check(ds != NULL && dv != NULL && ctrl != NULL, "ED25519's method");
    if (ds == NULL || dv == NULL || ctrl == NULL)
        return;
    EVP_MD_CTX_set_pkey_ctx(mc, c);
    len = 0;
    r = ds(mc, NULL, &len, msg, 1);
    printf("  size %d %zu\n", r, len);
    len = 63;
    r = ds(mc, sig, &len, msg, 1);
    printf("  into 63 octets %d\n", r);
    errors();
    len = sizeof(sig);
    r = ds(mc, sig, &len, msg, 1);
    check(r == 1, "RFC 8032's TEST 2");
    hex("sig", sig, len);
    errors();
    printf("  verify %d", dv(mc, sig, len, msg, 1));
    printf(" a 63-octet one %d", dv(mc, sig, 63, msg, 1));
    sig[63] ^= 0x40;
    printf(" changed %d\n", dv(mc, sig, len, msg, 1));
    errors();

    printf("  ctrl md NULL %d", ctrl(c, EVP_PKEY_CTRL_MD, 0, NULL));
    printf(" md_null %d", ctrl(c, EVP_PKEY_CTRL_MD, 0, (void *)EVP_md_null()));
    printf(" sha256 %d", ctrl(c, EVP_PKEY_CTRL_MD, 0, (void *)EVP_sha256()));
    printf(" digestinit %d", ctrl(c, EVP_PKEY_CTRL_DIGESTINIT, 0, NULL));
    printf(" peer %d", ctrl(c, EVP_PKEY_CTRL_PEER_KEY, 0, NULL));
    printf(" other %d\n", ctrl(c, EVP_PKEY_CTRL_GET_MD, 0, NULL));
    errors();
    EVP_MD_CTX_set_pkey_ctx(mc, NULL);
    EVP_MD_CTX_free(mc);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
}

static void test_x25519_method(void)
{
    const EVP_PKEY_METHOD *m = EVP_PKEY_meth_find(EVP_PKEY_X25519);
    derive_fn dv = NULL;
    init_fn dvi = NULL;
    ctrl_fn ctrl = NULL;
    ctrl_str_fn ctrl_str = NULL;
    EVP_PKEY *a = raw(EVP_PKEY_X25519, A_PRIV, 1), *b = raw(EVP_PKEY_X25519, B_PUB, 0);
    EVP_PKEY *zero = raw(EVP_PKEY_X25519,
                         "0000000000000000000000000000000000000000000000000000000000000000", 0);
    EVP_PKEY_CTX *c;
    unsigned char s[64];
    size_t len;
    int id = 0, flags = 0, r;

    EVP_PKEY_meth_get0_info(&id, &flags, m);
    printf("  id %d flags %d\n", id, flags);
    EVP_PKEY_meth_get_derive(m, &dvi, &dv);
    EVP_PKEY_meth_get_ctrl(m, &ctrl, &ctrl_str);
    printf("  functions: derive %d %d ctrl %d ctrl_str %d\n", dvi != NULL, dv != NULL,
           ctrl != NULL, ctrl_str != NULL);
    check(dv != NULL && ctrl != NULL, "X25519's method");
    if (dv == NULL || ctrl == NULL)
        return;
    c = EVP_PKEY_CTX_new(a, NULL);
    r = EVP_PKEY_derive_init(c);
    len = sizeof(s);
    r = r * 10 + dv(c, s, &len);
    printf("  no peer %d\n", r);
    errors();
    r = EVP_PKEY_derive_set_peer(c, b);
    len = 0;
    r = r * 10 + dv(c, NULL, &len);
    printf("  peer and size %d %zu\n", r, len);
    len = sizeof(s);
    r = dv(c, s, &len);
    check(r == 1, "RFC 7748's secret");
    hex("secret", s, len);
    errors();
    r = EVP_PKEY_derive_set_peer(c, zero);
    memset(s, 0x77, sizeof(s));
    len = sizeof(s);
    r = r * 10 + dv(c, s, &len);
    printf("  a low-order peer %d %zu\n", r, len);
    hex("buffer", s, 32);
    errors();
    printf("  ctrl peer %d md %d\n", ctrl(c, EVP_PKEY_CTRL_PEER_KEY, 0, NULL),
           ctrl(c, EVP_PKEY_CTRL_MD, 0, NULL));
    EVP_PKEY_CTX_free(c);
    c = EVP_PKEY_CTX_new(b, NULL);
    r = EVP_PKEY_derive_init(c);
    r = r * 10 + EVP_PKEY_derive_set_peer(c, a);
    len = sizeof(s);
    r = r * 10 + dv(c, s, &len);
    printf("  a public key %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    EVP_PKEY_free(zero);
}

static void test_asn1_methods(void)
{
    static const int ids[] = { EVP_PKEY_X25519, EVP_PKEY_ED25519 };
    size_t i;

    for (i = 0; i < 2; i++) {
        const EVP_PKEY_ASN1_METHOD *a = EVP_PKEY_asn1_find(NULL, ids[i]);
        int id = 0, base = 0, flags = 0;
        const char *info = NULL, *pem = NULL;

        EVP_PKEY_asn1_get0_info(&id, &base, &flags, &info, &pem, a);
        printf("  %d %d %d %s %s\n", id, base, flags, info, pem);
    }
}

/* Prints the key to a string. */
static char *printed(EVP_PKEY *k, int priv)
{
    BIO *b = BIO_new(BIO_s_mem());
    char *data, *s;
    long n;

    if (priv)
        EVP_PKEY_print_private(b, k, 2, NULL);
    else
        EVP_PKEY_print_public(b, k, 2, NULL);
    n = BIO_get_mem_data(b, &data);
    s = OPENSSL_strndup(data, (size_t)n);
    BIO_free(b);
    return s;
}

/* A provided key made from the legacy key's raw private key. */
static EVP_PKEY *provided_twin(EVP_PKEY *l, int id)
{
    unsigned char p[64];
    size_t n = sizeof(p);

    if (EVP_PKEY_get_raw_private_key(l, p, &n) != 1)
        return NULL;
    return EVP_PKEY_new_raw_private_key(id, NULL, p, n);
}

static unsigned char next_octet;

static int counting_bytes(unsigned char *buf, int num)
{
    int i;

    for (i = 0; i < num; i++)
        buf[i] = next_octet++;
    return 1;
}

static int counting_status(void)
{
    return 1;
}

static const RAND_METHOD counting_rand = {
    NULL, counting_bytes, NULL, NULL, counting_bytes, counting_status
};

static EVP_PKEY *legacy_keygen(int id)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(id, NULL);
    EVP_PKEY *k = NULL;
    int r = EVP_PKEY_keygen_init(c);

    r = r * 10 + EVP_PKEY_keygen(c, &k);
    printf("  keygen %d\n", r);
    EVP_PKEY_CTX_free(c);
    return k;
}

static void compare_keys(EVP_PKEY *l, EVP_PKEY *p, int id)
{
    unsigned char a[64], b[64];
    size_t an = sizeof(a), bn = sizeof(b);
    char *s1, *s2;
    int r, nid = -1;
    EVP_PKEY *d;

    printf("  get0 %d id %d base %d bits %d security %d size %d\n", EVP_PKEY_get0(l) != NULL,
           EVP_PKEY_get_id(l), EVP_PKEY_get_base_id(l), EVP_PKEY_get_bits(l),
           EVP_PKEY_get_security_bits(l), EVP_PKEY_get_size(l));
    r = EVP_PKEY_get_raw_public_key(l, a, &an);
    r = r * 10 + EVP_PKEY_get_raw_public_key(p, b, &bn);
    printf("  raw public %d %zu same %d\n", r, an, an == bn && memcmp(a, b, an) == 0);
    an = 0;
    r = EVP_PKEY_get_raw_private_key(l, NULL, &an);
    printf("  raw private size %d %zu", r, an);
    an = 10;
    r = EVP_PKEY_get_raw_private_key(l, a, &an);
    printf(" into 10 %d\n", r);
    errors();
    printf("  eq %d %d\n", EVP_PKEY_eq(l, p), EVP_PKEY_eq(p, l));
    errors();
    r = EVP_PKEY_get_default_digest_nid(l, &nid);
    printf("  default digest %d %d\n", r, nid);
    errors();
    s1 = printed(l, 1);
    s2 = printed(l, 0);
    printf("%s%s", s1, s2);
    OPENSSL_free(s1);
    OPENSSL_free(s2);
    errors();
    d = EVP_PKEY_dup(l);
    printf("  dup %d get0 %d eq %d\n", d != NULL, d != NULL && EVP_PKEY_get0(d) != NULL,
           EVP_PKEY_eq(d, l));
    EVP_PKEY_free(d);
    errors();
    (void)id;
}

static void test_legacy_keys(void)
{
    EVP_PKEY_METHOD *mx = EVP_PKEY_meth_new(EVP_PKEY_X25519, 0);
    EVP_PKEY_METHOD *me = EVP_PKEY_meth_new(EVP_PKEY_ED25519, 0);
    EVP_PKEY *l, *p, *l2, *p2;
    unsigned char s1[64], s2[64], *enc = NULL;
    size_t n1 = sizeof(s1), n2 = sizeof(s2), en;
    EVP_MD_CTX *m;
    int r;

    EVP_PKEY_meth_copy(mx, EVP_PKEY_meth_find(EVP_PKEY_X25519));
    EVP_PKEY_meth_copy(me, EVP_PKEY_meth_find(EVP_PKEY_ED25519));
    check(EVP_PKEY_meth_add0(mx) == 1 && EVP_PKEY_meth_add0(me) == 1,
          "applications' copies of the methods");
    RAND_set_rand_method(&counting_rand);

    l = legacy_keygen(EVP_PKEY_ED25519);
    p = l != NULL ? provided_twin(l, EVP_PKEY_ED25519) : NULL;
    check(l != NULL && p != NULL, "a legacy Ed25519 key and its provided twin");
    errors();
    if (l != NULL && p != NULL) {
        compare_keys(l, p, EVP_PKEY_ED25519);
        m = EVP_MD_CTX_new();
        r = EVP_DigestSignInit(m, NULL, NULL, NULL, l);
        r = r * 10 + EVP_DigestSign(m, s1, &n1, (const unsigned char *)"abc", 3);
        printf("  legacy sign %d %zu", r, n1);
        r = EVP_DigestVerifyInit(m, NULL, NULL, NULL, l);
        r = r * 10 + EVP_DigestVerify(m, s1, n1, (const unsigned char *)"abc", 3);
        printf(" verify %d", r);
        r = EVP_DigestSignInit(m, NULL, NULL, NULL, p);
        r = r * 10 + EVP_DigestSign(m, s2, &n2, (const unsigned char *)"abc", 3);
        printf(" provided sign %d same %d\n", r, n1 == n2 && memcmp(s1, s2, n1) == 0);
        r = EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, l);
        printf("  legacy sign with SHA-256 %d\n", r);
        errors();
        EVP_MD_CTX_free(m);
    }
    EVP_PKEY_free(l);
    EVP_PKEY_free(p);

    l = legacy_keygen(EVP_PKEY_X25519);
    l2 = legacy_keygen(EVP_PKEY_X25519);
    p = l != NULL ? provided_twin(l, EVP_PKEY_X25519) : NULL;
    p2 = l2 != NULL ? provided_twin(l2, EVP_PKEY_X25519) : NULL;
    check(l != NULL && l2 != NULL && p != NULL && p2 != NULL,
          "legacy X25519 keys and their provided twins");
    errors();
    if (l != NULL && p != NULL && l2 != NULL && p2 != NULL) {
        EVP_PKEY_CTX *c;

        compare_keys(l, p, EVP_PKEY_X25519);
        c = EVP_PKEY_CTX_new(l, NULL);
        r = EVP_PKEY_derive_init(c);
        r = r * 10 + EVP_PKEY_derive_set_peer(c, l2);
        n1 = sizeof(s1);
        r = r * 10 + EVP_PKEY_derive(c, s1, &n1);
        printf("  legacy derive %d %zu", r, n1);
        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new(p2, NULL);
        r = EVP_PKEY_derive_init(c);
        r = r * 10 + EVP_PKEY_derive_set_peer(c, p);
        n2 = sizeof(s2);
        r = r * 10 + EVP_PKEY_derive(c, s2, &n2);
        printf(" provided derive %d same %d\n", r, n1 == n2 && memcmp(s1, s2, n1) == 0);
        EVP_PKEY_CTX_free(c);
        errors();
        en = EVP_PKEY_get1_encoded_public_key(l, &enc);
        n1 = sizeof(s1);
        EVP_PKEY_get_raw_public_key(l, s1, &n1);
        printf("  encoded public key %zu same %d\n", en,
               enc != NULL && en == n1 && memcmp(enc, s1, n1) == 0);
        r = EVP_PKEY_set1_encoded_public_key(l2, enc, en);
        printf("  set as another's %d eq %d\n", r, EVP_PKEY_eq(l2, p));
        r = EVP_PKEY_set1_encoded_public_key(l2, enc, en - 1);
        printf("  a short one %d\n", r);
        OPENSSL_free(enc);
        errors();
    }
    EVP_PKEY_free(l);
    EVP_PKEY_free(l2);
    EVP_PKEY_free(p);
    EVP_PKEY_free(p2);
    RAND_set_rand_method(NULL);
    EVP_PKEY_meth_remove(mx);
    EVP_PKEY_meth_remove(me);
    EVP_PKEY_meth_free(mx);
    EVP_PKEY_meth_free(me);
}

int main(void)
{
    test_ed25519_method();
    test_x25519_method();
    test_asn1_methods();
    test_legacy_keys();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
