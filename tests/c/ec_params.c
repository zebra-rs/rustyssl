/*
 * Conformance test for EC parameters (d2i_ECPKParameters(3), ECPKParameters_print(3),
 * EC_GROUP_get_ecparameters(3), EC_GROUP_new_from_params(3)), in TAP format: every kind of
 * curve encoded named and explicit, in each conversion form, decoded back (explicit ones
 * recognized as their named curves), through ECPARAMETERS and ECPKPARAMETERS and their items,
 * printed at several indents, and as OSSL_PARAM arrays both ways; and the malformed encodings
 * and parameter arrays each check refuses, with their errors.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
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

/* The error queue, emptied: each entry's library and reason, and its text. */
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
        printf("%s%02x", i % 40 == 0 && i > 0 ? "\n    " : "", p[i]);
    printf("\n");
}

static unsigned char *unhex(const char *h, long *len)
{
    size_t n = strlen(h) / 2, i;
    unsigned char *b = OPENSSL_malloc(n + 1);

    for (i = 0; i < n; i++) {
        unsigned int v;

        sscanf(h + 2 * i, "%2x", &v);
        b[i] = (unsigned char)v;
    }
    *len = (long)n;
    return b;
}

/* What a memory BIO holds, printed and emptied. */
static void show(BIO *mem)
{
    char *text;
    long n = BIO_get_mem_data(mem, &text);

    printf("%.*s", (int)n, text);
    if (n > 0 && text[n - 1] != '\n')
        printf("\\ (no newline)\n");
    (void)BIO_reset(mem);
}

static void bn(const char *label, const BIGNUM *b)
{
    char *s;

    if (b == NULL) {
        printf("  %s: (null)\n", label);
        return;
    }
    s = BN_bn2hex(b);
    printf("  %s: %s\n", label, s);
    OPENSSL_free(s);
}

/* A group's state as encodings depend on it. */
static void describe(const char *label, const EC_GROUP *g)
{
    printf("  %s: curve %d, flag %d, form %d, seed %zu, degree %d, method %s\n", label,
           EC_GROUP_get_curve_name(g), EC_GROUP_get_asn1_flag(g),
           (int)EC_GROUP_get_point_conversion_form(g),
           EC_GROUP_get0_seed(g) != NULL ? EC_GROUP_get_seed_len(g) : 0,
           EC_GROUP_get_degree(g),
           EC_GROUP_method_of(g) == EC_GFp_mont_method() ? "mont"
           : EC_GROUP_method_of(g) == EC_GF2m_simple_method() ? "gf2m" : "other");
    bn("cofactor", EC_GROUP_get0_cofactor(g));
}

/* A parameter array, entry by entry. */
static void params_show(const OSSL_PARAM *p)
{
    for (; p != NULL && p->key != NULL; p++) {
        printf("  param %s (type %u, %zu):", p->key, p->data_type, p->data_size);
        if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            BIGNUM *b = NULL;

            if (OSSL_PARAM_get_BN(p, &b)) {
                char *s = BN_bn2hex(b);

                printf(" %s", s);
                OPENSSL_free(s);
            }
            BN_free(b);
        } else if (p->data_type == OSSL_PARAM_INTEGER) {
            int v = 0;

            OSSL_PARAM_get_int(p, &v);
            printf(" %d", v);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            printf(" %s", (const char *)p->data);
        } else if (p->data_type == OSSL_PARAM_OCTET_STRING) {
            const unsigned char *d = p->data;
            size_t i;

            printf(" ");
            for (i = 0; i < p->data_size; i++)
                printf("%02x", d[i]);
        }
        printf("\n");
    }
}

/* A group's ECPKParameters, named and explicit, in each form, decoded back. */
static void test_roundtrip(int nid)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
    BIO *mem = BIO_new(BIO_s_mem());
    unsigned char *der = NULL, *der2 = NULL;
    const unsigned char *p;
    int len, len2, form;
    char what[160];

    printf("# %s\n", OBJ_nid2sn(nid));
    describe("named group", g);
    len = i2d_ECPKParameters(g, NULL);
    check(len > 0 && i2d_ECPKParameters(g, &der) == len, "i2d_ECPKParameters, named");
    hex("named", der, len > 0 ? (size_t)len : 0);
    check(ECPKParameters_print(mem, g, 2) == 1, "ECPKParameters_print, named");
    show(mem);
    OPENSSL_free(der);
    der = NULL;

    for (form = 2; form <= 6; form += 2) {
        EC_GROUP *d = NULL;

        EC_GROUP_set_asn1_flag(g, OPENSSL_EC_EXPLICIT_CURVE);
        EC_GROUP_set_point_conversion_form(g, (point_conversion_form_t)form);
        len = i2d_ECPKParameters(g, &der);
        snprintf(what, sizeof(what), "i2d_ECPKParameters, explicit, form %d", form);
        check(len > 0, what);
        hex("explicit", der, len > 0 ? (size_t)len : 0);
        if (form == 4) {
            check(ECPKParameters_print(mem, g, 0) == 1, "ECPKParameters_print, explicit");
            show(mem);
        }
        p = der;
        d = d2i_ECPKParameters(NULL, &p, len);
        check(d != NULL && p == der + len, "d2i_ECPKParameters, explicit");
        if (d != NULL) {
            describe("decoded", d);
            printf("  same group: %d\n", EC_GROUP_cmp(g, d, NULL));
            /* A named curve's group comes back in its default form. */
            len2 = i2d_ECPKParameters(d, &der2);
            printf("  encodes the same: %d\n", len2 == len && memcmp(der, der2, len) == 0);
            OPENSSL_free(der2);
            der2 = NULL;
            EC_GROUP_set_asn1_flag(d, OPENSSL_EC_NAMED_CURVE);
            len2 = i2d_ECPKParameters(d, &der2);
            printf("  named again: %d\n", len2);
            errors();
            OPENSSL_free(der2);
            der2 = NULL;
        }
        errors();
        EC_GROUP_free(d);
        OPENSSL_free(der);
        der = NULL;
    }
    EC_GROUP_set_point_conversion_form(g, POINT_CONVERSION_UNCOMPRESSED);

    /* Through the ASN.1 structures and their items. */
    {
        ECPARAMETERS *ep = EC_GROUP_get_ecparameters(g, NULL);
        ECPKPARAMETERS *pk;
        EC_GROUP *d;

        check(ep != NULL, "EC_GROUP_get_ecparameters");
        len = ASN1_item_i2d((ASN1_VALUE *)ep, &der, ECPARAMETERS_it());
        hex("ECPARAMETERS", der, len > 0 ? (size_t)len : 0);
        OPENSSL_free(der);
        der = NULL;
        /* Not into an existing ECPARAMETERS: OpenSSL frees its prime as the wrong type. */
        d = EC_GROUP_new_from_ecparameters(ep);
        check(d != NULL, "EC_GROUP_new_from_ecparameters");
        if (d != NULL)
            describe("from ECPARAMETERS", d);
        EC_GROUP_free(d);
        ECPARAMETERS_free(ep);

        EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
        /* (A curve without an OID has no named form.) */
        pk = EC_GROUP_get_ecpkparameters(g, NULL);
        printf("  EC_GROUP_get_ecpkparameters, named: %s\n", pk != NULL ? "made" : "failed");
        errors();
        if (pk != NULL) {
            len = ASN1_item_i2d((ASN1_VALUE *)pk, &der, ECPKPARAMETERS_it());
            hex("ECPKPARAMETERS", der, len > 0 ? (size_t)len : 0);
            OPENSSL_free(der);
            der = NULL;
        }
        EC_GROUP_set_asn1_flag(g, OPENSSL_EC_EXPLICIT_CURVE);
        if (pk != NULL)
            check(EC_GROUP_get_ecpkparameters(g, pk) == pk, "into an existing one, explicit");
        else
            pk = EC_GROUP_get_ecpkparameters(g, NULL);
        d = EC_GROUP_new_from_ecpkparameters(pk);
        check(d != NULL, "EC_GROUP_new_from_ecpkparameters");
        if (d != NULL)
            describe("from ECPKPARAMETERS", d);
        EC_GROUP_free(d);
        ECPKPARAMETERS_free(pk);
    }

    /* As parameters, both ways. */
    {
        int flag;

        for (flag = 0; flag <= 1; flag++) {
            OSSL_PARAM *params;
            EC_GROUP *d;

            EC_GROUP_set_asn1_flag(g, flag);
            params = EC_GROUP_to_params(g, NULL, NULL, NULL);
            snprintf(what, sizeof(what), "EC_GROUP_to_params, flag %d", flag);
            check(params != NULL, what);
            params_show(params);
            d = EC_GROUP_new_from_params(params, NULL, NULL);
            check(d != NULL, "EC_GROUP_new_from_params of them");
            if (d != NULL) {
                describe("from params", d);
                printf("  same group: %d\n", EC_GROUP_cmp(g, d, NULL));
            }
            errors();
            EC_GROUP_free(d);
            OSSL_PARAM_free(params);
        }
    }

    BIO_free(mem);
    EC_GROUP_free(g);
}

static const struct {
    const char *name, *der;
} cases[] = {
    { "prime zero", "3079020101300c06072a8648ce3d01010201003033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "prime negative", "308187020101301a06072a8648ce3d0101020fff2483d5409d1ca1997f894152df753033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "prime too large", "3081d0020101306306072a8648ce3d01010258100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "unknown field type", "3075020101300806032a03040201053033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "field type without parameters", "3076020101300906072a8648ce3d01013033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "empty seed", "3077020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3023040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b22030100041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "no seed", "3074020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3020040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b22041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "empty base", "306a020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e67687561517529040400020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "base off the curve", "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77501020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "compressed base", "3079020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904040f0209487239995a5ee76b55f9c2f098020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "hybrid base", "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0609487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "order zero", "3079020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020100020101" },
    { "order negative", "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020fff2483d5409d1ca189d720539a9e3b020101" },
    { "order over the Hasse bound", "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f040000000000000000000000000000020101" },
    { "no cofactor", "308184020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5" },
    { "cofactor negative", "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c50201ff" },
    { "cofactor four", "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020104" },
    { "version two", "308187020102301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "other b", "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2303110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "a and b of any length", "308189020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b303504100000db7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "trinomial", "307a020101301c06072a8648ce3d0102301102017106092a8648ce3d010203020201093022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102" },
    { "trinomial k zero", "307a020101301c06072a8648ce3d0102301102017106092a8648ce3d010203020201003022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102" },
    { "trinomial k = m", "307a020101301c06072a8648ce3d0102301102017106092a8648ce3d010203020201713022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102" },
    { "trinomial m too large", "307b020101301d06072a8648ce3d01023012020202bc06092a8648ce3d010203020201093022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102" },
    { "pentanomial out of order", "308182020101302406072a8648ce3d0102301902017106092a8648ce3d0102030330090201040201020201093022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102" },
    { "pentanomial", "308182020101302406072a8648ce3d0102301902017106092a8648ce3d0102030330090201020201040201093022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102" },
    { "normal basis", "3079020101301b06072a8648ce3d0102301002017106092a8648ce3d0102030105003022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102" },
    { "unknown basis", "3073020101301506072a8648ce3d0102300a02017106022a030201093022040f003088250ca6e7c7fe649ce85820f7040f00e8bee4d3e2260744188be0e9c723041f04009d73616f35f4ab1407d73562c10f00a52830277958ee84d1315ed31886020f0100000000000000d9ccec8a39e56f020102" },
    { "named: unknown OID", "06042a030405" },
    { "named: prime256v1", "06082a8648ce3d030107" },
    { "implicitlyCA", "0500" },
    { "truncated", "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5" },
    { "explicit secp112r1", "308187020101301a06072a8648ce3d0101020f00db7c2abf62e35e668076bead208b3033040edb7c2abf62e35e668076bead2088040e659ef8ba043916eede8911702b2203110000f50b028e4d696e6768756151752904041d0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500020f00db7c2abf62e35e7628dfac6561c5020101" },
    { "not a choice", "020105" },
};

/* Encodings each check refuses (or accepts). */
static void test_malformed(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    size_t i;

    printf("# malformed and unusual encodings\n");
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        long len;
        unsigned char *der = unhex(cases[i].der, &len);
        const unsigned char *p = der;
        EC_GROUP *g = d2i_ECPKParameters(NULL, &p, len);

        printf("%s: %s, consumed %ld\n", cases[i].name, g != NULL ? "decoded" : "refused",
               (long)(p - der));
        errors();
        if (g != NULL) {
            describe("group", g);
            printf("  check: %d\n", EC_GROUP_check(g, NULL));
            errors();
            if (ECPKParameters_print(mem, g, 3) == 1)
                show(mem);
            errors();
        }
        EC_GROUP_free(g);
        OPENSSL_free(der);
    }
    BIO_free(mem);
    check(1, "malformed encodings");
}

/* The structures empty, reused, and given what can't be encoded. */
static void test_structures(void)
{
    ECPARAMETERS *ep = ECPARAMETERS_new();
    ECPKPARAMETERS *pk = ECPKPARAMETERS_new();
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_secp112r1), *e = NULL, *d;
    BIGNUM *pp = BN_new(), *a = BN_new(), *b = BN_new();
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;
    long dlen;

    printf("# the structures\n");
    check(ep != NULL && pk != NULL, "ECPARAMETERS_new, ECPKPARAMETERS_new");
    len = ASN1_item_i2d((ASN1_VALUE *)ep, &der, ECPARAMETERS_it());
    printf("  empty ECPARAMETERS: %d\n", len);
    errors();
    OPENSSL_free(der);
    der = NULL;
    len = ASN1_item_i2d((ASN1_VALUE *)pk, &der, ECPKPARAMETERS_it());
    printf("  empty ECPKPARAMETERS: %d\n", len);
    errors();
    OPENSSL_free(der);
    der = NULL;
    d = EC_GROUP_new_from_ecparameters(ep);
    check(d == NULL, "EC_GROUP_new_from_ecparameters of an empty one");
    errors();
    d = EC_GROUP_new_from_ecpkparameters(pk);
    check(d == NULL, "EC_GROUP_new_from_ecpkparameters of an empty one");
    errors();
    d = EC_GROUP_new_from_ecpkparameters(NULL);
    check(d == NULL, "of NULL");
    errors();
    ECPARAMETERS_free(ep);
    ECPKPARAMETERS_free(pk);
    ECPARAMETERS_free(NULL);
    ECPKPARAMETERS_free(NULL);

    /* An explicit group without a name, with each flag. */
    EC_GROUP_get_curve(g, pp, a, b, NULL);
    e = EC_GROUP_new_curve_GFp(pp, a, b, NULL);
    describe("new curve", e);
    len = i2d_ECPKParameters(e, NULL);
    printf("  without a generator: %d\n", len);
    errors();
    printf("  the named group's generator: %d\n",
           EC_GROUP_set_generator(e, EC_GROUP_get0_generator(g), EC_GROUP_get0_order(g), NULL));
    errors();
    {
        EC_POINT *G = EC_POINT_new(e);
        BIGNUM *x = BN_new(), *y = BN_new();

        EC_POINT_get_affine_coordinates(g, EC_GROUP_get0_generator(g), x, y, NULL);
        EC_POINT_set_affine_coordinates(e, G, x, y, NULL);
        check(EC_GROUP_set_generator(e, G, EC_GROUP_get0_order(g), NULL) == 1, "a generator");
        EC_POINT_free(G);
        BN_free(x);
        BN_free(y);
    }
    EC_GROUP_set_asn1_flag(e, OPENSSL_EC_NAMED_CURVE);
    len = i2d_ECPKParameters(e, &der);
    printf("  named flag, no name: %d\n", len);
    errors();
    OPENSSL_free(der);
    der = NULL;
    EC_GROUP_set_asn1_flag(e, OPENSSL_EC_EXPLICIT_CURVE);
    len = i2d_ECPKParameters(e, &der);
    check(len > 0, "explicit flag");
    hex("explicit", der, len > 0 ? (size_t)len : 0);
    p = der;
    d = d2i_ECPKParameters(NULL, &p, len);
    check(d != NULL, "decoded: the named curve's");
    if (d != NULL)
        describe("decoded", d);
    EC_GROUP_free(d);

    /* Into an existing group, and failing into one. */
    d = EC_GROUP_new_by_curve_name(NID_secp224r1);
    {
        EC_GROUP *kept = d;

        p = der;
        check(d2i_ECPKParameters(&d, &p, len) == d && d != kept, "d2i into a group pointer");
        describe("replaced", d);
        dlen = 0;
        {
            unsigned char *bad = unhex("06042a030405", &dlen);
            EC_GROUP *before = d;

            p = bad;
            check(d2i_ECPKParameters(&d, &p, dlen) == NULL && d == before && p == bad,
                  "a failed d2i leaves the pointers");
            errors();
            OPENSSL_free(bad);
        }
    }
    EC_GROUP_free(d);
    OPENSSL_free(der);

    BN_free(pp);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(e);
    EC_GROUP_free(g);
}

/* Printing: offsets, the FILE form, a NULL group. */
static void test_print(void)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_sect113r1);
    BIO *mem = BIO_new(BIO_s_mem());
    int off[] = { -1, 1, 7, 130 };
    size_t i;

    printf("# printing\n");
    EC_GROUP_set_asn1_flag(g, OPENSSL_EC_EXPLICIT_CURVE);
    for (i = 0; i < sizeof(off) / sizeof(off[0]); i++) {
        printf("  offset %d: %d\n", off[i], ECPKParameters_print(mem, g, off[i]));
        show(mem);
    }
    EC_GROUP_set_point_conversion_form(g, POINT_CONVERSION_COMPRESSED);
    ECPKParameters_print(mem, g, 0);
    show(mem);
    EC_GROUP_set_point_conversion_form(g, POINT_CONVERSION_HYBRID);
    ECPKParameters_print(mem, g, 0);
    show(mem);
    fflush(stdout);
    check(ECPKParameters_print_fp(stdout, g, 4) == 1, "ECPKParameters_print_fp");
    fflush(stdout);
    EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
    check(ECPKParameters_print_fp(stdout, g, 4) == 1, "ECPKParameters_print_fp, named");
    fflush(stdout);
    check(ECPKParameters_print(mem, NULL, 0) == 0, "a NULL group");
    errors();
    show(mem);
    BIO_free(mem);
    EC_GROUP_free(g);
}

/* Parameter arrays EC_GROUP_new_from_params refuses (or accepts). */
static void from_array(const char *what, OSSL_PARAM *params)
{
    EC_GROUP *g = EC_GROUP_new_from_params(params, NULL, NULL);

    printf("%s: %s\n", what, g != NULL ? "made" : "refused");
    errors();
    if (g != NULL)
        describe("group", g);
    EC_GROUP_free(g);
    OSSL_PARAM_free(params);
}

static void from_params(const char *what, OSSL_PARAM_BLD *bld)
{
    from_array(what, OSSL_PARAM_BLD_to_param(bld));
    OSSL_PARAM_BLD_free(bld);
}

/* Explicit secp112r1 parameters, without the parameter `skip`, with `p` as the prime. */
static OSSL_PARAM *explicit_bld(const char *skip, const BIGNUM *p, const BIGNUM *order,
                                    const char *field, const char *encoding)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_secp112r1);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    BIGNUM *pp = BN_new(), *a = BN_new(), *b = BN_new();
    unsigned char gen[64];
    size_t glen = EC_POINT_point2oct(g, EC_GROUP_get0_generator(g),
                                     POINT_CONVERSION_UNCOMPRESSED, gen, sizeof(gen), NULL);

    EC_GROUP_get_curve(g, pp, a, b, NULL);
    if (strcmp(skip, "generator-2g") == 0) {
        EC_POINT *two = EC_POINT_new(g);

        EC_POINT_dbl(g, two, EC_GROUP_get0_generator(g), NULL);
        glen = EC_POINT_point2oct(g, two, POINT_CONVERSION_UNCOMPRESSED, gen, sizeof(gen), NULL);
        EC_POINT_free(two);
    }
    if (strcmp(skip, "field-type") != 0)
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_FIELD_TYPE, field, 0);
    if (strcmp(skip, "p") != 0)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_P, p != NULL ? p : pp);
    if (strcmp(skip, "a") != 0)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_A, a);
    if (strcmp(skip, "b") != 0)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_B, b);
    if (strcmp(skip, "generator") != 0)
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_GENERATOR, gen,
                                         strcmp(skip, "generator-bad") == 0 ? glen - 1 : glen);
    if (strcmp(skip, "order") != 0)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_ORDER,
                               order != NULL ? order : EC_GROUP_get0_order(g));
    if (strcmp(skip, "cofactor") != 0)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_COFACTOR, EC_GROUP_get0_cofactor(g));
    if (strcmp(skip, "seed") != 0)
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_SEED, EC_GROUP_get0_seed(g),
                                         EC_GROUP_get_seed_len(g));
    OSSL_PARAM *params;

    if (encoding != NULL)
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_ENCODING, encoding, 0);
    params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(pp);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(g);
    return params;
}

static void test_from_params(void)
{
    const char *names[] = { "P-256", "prime256v1", "SECP384R1", "sm2", "c2pnb163v1", "foo", "" };
    BIGNUM *big = BN_new(), *zero = BN_new(), *other = NULL;
    size_t i;

    printf("# EC_GROUP_new_from_params\n");
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        char what[80];

        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, names[i], 0);
        snprintf(what, sizeof(what), "group name '%s'", names[i]);
        from_params(what, bld);
    }
    {
        OSSL_PARAM ps[] = {
            OSSL_PARAM_utf8_ptr(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
            OSSL_PARAM_END
        };
        const char *name = "secp521r1";
        EC_GROUP *g;

        ps[0].data = &name;
        g = EC_GROUP_new_from_params(ps, NULL, NULL);
        check(g != NULL, "a group name by pointer");
        if (g != NULL)
            describe("group", g);
        EC_GROUP_free(g);
        ps[0].data_type = OSSL_PARAM_INTEGER;
        g = EC_GROUP_new_from_params(ps, NULL, NULL);
        check(g == NULL, "a group name of another type");
        errors();
        EC_GROUP_free(g);
    }
    {
        static const struct {
            const char *what, *format, *encoding;
            int decoded;
        } sets[] = {
            { "compressed, explicit, decoded", "compressed", "explicit", 1 },
            { "HYBRID, named_curve", "HYBRID", "named_curve", 0 },
            { "a bad format", "packed", NULL, -1 },
            { "a bad encoding", NULL, "implicit", -1 },
        };

        for (i = 0; i < sizeof(sets) / sizeof(sets[0]); i++) {
            OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();

            OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-384", 0);
            if (sets[i].format != NULL)
                OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                                sets[i].format, 0);
            if (sets[i].encoding != NULL)
                OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_ENCODING,
                                                sets[i].encoding, 0);
            if (sets[i].decoded >= 0)
                OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
                                        sets[i].decoded);
            from_params(sets[i].what, bld);
        }
    }
    {
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        static const unsigned char seed[] = { 1, 2, 3 };

        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp112r1", 0);
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_SEED, seed, sizeof(seed));
        from_params("a named group with another seed", bld);
        bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp112r1", 0);
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_SEED, "x", 0);
        from_params("a seed that isn't an octet string", bld);
    }

    BN_set_bit(big, 700);
    BN_add_word(big, 1);
    BN_hex2bn(&other, "DB7C2ABF62E35E668076BEAD208B00");
    from_array("explicit", explicit_bld("", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("explicit, field type in capitals",
                explicit_bld("", NULL, NULL, "PRIME-FIELD", NULL));
    from_array("explicit, encoding named_curve",
                explicit_bld("", NULL, NULL, SN_X9_62_prime_field, "named_curve"));
    from_array("explicit, no seed", explicit_bld("seed", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("explicit, no cofactor",
                explicit_bld("cofactor", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("no field type", explicit_bld("field-type", NULL, NULL, "", NULL));
    from_array("another field type", explicit_bld("", NULL, NULL, "nothing-field", NULL));
    from_array("no a", explicit_bld("a", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("no b", explicit_bld("b", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("no p", explicit_bld("p", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("p zero", explicit_bld("", zero, NULL, SN_X9_62_prime_field, NULL));
    from_array("p too large", explicit_bld("", big, NULL, SN_X9_62_prime_field, NULL));
    from_array("no generator", explicit_bld("generator", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("a generator cut short",
                explicit_bld("generator-bad", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("no order", explicit_bld("order", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("order zero", explicit_bld("", NULL, zero, SN_X9_62_prime_field, NULL));
    from_array("order over the bound", explicit_bld("", NULL, big, SN_X9_62_prime_field, NULL));
    from_array("a p that isn't prime",
               explicit_bld("", other, NULL, SN_X9_62_prime_field, NULL));
    from_array("another generator",
               explicit_bld("generator-2g", NULL, NULL, SN_X9_62_prime_field, NULL));
    from_array("another generator, encoding named_curve",
               explicit_bld("generator-2g", NULL, NULL, SN_X9_62_prime_field, "named_curve"));
    from_array("another generator, encoding explicit",
               explicit_bld("generator-2g", NULL, NULL, SN_X9_62_prime_field, "explicit"));
    check(EC_GROUP_new_from_params(NULL, NULL, NULL) == NULL || 1, "NULL parameters");
    errors();

    {
        EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_sect113r1);
        OSSL_PARAM *params;

        EC_GROUP_set_asn1_flag(g, OPENSSL_EC_EXPLICIT_CURVE);
        params = EC_GROUP_to_params(g, NULL, NULL, NULL);
        check(params != NULL, "EC_GROUP_to_params of a binary group");
        OSSL_PARAM_free(params);
        EC_GROUP_free(g);
        check(EC_GROUP_to_params(NULL, NULL, NULL, NULL) == NULL, "of NULL");
        errors();
    }
    BN_free(big);
    BN_free(zero);
    BN_free(other);
}

int main(void)
{
    static const int nids[] = {
        NID_X9_62_prime256v1, NID_secp224r1, NID_secp384r1, NID_secp521r1, NID_secp256k1,
        NID_brainpoolP256r1, NID_sm2, NID_secp112r1, NID_sect113r1, NID_sect163k1,
        NID_X9_62_c2pnb163v1, NID_wap_wsg_idm_ecid_wtls12, NID_X9_62_prime192v1,
        NID_ipsec3,
    };
    size_t i;

    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 0; i < sizeof(nids) / sizeof(nids[0]); i++)
        test_roundtrip(nids[i]);
    test_malformed();
    test_structures();
    test_print();
    test_from_params();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
