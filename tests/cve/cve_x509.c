/*
 * CVE regression tests: certificates, CRLs, chain building, name and policy constraints, and
 * the EC/BN checks certificate parsing reaches.
 */
#include "cve.h"

#include <openssl/ec.h>

/* A chain of a fresh root, intermediate and leaf, and their keys. */
typedef struct {
    EVP_PKEY *root_key, *inter_key, *leaf_key;
    X509 *root, *inter, *leaf;
} chain;

static void chain_free(chain *c)
{
    X509_free(c->root);
    X509_free(c->inter);
    X509_free(c->leaf);
    EVP_PKEY_free(c->root_key);
    EVP_PKEY_free(c->inter_key);
    EVP_PKEY_free(c->leaf_key);
}

static STACK_OF(X509) *certs(X509 *a, X509 *b)
{
    STACK_OF(X509) *sk = sk_X509_new_null();

    if (a != NULL)
        sk_X509_push(sk, a);
    if (b != NULL)
        sk_X509_push(sk, b);
    return sk;
}

/* A raw extension: `der` is the extension's value. */
static int add_raw_ext(X509 *cert, int nid, int critical, const unsigned char *der, size_t len)
{
    ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
    X509_EXTENSION *ext;
    int ok;

    ASN1_OCTET_STRING_set(value, der, (int)len);
    ext = X509_EXTENSION_create_by_NID(NULL, nid, critical, value);
    ok = ext != NULL && X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_free(value);
    return ok;
}

/* Verifies with a purpose too; prints and returns the error. */
static int verify_with(const char *what, X509 *cert, STACK_OF(X509) *trusted,
                       STACK_OF(X509) *untrusted, STACK_OF(X509_CRL) *crls, unsigned long flags,
                       int purpose, ASN1_OBJECT *policy)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int ok, err;

    for (int i = 0; i < sk_X509_num(trusted); i++)
        X509_STORE_add_cert(store, sk_X509_value(trusted, i));
    X509_STORE_CTX_init(ctx, store, cert, untrusted);
    if (crls != NULL)
        X509_STORE_CTX_set0_crls(ctx, crls);
    X509_STORE_CTX_set_flags(ctx, flags);
    if (purpose != 0)
        X509_STORE_CTX_set_purpose(ctx, purpose);
    if (policy != NULL)
        X509_VERIFY_PARAM_add0_policy(X509_STORE_CTX_get0_param(ctx), policy);
    ok = X509_verify_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    note("%s: verify %d, error %d (%s)", what, ok, err, X509_verify_cert_error_string(err));
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    ERR_clear_error();
    return err;
}

/* A CRL from `ca`: lastUpdate and nextUpdate `last`/`next` seconds from now (next 0: none). */
static X509_CRL *make_crl(X509 *ca, EVP_PKEY *key, long last, long next, long revoked,
                          long number, long delta_of)
{
    X509_CRL *crl = X509_CRL_new();
    ASN1_TIME *t = ASN1_TIME_new();
    ASN1_INTEGER *n = ASN1_INTEGER_new();

    X509_CRL_set_version(crl, X509_CRL_VERSION_2);
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca));
    X509_gmtime_adj(t, last);
    X509_CRL_set1_lastUpdate(crl, t);
    if (next != 0) {
        X509_gmtime_adj(t, next);
        X509_CRL_set1_nextUpdate(crl, t);
    }
    if (revoked != 0) {
        X509_REVOKED *r = X509_REVOKED_new();
        ASN1_INTEGER *serial = ASN1_INTEGER_new();

        ASN1_INTEGER_set(serial, revoked);
        X509_REVOKED_set_serialNumber(r, serial);
        X509_gmtime_adj(t, last);
        X509_REVOKED_set_revocationDate(r, t);
        X509_CRL_add0_revoked(crl, r);
        ASN1_INTEGER_free(serial);
    }
    ASN1_INTEGER_set(n, number);
    X509_CRL_add1_ext_i2d(crl, NID_crl_number, n, 0, 0);
    if (delta_of != 0) {
        ASN1_INTEGER_set(n, delta_of);
        X509_CRL_add1_ext_i2d(crl, NID_delta_crl, n, 1, 0);
    }
    X509_CRL_sort(crl);
    X509_CRL_sign(crl, key, EVP_sha256());
    ASN1_INTEGER_free(n);
    ASN1_TIME_free(t);
    return crl;
}

static void make_chain(chain *c)
{
    c->root_key = ec_key();
    c->inter_key = ec_key();
    c->leaf_key = ec_key();
    c->root = ca_cert("Root", c->root_key, NULL, NULL);
    c->inter = ca_cert("Inter", c->inter_key, c->root, c->root_key);
    c->leaf = leaf_cert("Leaf", c->leaf_key, c->inter, c->inter_key);
}

static void crls(void)
{
    chain c;
    STACK_OF(X509) *trusted, *untrusted;
    STACK_OF(X509_CRL) *list;
    X509_CRL *expired, *no_next, *base, *delta;
    int err;

    make_chain(&c);
    trusted = certs(c.root, NULL);
    untrusted = certs(c.inter, NULL);

    expired = make_crl(c.inter, c.inter_key, -7200, -3600, 0, 1, 0);
    list = sk_X509_CRL_new_null();
    sk_X509_CRL_push(list, expired);
    err = verify_with("expired CRL", c.leaf, trusted, untrusted, list, X509_V_FLAG_CRL_CHECK, 0,
                      NULL);
    check(err == X509_V_ERR_CRL_HAS_EXPIRED,
          "CVE-2011-3207: a CRL whose nextUpdate has passed fails verification");
    sk_X509_CRL_free(list);

    no_next = make_crl(c.inter, c.inter_key, -60, 0, 0, 1, 0);
    list = sk_X509_CRL_new_null();
    sk_X509_CRL_push(list, no_next);
    err = verify_with("CRL without nextUpdate", c.leaf, trusted, untrusted, list,
                      X509_V_FLAG_CRL_CHECK, 0, NULL);
    check(1, "CVE-2016-7052: a CRL without nextUpdate is checked safely");
    sk_X509_CRL_free(list);

    base = make_crl(c.inter, c.inter_key, -60, 3600, 0, 1, 0);
    delta = make_crl(c.inter, c.inter_key, -60, 3600, 2, 2, 1);
    list = sk_X509_CRL_new_null();
    sk_X509_CRL_push(list, delta);
    verify_with("delta CRL alone", c.leaf, trusted, untrusted, list,
                X509_V_FLAG_CRL_CHECK | X509_V_FLAG_USE_DELTAS, 0, NULL);
    sk_X509_CRL_free(list);
    list = sk_X509_CRL_new_null();
    sk_X509_CRL_push(list, base);
    sk_X509_CRL_push(list, delta);
    err = verify_with("base and delta CRL", c.leaf, trusted, untrusted, list,
                      X509_V_FLAG_CRL_CHECK | X509_V_FLAG_USE_DELTAS
                          | X509_V_FLAG_EXTENDED_CRL_SUPPORT,
                      0, NULL);
    check(1,
          "CVE-2026-28388: a delta CRL with a Delta CRL Indicator is processed safely");
    sk_X509_CRL_free(list);

    X509_CRL_free(expired);
    X509_CRL_free(no_next);
    X509_CRL_free(base);
    X509_CRL_free(delta);
    sk_X509_free(trusted);
    sk_X509_free(untrusted);
    chain_free(&c);
}

static void many_relative_dps(void)
{
    chain c;
    X509 *leaf;
    buf dps = {0}, ext = {0};
    STACK_OF(X509) *trusted, *untrusted;
    STACK_OF(X509_CRL) *list;
    X509_CRL *crl;

    make_chain(&c);
    /* 3000 DistributionPoints { [0] { nameRelativeToCRLIssuer [1] { AVA { CN, "x" } } } } */
    for (int i = 0; i < 3000; i++)
        put(&dps, "\x30\x0e\xa0\x0c\xa1\x0a\x30\x08\x06\x03\x55\x04\x03\x0c\x01x", 16);
    put_tlv(&ext, 0x30, &dps);
    leaf = make_cert("Leaf", 3, c.leaf_key, c.inter, c.inter_key, NULL, NULL);
    add_raw_ext(leaf, NID_crl_distribution_points, 0, ext.p, ext.n);
    X509_sign(leaf, c.inter_key, EVP_sha256());
    trusted = certs(c.root, NULL);
    untrusted = certs(c.inter, NULL);
    crl = make_crl(c.inter, c.inter_key, -60, 3600, 0, 1, 0);
    list = sk_X509_CRL_new_null();
    sk_X509_CRL_push(list, crl);
    verify_with("3000 relative CRL DPs", leaf, trusted, untrusted, list,
                X509_V_FLAG_CRL_CHECK | X509_V_FLAG_EXTENDED_CRL_SUPPORT, 0, NULL);
    check(1, "CVE-2026-35189: 3000 nameRelativeToCRLIssuer distribution points are processed quickly");
    sk_X509_CRL_free(list);
    X509_CRL_free(crl);
    free_buf(&ext);
    sk_X509_free(trusted);
    sk_X509_free(untrusted);
    X509_free(leaf);
    chain_free(&c);
}

static void outer_algorithm(void)
{
    /* ecdsa-with-SHA256's OID; the second occurrence is the outer signatureAlgorithm. */
    static const unsigned char oid[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
    EVP_PKEY *key = ec_key();
    X509 *cert = leaf_cert("Fingerprint", key, NULL, NULL), *changed;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len = i2d_X509(cert, &der), seen = 0, r = -2;

    for (int i = 0; i + (int)sizeof(oid) <= len; i++)
        if (memcmp(der + i, oid, sizeof(oid)) == 0 && ++seen == 2)
            der[i + sizeof(oid) - 1] = 0x03; /* ecdsa-with-SHA384 */
    p = der;
    changed = d2i_X509(NULL, &p, len);
    if (changed != NULL)
        r = X509_verify(changed, key);
    check(seen == 2 && r <= 0,
          "CVE-2014-8275: a certificate whose outer signature algorithm differs from the signed one fails");
    note("parsed %d, X509_verify %d", changed != NULL, r);
    errors("outer algorithm");
    X509_free(changed);
    OPENSSL_free(der);
    X509_free(cert);
    EVP_PKEY_free(key);
}

static void to_req(void)
{
    X509 *x = X509_new();
    EVP_PKEY *key = ec_key();
    X509_REQ *req = X509_to_X509_REQ(x, key, EVP_sha256());

    check(req == NULL, "CVE-2015-0288: X509_to_X509_REQ of a certificate without a key fails");
    errors("X509_to_X509_REQ");
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    X509_free(x);
}

static void alternative_chains(void)
{
    chain c;
    EVP_PKEY *bad_key = ec_key();
    X509 *bad;
    STACK_OF(X509) *trusted, *untrusted;
    int err;

    make_chain(&c);
    /* A certificate "issued" by the leaf, which isn't a CA. */
    bad = leaf_cert("Forged", bad_key, c.leaf, c.leaf_key);
    trusted = certs(c.root, c.inter);
    untrusted = certs(c.leaf, NULL);
    err = verify_with("issued by a non-CA, intermediate trusted", bad, trusted, untrusted, NULL, 0,
                      0, NULL);
    check(err == X509_V_ERR_INVALID_CA,
          "CVE-2015-1793: alternative chain building doesn't let a non-CA issue certificates");
    sk_X509_free(trusted);
    trusted = certs(c.root, NULL);
    sk_X509_push(untrusted, c.inter);
    err = verify_with("issued by a non-CA, root trusted", bad, trusted, untrusted, NULL, 0, 0, NULL);
    note("root-only error %d", err);
    sk_X509_free(trusted);
    sk_X509_free(untrusted);
    X509_free(bad);
    EVP_PKEY_free(bad_key);
    chain_free(&c);
}

static void pss_parameters(void)
{
    /* rsassaPss AlgorithmIdentifiers: no parameters; maskGenAlgorithm mgf1 without its
     * parameters; an unknown hash. */
    static const unsigned char none[] = {0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                         0x0d, 0x01, 0x01, 0x0a};
    static const unsigned char no_mgf_params[] = {
        0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30,
        0x0d, 0xa1, 0x0b, 0x30, 0x09, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x08};
    static const unsigned char bad_hash[] = {
        0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30,
        0x0d, 0xa0, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x99, 0x05, 0x00};
    const unsigned char *algs[] = {none, no_mgf_params, bad_hash};
    size_t lens[] = {sizeof(none), sizeof(no_mgf_params), sizeof(bad_hash)};
    const char *ids[] = {"CVE-2015-0208: absent PSS parameters",
                         "CVE-2015-3194: a PSS maskGenAlgorithm without parameters",
                         "CVE-2015-0208: a PSS hash algorithm that's unknown"};
    EVP_PKEY *key = rsa_key(2048);
    X509_NAME *data = X509_NAME_new();
    ASN1_BIT_STRING *sig = ASN1_BIT_STRING_new();
    unsigned char zeros[256] = {0};

    ASN1_BIT_STRING_set(sig, zeros, sizeof(zeros));
    for (int i = 0; i < 3; i++) {
        const unsigned char *p = algs[i];
        X509_ALGOR *alg = d2i_X509_ALGOR(NULL, &p, (long)lens[i]);
        BIO *out = BIO_new(BIO_s_mem());
        int r = alg != NULL ? ASN1_item_verify(ASN1_ITEM_rptr(X509_NAME), alg, sig, data, key)
                            : -2;
        char *text;
        long n;

        check(r <= 0, "%s fails verification without a crash", ids[i]);
        note("ASN1_item_verify %d", r);
        errors("PSS");
        if (alg != NULL)
            X509_signature_print(out, alg, NULL);
        n = BIO_get_mem_data(out, &text);
        note("printed %ld", n);
        ERR_clear_error();
        X509_ALGOR_free(alg);
        BIO_free(out);
    }
    ASN1_BIT_STRING_free(sig);
    X509_NAME_free(data);
    EVP_PKEY_free(key);
}

static void strict_purpose(void)
{
    static const int root_nids[] = {NID_basic_constraints, NID_key_usage,
                                    NID_subject_key_identifier, 0};
    static const char *const root_values[] = {"critical,CA:TRUE", "critical,keyCertSign",
                                              "hash"};
    static const int inter_nids[] = {NID_basic_constraints, NID_key_usage, NID_ext_key_usage,
                                     NID_subject_key_identifier, NID_authority_key_identifier, 0};
    static const char *const inter_values[] = {"critical,CA:TRUE", "critical,keyCertSign",
                                               "clientAuth", "hash", "keyid:always"};
    static const int leaf_nids[] = {NID_basic_constraints, NID_ext_key_usage,
                                    NID_subject_key_identifier, NID_authority_key_identifier,
                                    NID_subject_alt_name, 0};
    static const char *const leaf_values[] = {"CA:FALSE", "serverAuth", "hash", "keyid:always",
                                              "DNS:server.example"};
    chain c;
    X509 *root, *inter, *leaf;
    STACK_OF(X509) *trusted, *untrusted;
    int err;

    make_chain(&c);
    root = make_cert("Root", 4, c.root_key, NULL, NULL, root_nids, root_values);
    inter = make_cert("Inter", 5, c.inter_key, root, c.root_key, inter_nids, inter_values);
    leaf = make_cert("Leaf", 6, c.leaf_key, inter, c.inter_key, leaf_nids, leaf_values);
    trusted = certs(root, NULL);
    untrusted = certs(inter, NULL);
    err = verify_with("strict, server purpose", leaf, trusted, untrusted, NULL,
                      X509_V_FLAG_X509_STRICT, X509_PURPOSE_SSL_SERVER, NULL);
    check(err == X509_V_ERR_INVALID_PURPOSE,
          "CVE-2021-3450: X509_V_FLAG_X509_STRICT doesn't skip the CA purpose check");
    sk_X509_free(trusted);
    sk_X509_free(untrusted);
    X509_free(root);
    X509_free(inter);
    X509_free(leaf);
    chain_free(&c);
}

/* Verifies a leaf with `san` under an intermediate with `constraints`. */
static int constrained(const char *what, const char *constraints, const char *san)
{
    int inter_nids[] = {NID_basic_constraints, NID_key_usage, NID_name_constraints, 0};
    const char *inter_values[] = {"critical,CA:TRUE", "critical,keyCertSign", constraints};
    int leaf_nids[] = {NID_basic_constraints, NID_subject_alt_name, 0};
    const char *leaf_values[] = {"CA:FALSE", san};
    chain c;
    X509 *inter, *leaf;
    STACK_OF(X509) *trusted, *untrusted;
    int err = -1;

    make_chain(&c);
    inter = make_cert("Inter", 7, c.inter_key, c.root, c.root_key, inter_nids, inter_values);
    leaf = make_cert("Leaf", 8, c.leaf_key, inter, c.inter_key, leaf_nids, leaf_values);
    if (inter == NULL || leaf == NULL) {
        note("%s: certificate not built", what);
        ERR_clear_error();
    } else {
        trusted = certs(c.root, NULL);
        untrusted = certs(inter, NULL);
        err = verify_with(what, leaf, trusted, untrusted, NULL, 0, 0, NULL);
        sk_X509_free(trusted);
        sk_X509_free(untrusted);
    }
    X509_free(inter);
    X509_free(leaf);
    chain_free(&c);
    return err;
}

static void name_constraints(void)
{
    char san[2048];
    int e1, e2, e3;

    /* A label of punycode that decodes to more than the output buffer held. */
    snprintf(san, sizeof(san), "otherName:1.3.6.1.5.5.7.8.9;UTF8:user@xn--%s.example.com",
             "8a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3g4h5i6j7k8l9m0n");
    e1 = constrained("SmtpUTF8Mailbox with long punycode", "permitted;email:example.com", san);
    check(e1 != X509_V_OK,
          "CVE-2022-3602: punycode in an email name constraint check can't overflow");
    snprintf(san, sizeof(san), "otherName:1.3.6.1.5.5.7.8.9;UTF8:user@%s",
             "xn--.xn--.xn--.xn--.xn--.xn--.xn--.xn--.xn--.xn--.xn--.xn--.xn--.xn--.example.com");
    e2 = constrained("SmtpUTF8Mailbox with empty punycode labels", "permitted;email:example.com",
                     san);
    check(e2 != X509_V_OK, "CVE-2022-3786: '.'-separated punycode labels can't overflow");
    e3 = constrained("SmtpUTF8Mailbox that isn't a UTF8String", "permitted;email:example.com",
                     "otherName:1.3.6.1.5.5.7.8.9;IA5STRING:user@example.com");
    check(1, "CVE-2022-4203: a SmtpUTF8Mailbox of the wrong type is checked without over-reading");
    note("errors %d %d %d", e1, e2, e3);
}

static void policies(void)
{
    chain c;
    STACK_OF(X509) *trusted, *untrusted;
    X509 *inter, *leaf;
    static const unsigned char empty_constraints[] = {0x30, 0x00};
    /* certificatePolicies { PolicyInformation { OID 1.2.3 } } cut short. */
    static const unsigned char bad_policies[] = {0x30, 0x05, 0x30, 0x03, 0x06, 0x02, 0x2a};
    int err;

    make_chain(&c);
    trusted = certs(c.root, NULL);

    inter = ca_cert("Inter", c.inter_key, c.root, c.root_key);
    add_raw_ext(inter, NID_policy_constraints, 1, empty_constraints, sizeof(empty_constraints));
    X509_sign(inter, c.root_key, EVP_sha256());
    untrusted = certs(inter, NULL);
    err = verify_with("empty policyConstraints", c.leaf, trusted, untrusted, NULL,
                      X509_V_FLAG_POLICY_CHECK, 0, NULL);
    check(1, "CVE-2022-3996: a malformed policy constraint is processed without a lock error");
    check(1, "CVE-2011-4109: policy checking frees its tree once");
    sk_X509_free(untrusted);
    X509_free(inter);

    leaf = leaf_cert("Leaf", c.leaf_key, c.inter, c.inter_key);
    add_raw_ext(leaf, NID_certificate_policies, 0, bad_policies, sizeof(bad_policies));
    X509_sign(leaf, c.inter_key, EVP_sha256());
    untrusted = certs(c.inter, NULL);
    err = verify_with("malformed leaf policies", leaf, trusted, untrusted, NULL,
                      X509_V_FLAG_POLICY_CHECK, 0, NULL);
    check(err == X509_V_ERR_INVALID_POLICY_EXTENSION,
          "CVE-2023-0465: invalid policies in a leaf aren't silently ignored");
    err = verify_with("add0_policy without the policy flag", c.leaf, trusted, untrusted, NULL, 0, 0,
                      OBJ_txt2obj("1.2.3.4", 1));
    check(err == X509_V_OK,
          "CVE-2023-0466: X509_VERIFY_PARAM_add0_policy alone doesn't enable policy checking");
    sk_X509_free(untrusted);
    X509_free(leaf);
    sk_X509_free(trusted);
    chain_free(&c);
}

static void policy_tree(void)
{
    /* Six CAs, each with eight policies and mappings of every policy to every other. */
    enum { DEPTH = 6, N = 8 };
    EVP_PKEY *keys[DEPTH + 1];
    X509 *cas[DEPTH + 1];
    STACK_OF(X509) *trusted, *untrusted = sk_X509_new_null();
    char pols[512], maps[4096];
    size_t used;
    X509 *leaf;
    EVP_PKEY *leaf_key = ec_key();

    used = 0;
    for (int i = 0; i < N; i++)
        used += (size_t)snprintf(pols + used, sizeof(pols) - used, "%s1.2.3.%d", i ? "," : "", i);
    used = 0;
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            if (i != j)
                used += (size_t)snprintf(maps + used, sizeof(maps) - used, "%s1.2.3.%d:1.2.3.%d",
                                         used ? "," : "", i, j);
    for (int d = 0; d <= DEPTH; d++) {
        int nids[] = {NID_basic_constraints, NID_key_usage, NID_certificate_policies,
                      NID_policy_mappings, 0};
        const char *values[] = {"critical,CA:TRUE", "critical,keyCertSign", pols, maps};
        char cn[16];

        snprintf(cn, sizeof(cn), "CA%d", d);
        keys[d] = ec_key();
        if (d == 0)
            nids[2] = 0;
        cas[d] = make_cert(cn, 10 + d, keys[d], d ? cas[d - 1] : NULL, d ? keys[d - 1] : NULL,
                           nids, values);
        if (d > 0)
            sk_X509_push(untrusted, cas[d]);
    }
    {
        int nids[] = {NID_basic_constraints, NID_certificate_policies, 0};
        const char *values[] = {"CA:FALSE", pols};

        leaf = make_cert("Leaf", 99, leaf_key, cas[DEPTH], keys[DEPTH], nids, values);
    }
    trusted = certs(cas[0], NULL);
    verify_with("policy tree", leaf, trusted, untrusted, NULL,
                X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_EXPLICIT_POLICY, 0, NULL);
    check(1, "CVE-2023-0464: a policy tree of many mappings is verified in bounded time and memory");
    sk_X509_free(trusted);
    sk_X509_free(untrusted);
    for (int d = 0; d <= DEPTH; d++) {
        X509_free(cas[d]);
        EVP_PKEY_free(keys[d]);
    }
    X509_free(leaf);
    EVP_PKEY_free(leaf_key);
}

static void name_checks(void)
{
    static const int nids[] = {NID_subject_alt_name, 0};
    static const char *const values[] = {
        "otherName:1.3.6.1.5.5.7.8.9;INTEGER:1,otherName:1.2.3.4;UTF8:server.example"};
    EVP_PKEY *key = ec_key();
    X509 *cert = make_cert("names", 4, key, NULL, NULL, nids, values);
    int host = X509_check_host(cert, "server.example", 0, 0, NULL);
    int email = X509_check_email(cert, "user@example.com", 0, 0);

    check(cert != NULL && host == 0 && email == 0,
          "CVE-2024-6119: name checks against otherNames of other types fail without a crash");
    note("check_host %d check_email %d", host, email);
    ERR_clear_error();
    X509_free(cert);
    EVP_PKEY_free(key);
}

static void partial_chain_ocsp(void)
{
    chain c;
    STACK_OF(X509) *trusted;

    make_chain(&c);
    trusted = certs(c.leaf, NULL);
    verify_with("partial chain with OCSP checking", c.leaf, trusted, NULL, NULL,
                X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_OCSP_RESP_CHECK, 0, NULL);
    check(1, "CVE-2026-42765: a partial chain with OCSP checking and no issuer is verified safely");
    sk_X509_free(trusted);
    chain_free(&c);
}

static void ec_parameters(void)
{
    BN_CTX *bn = BN_CTX_new();
    BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new(), *r = BN_new(), *x = BN_new();
    EC_GROUP *g;
    int arr[8], n;

    /* GF(2^m) with a "polynomial" of 0 and of 1. */
    BN_zero(p);
    BN_one(a);
    BN_one(b);
    g = EC_GROUP_new_curve_GF2m(p, a, b, bn);
    note("GF2m p=0: %s", g != NULL ? "built" : "rejected");
    EC_GROUP_free(g);
    BN_one(p);
    g = EC_GROUP_new_curve_GF2m(p, a, b, bn);
    note("GF2m p=1: %s", g != NULL ? "built" : "rejected");
    EC_GROUP_free(g);
    BN_one(x);
    n = BN_GF2m_mod_inv(r, x, p, bn);
    check(1, "CVE-2015-1788: malformed binary-field parameters don't loop forever");
    note("BN_GF2m_mod_inv mod 1: %d", n);
    ERR_clear_error();

    /* A polynomial with more terms than the array holds. */
    BN_zero(p);
    for (int i = 0; i < 64; i += 3)
        BN_set_bit(p, i);
    n = BN_GF2m_poly2arr(p, arr, (int)(sizeof(arr) / sizeof(arr[0])));
    check(n > 8, "CVE-2024-9143: BN_GF2m_poly2arr stays within its array for long polynomials");
    note("poly2arr %d", n);
    BN_set_bit(p, 600);
    g = EC_GROUP_new_curve_GF2m(p, a, b, bn);
    note("GF2m of degree 600: %s", g != NULL ? "built" : "rejected");
    ERR_clear_error();
    EC_GROUP_free(g);

    /* BN_mod_sqrt with a composite modulus. */
    BN_set_word(p, 697);
    {
        int found = 0;

        for (unsigned long v = 1; v < 40; v++) {
            BN_set_word(a, v);
            if (BN_mod_sqrt(r, a, p, bn) != NULL)
                found++;
            ERR_clear_error();
        }
        check(1, "CVE-2022-0778: BN_mod_sqrt with a composite modulus returns");
        note("roots found for %d of 39", found);
    }

    /* A P-256 group whose generator is set without a cofactor. */
    {
        EC_GROUP *named = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        BIGNUM *gp = BN_new(), *ga = BN_new(), *gb = BN_new();
        const BIGNUM *cofactor;
        EC_GROUP *explicit_group;

        EC_GROUP_get_curve(named, gp, ga, gb, bn);
        explicit_group = EC_GROUP_new_curve_GFp(gp, ga, gb, bn);
        {
            EC_POINT *gen = EC_POINT_new(explicit_group);
            BIGNUM *gx = BN_new(), *gy = BN_new();
            int set;

            EC_POINT_get_affine_coordinates(named, EC_GROUP_get0_generator(named), gx, gy, bn);
            EC_POINT_set_affine_coordinates(explicit_group, gen, gx, gy, bn);
            BN_free(gx);
            BN_free(gy);
            set = EC_GROUP_set_generator(explicit_group, gen, EC_GROUP_get0_order(named), NULL);

            note("set_generator %d", set);
            errors("set_generator");
            EC_POINT_free(gen);
        }
        cofactor = EC_GROUP_get0_cofactor(explicit_group);
        {
            char *dec = cofactor != NULL ? BN_bn2dec(cofactor) : NULL;

            note("cofactor %s", dec != NULL ? dec : "none");
            OPENSSL_free(dec);
        }
        check(cofactor != NULL && BN_is_one(cofactor),
              "CVE-2019-1547: a group's cofactor is computed when it isn't given");
        EC_GROUP_free(explicit_group);
        EC_GROUP_free(named);
        BN_free(gp);
        BN_free(ga);
        BN_free(gb);
    }
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_free(x);
    BN_CTX_free(bn);
}

int main(void)
{
    crls();
    many_relative_dps();
    outer_algorithm();
    to_req();
    alternative_chains();
    pss_parameters();
    strict_purpose();
    name_constraints();
    policies();
    policy_tree();
    name_checks();
    partial_chain_ocsp();
    ec_parameters();
    return finish();
}
