/*
 * Conformance test for DANE's settings and records (SSL_CTX_dane_enable(3),
 * SSL_CTX_dane_mtype_set(3), SSL_dane_enable(3), SSL_dane_tlsa_add(3), SSL_dane_set_flags(3),
 * SSL_get0_dane_authority(3), SSL_get0_dane_tlsa(3), SSL_get0_dane): enabling a context and a
 * connection (with its SNI name and reference identifier), matching types, every check a TLSA
 * record goes through, flags, and what a connection reports before any handshake; then
 * handshakes verifying the server with records of every usage (DANE-EE, DANE-TA, PKIX-TA,
 * PKIX-EE), selector and matching type: with and without the CA sent or in the trust store,
 * name checks (and DANE_FLAG_NO_DANE_EE_NAMECHECKS), digest agility, no match
 * (X509_V_ERR_DANE_NO_MATCH), and what the client reports of the match afterwards; and
 * X509_verify_cert with a connection's state (X509_STORE_CTX_set0_dane), for a certificate and
 * for a raw public key.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

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

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBmzCCAUCgAwIBAgIUHfTNPsE5lGD3nT8fR1Nd24C0BsgwCgYIKoZIzj0EAwIw\n"
    "KjEQMA4GA1UECgwHRXhhbXBsZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0y\n"
    "NjEwMTgwOTMyNDZaGA8yMTI2MDkyNDA5MzI0NlowKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
    "A0IABLfBhwdOVIbIOwWlwBUmASMV1CS8SOnPi/viY8J5Ml2EwP5wOJe2mtSxgMlo\n"
    "COh/RepmP8BAKwLO40zMoIv99xOjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n"
    "AQH/BAQDAgEGMB0GA1UdDgQWBBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjO\n"
    "PQQDAgNJADBGAiEA8n+eFk52ddsEdBxGgskm6aD0for7v4Ys0o0bN2t9wq8CIQDY\n"
    "V8DuzBptykbkta8E/bbLFVRo0LjIzjF/bGH+iqEMeA==\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBxDCCAWqgAwIBAgICA+kwCgYIKoZIzj0EAwIwKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0yNjEwMTgwOTMyNDZaGA8yMTI2\n"
    "MDkyNDA5MzI0NlowGTEXMBUGA1UEAwwOc2VydmVyLmV4YW1wbGUwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAARQwBruuNdz4xCD1gvolSn84T4lhmxXimDiZyo55Kdd\n"
    "rfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHko4GOMIGLMAkGA1UdEwQC\n"
    "MAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBkGA1UdEQQS\n"
    "MBCCDnNlcnZlci5leGFtcGxlMB0GA1UdDgQWBBTJhnvwTSY1MKJTWPQEV8hTOvQj\n"
    "CzAfBgNVHSMEGDAWgBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjOPQQDAgNI\n"
    "ADBFAiA9HtDZKkG58jRwUNQ4CbP61ozryZRRkz7W3RF94vEpSQIhAKwrnOIS/FEg\n"
    "N7iBJyOB+Buj5UbPic6SYxuj11J3f/PG\n"
    "-----END CERTIFICATE-----\n";


static X509 *cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

/* Adds a record and prints the result and errors. */
static int add(SSL *s, int usage, int selector, int mtype, const unsigned char *data, size_t len,
               const char *what)
{
    int r = SSL_dane_tlsa_add(s, (uint8_t)usage, (uint8_t)selector, (uint8_t)mtype, data, len);

    printf("  %d %d %d (%zu octets) -> %d\n", usage, selector, mtype, len, r);
    errors();
    check(1, what);
    return r;
}

static void report(SSL *s)
{
    X509 *mcert = (X509 *)1;
    EVP_PKEY *mspki = (EVP_PKEY *)1;
    uint8_t u = 9, sel = 9, mt = 9;
    const unsigned char *data = (const unsigned char *)"x";
    size_t dlen = 99;
    int a = SSL_get0_dane_authority(s, &mcert, &mspki);
    int t = SSL_get0_dane_tlsa(s, &u, &sel, &mt, &data, &dlen);

    printf("  authority %d (%s, %s) tlsa %d (%d %d %d, %zu)\n", a, mcert == (X509 *)1 ? "untouched" : "set",
           mspki == (EVP_PKEY *)1 ? "untouched" : "set", t, u, sel, mt, dlen);
}


static const char SERVER_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvhwC7sEHpNUtRIwR\n"
    "1HpSoTfsfnL+ayakODf8YQkvzpKhRANCAARQwBruuNdz4xCD1gvolSn84T4lhmxX\n"
    "imDiZyo55KddrfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHk\n"
    "-----END PRIVATE KEY-----\n";

/* What a record's data is made from. */
enum source { LEAF_CERT, LEAF_SPKI, CA_CERT, CA_SPKI, WRONG };

struct rec {
    int usage, selector, mtype;
    enum source from;
};

static X509 *hs_ca, *hs_leaf;

/* A record's data: the source's DER, or its digest for the matching type. */
static size_t rec_data(const struct rec *r, unsigned char *out, size_t max)
{
    unsigned char *der = NULL, junk[32];
    int len;
    unsigned int n = 0;
    const EVP_MD *md = r->mtype == 1 ? EVP_sha256() : r->mtype == 2 ? EVP_sha512() : NULL;

    switch (r->from) {
    case LEAF_CERT:
        len = i2d_X509(hs_leaf, &der);
        break;
    case LEAF_SPKI:
        len = i2d_PUBKEY(X509_get0_pubkey(hs_leaf), &der);
        break;
    case CA_CERT:
        len = i2d_X509(hs_ca, &der);
        break;
    case CA_SPKI:
        len = i2d_PUBKEY(X509_get0_pubkey(hs_ca), &der);
        break;
    default:
        memset(junk, 0x5a, sizeof(junk));
        len = (int)sizeof(junk);
        der = OPENSSL_malloc(sizeof(junk));
        memcpy(der, junk, sizeof(junk));
    }
    if (len <= 0 || (size_t)len > max) {
        printf("Bail out! record data\n");
        exit(1);
    }
    if (md == NULL) {
        memcpy(out, der, (size_t)len);
        n = (unsigned int)len;
    } else {
        EVP_Digest(der, (size_t)len, out, &n, md, NULL);
    }
    OPENSSL_free(der);
    return n;
}

static int verify_cb(int ok, X509_STORE_CTX *xs)
{
    printf("  verify cb ok=%d depth=%d error=%d\n", ok, X509_STORE_CTX_get_error_depth(xs),
        X509_STORE_CTX_get_error(xs));
    return ok;
}

/* Runs both ends' handshakes in turn until both finish (1) or one fails (0). */
static int run(SSL *c, SSL *s)
{
    int cdone = 0, sdone = 0, round;

    for (round = 0; round < 64 && (!cdone || !sdone); round++) {
        int i;

        for (i = 0; i < 2; i++) {
            SSL *x = i == 0 ? c : s;
            int *done = i == 0 ? &cdone : &sdone, r, e;

            if (*done)
                continue;
            r = SSL_do_handshake(x);
            if (r == 1) {
                *done = 1;
                continue;
            }
            e = SSL_get_error(x, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                return 0;
            }
        }
    }
    return cdone && sdone;
}

/* The common name of a certificate, or "(none)". */
static const char *cn(X509 *x, char *buf, int len)
{
    if (x == NULL)
        return "(none)";
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, buf, len) < 0)
        return "(no CN)";
    return buf;
}

/*
 * A handshake whose client verifies the server with these records (for `base`, with these DANE
 * flags and verify mode), then what it reports.
 */
static void dane_case(const char *what, SSL_CTX *cctx, SSL_CTX *sctx, int version,
    const char *base, unsigned long flags, int mode, const struct rec *recs, int nrecs)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    X509 *mcert = (X509 *)1;
    EVP_PKEY *mspki = (EVP_PKEY *)1;
    uint8_t u = 9, sel = 9, mt = 9;
    const unsigned char *data = NULL;
    size_t dlen = 0;
    char buf[64];
    int i, ok, depth, tdepth;
    STACK_OF(X509) *chain;

    printf("# %s\n", what);
    if (c == NULL || s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1) {
        printf("Bail out! connection\n");
        exit(1);
    }
    SSL_set_min_proto_version(c, version);
    SSL_set_max_proto_version(c, version);
    SSL_set_verify(c, mode, verify_cb);
    if (SSL_dane_enable(c, base) != 1) {
        printf("Bail out! SSL_dane_enable\n");
        exit(1);
    }
    if (flags != 0)
        SSL_dane_set_flags(c, flags);
    for (i = 0; i < nrecs; i++) {
        unsigned char d[2048];
        size_t n = rec_data(&recs[i], d, sizeof(d));

        if (SSL_dane_tlsa_add(c, (uint8_t)recs[i].usage, (uint8_t)recs[i].selector,
                (uint8_t)recs[i].mtype, d, n) != 1) {
            printf("Bail out! SSL_dane_tlsa_add\n");
            exit(1);
        }
    }
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    ok = run(c, s);
    printf("  handshake %s, verify result %ld\n", ok ? "done" : "failed", SSL_get_verify_result(c));
    errors();
    depth = SSL_get0_dane_authority(c, &mcert, &mspki);
    tdepth = SSL_get0_dane_tlsa(c, &u, &sel, &mt, &data, &dlen);
    printf("  authority %d: cert %s, key %s\n", depth,
        mcert == (X509 *)1 ? "untouched" : cn(mcert, buf, sizeof(buf)),
        mspki == (EVP_PKEY *)1 ? "untouched" : mspki == NULL ? "(none)" : "set");
    printf("  tlsa %d: %d %d %d, %zu octets%s\n", tdepth, u, sel, mt, dlen,
        data == NULL ? "" : ", data set");
    chain = SSL_get0_verified_chain(c);
    printf("  verified chain %d\n", chain == NULL ? -1 : sk_X509_num(chain));
    check(1, what);
    if (ok) {
        printf("  after SSL_clear: authority %d\n",
            (SSL_clear(c), SSL_get0_dane_authority(c, NULL, NULL)));
    }
    SSL_free(c);
    SSL_free(s);
}


/* X509_verify_cert with a connection's DANE state (X509_STORE_CTX_set0_dane), outside TLS. */
static void direct(SSL_CTX *ctx)
{
    static const struct rec ee[] = { { 3, 1, 1, LEAF_SPKI } };
    static const struct rec ee_full[] = { { 3, 1, 0, LEAF_SPKI } };
    static const struct rec wrong[] = { { 3, 1, 1, WRONG } };
    static const struct rec ta[] = { { 2, 0, 0, CA_CERT } };
    static const struct rec *const sets[] = { ee, ee_full, wrong, ta };
    static const char *const names[] = { "3 1 1", "3 1 0", "3 1 1 (wrong)", "2 0 0" };
    X509_STORE *store = X509_STORE_new();
    int i, rpk;

    for (rpk = 0; rpk < 2; rpk++) {
        for (i = 0; i < 4; i++) {
            SSL *s = SSL_new(ctx);
            X509_STORE_CTX *xs = X509_STORE_CTX_new();
            unsigned char d[2048];
            size_t n = rec_data(sets[i], d, sizeof(d));
            int r;

            printf("# X509_verify_cert, %s, %s\n", rpk ? "a raw public key" : "a certificate",
                names[i]);
            if (s == NULL || xs == NULL || SSL_dane_enable(s, "server.example") != 1
                || SSL_dane_tlsa_add(s, (uint8_t)sets[i]->usage, (uint8_t)sets[i]->selector,
                       (uint8_t)sets[i]->mtype, d, n) != 1) {
                printf("Bail out! direct\n");
                exit(1);
            }
            if (rpk)
                r = X509_STORE_CTX_init_rpk(xs, store, X509_get0_pubkey(hs_leaf));
            else
                r = X509_STORE_CTX_init(xs, store, hs_leaf, NULL);
            X509_STORE_CTX_set0_dane(xs, SSL_get0_dane(s));
            X509_VERIFY_PARAM_set1_host(X509_STORE_CTX_get0_param(xs), "server.example", 0);
            X509_STORE_CTX_set_verify_cb(xs, verify_cb);
            r = r == 1 ? X509_verify_cert(xs) : -2;
            printf("  result %d, error %d at %d\n", r, X509_STORE_CTX_get_error(xs),
                X509_STORE_CTX_get_error_depth(xs));
            errors();
            printf("  the connection's authority %d\n", SSL_get0_dane_authority(s, NULL, NULL));
            check(1, names[i]);
            X509_STORE_CTX_free(xs);
            SSL_free(s);
        }
    }
    X509_STORE_free(store);
}

/* The handshakes, with every usage, selector and matching type. */
static void handshakes(void)
{
    SSL_CTX *bare = SSL_CTX_new(TLS_client_method()), *store = SSL_CTX_new(TLS_client_method()),
            *leaf_only = SSL_CTX_new(TLS_server_method()),
            *with_ca = SSL_CTX_new(TLS_server_method());
    BIO *kb = BIO_new_mem_buf(SERVER_KEY_PEM, -1);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
    static const struct rec ee_spki_256[] = { { 3, 1, 1, LEAF_SPKI } };
    static const struct rec ee_cert_full[] = { { 3, 0, 0, LEAF_CERT } };
    static const struct rec ee_spki_512[] = { { 3, 1, 2, LEAF_SPKI } };
    static const struct rec ee_wrong[] = { { 3, 1, 1, WRONG } };
    static const struct rec agility[] = { { 3, 1, 2, WRONG }, { 3, 1, 1, LEAF_SPKI } };
    static const struct rec agility_full[] = { { 3, 1, 2, WRONG }, { 3, 1, 0, LEAF_SPKI } };
    static const struct rec ta_cert_full[] = { { 2, 0, 0, CA_CERT } };
    static const struct rec ta_spki_256[] = { { 2, 1, 1, CA_SPKI } };
    static const struct rec ta_cert_512[] = { { 2, 0, 2, CA_CERT } };
    static const struct rec ta_spki_full[] = { { 2, 1, 0, CA_SPKI } };
    static const struct rec ta_wrong[] = { { 2, 0, 1, WRONG } };
    static const struct rec pkix_ta[] = { { 0, 0, 1, CA_CERT } };
    static const struct rec pkix_ta_wrong[] = { { 0, 1, 1, WRONG } };
    static const struct rec pkix_ee[] = { { 1, 1, 1, LEAF_SPKI } };
    static const struct rec pkix_ee_full[] = { { 1, 0, 0, LEAF_CERT } };
    static const struct rec mixed[] = { { 3, 1, 1, WRONG }, { 2, 0, 0, CA_CERT },
        { 1, 1, 1, WRONG } };
    static const struct rec mixed_pkix[] = { { 3, 1, 1, WRONG }, { 0, 0, 1, CA_CERT } };
    static const struct rec ta_then_ee[] = { { 2, 1, 1, CA_SPKI }, { 3, 1, 1, LEAF_SPKI } };
    int v;

    if (bare == NULL || store == NULL || leaf_only == NULL || with_ca == NULL || key == NULL
        || SSL_CTX_use_certificate(leaf_only, hs_leaf) != 1
        || SSL_CTX_use_PrivateKey(leaf_only, key) != 1
        || SSL_CTX_use_certificate(with_ca, hs_leaf) != 1
        || SSL_CTX_use_PrivateKey(with_ca, key) != 1 || SSL_CTX_add1_chain_cert(with_ca, hs_ca) != 1
        || X509_STORE_add_cert(SSL_CTX_get_cert_store(store), hs_ca) != 1
        || SSL_CTX_dane_enable(bare) != 1 || SSL_CTX_dane_enable(store) != 1) {
        printf("Bail out! handshake contexts\n");
        exit(1);
    }

    for (v = 0; v < 2; v++) {
        int version = v == 0 ? TLS1_3_VERSION : TLS1_2_VERSION;

        printf("# -- %s\n", v == 0 ? "TLS 1.3" : "TLS 1.2");
        dane_case("DANE-EE SPKI SHA2-256", bare, leaf_only, version, "server.example", 0,
            SSL_VERIFY_PEER, ee_spki_256, 1);
        dane_case("DANE-TA Cert Full, the CA not sent", bare, leaf_only, version,
            "server.example", 0, SSL_VERIFY_PEER, ta_cert_full, 1);
        dane_case("PKIX-TA Cert SHA2-256, the CA in the store", store, leaf_only, version,
            "server.example", 0, SSL_VERIFY_PEER, pkix_ta, 1);
    }
    printf("# -- TLS 1.3\n");
    v = TLS1_3_VERSION;
    dane_case("DANE-EE Cert Full", bare, leaf_only, v, "server.example", 0, SSL_VERIFY_PEER,
        ee_cert_full, 1);
    dane_case("DANE-EE SPKI SHA2-512", bare, leaf_only, v, "server.example", 0, SSL_VERIFY_PEER,
        ee_spki_512, 1);
    dane_case("DANE-EE, another name", bare, leaf_only, v, "other.example", 0, SSL_VERIFY_PEER,
        ee_spki_256, 1);
    dane_case("DANE-EE, another name, no name checks", bare, leaf_only, v, "other.example",
        DANE_FLAG_NO_DANE_EE_NAMECHECKS, SSL_VERIFY_PEER, ee_spki_256, 1);
    dane_case("DANE-EE, no match", bare, leaf_only, v, "server.example", 0, SSL_VERIFY_PEER,
        ee_wrong, 1);
    dane_case("DANE-EE, no match, SSL_VERIFY_NONE", bare, leaf_only, v, "server.example", 0,
        SSL_VERIFY_NONE, ee_wrong, 1);
    dane_case("DANE-EE, no match, the CA in the store", store, leaf_only, v, "server.example", 0,
        SSL_VERIFY_PEER, ee_wrong, 1);
    dane_case("digest agility: the strongest digest only", bare, leaf_only, v, "server.example",
        0, SSL_VERIFY_PEER, agility, 2);
    dane_case("digest agility: Full is always tried", bare, leaf_only, v, "server.example", 0,
        SSL_VERIFY_PEER, agility_full, 2);
    dane_case("DANE-TA Cert Full, the CA sent", bare, with_ca, v, "server.example", 0,
        SSL_VERIFY_PEER, ta_cert_full, 1);
    dane_case("DANE-TA SPKI SHA2-256, the CA sent", bare, with_ca, v, "server.example", 0,
        SSL_VERIFY_PEER, ta_spki_256, 1);
    dane_case("DANE-TA SPKI SHA2-256, the CA not sent", bare, leaf_only, v, "server.example", 0,
        SSL_VERIFY_PEER, ta_spki_256, 1);
    dane_case("DANE-TA Cert SHA2-512, the CA sent", bare, with_ca, v, "server.example", 0,
        SSL_VERIFY_PEER, ta_cert_512, 1);
    dane_case("DANE-TA SPKI Full, a bare key", bare, leaf_only, v, "server.example", 0,
        SSL_VERIFY_PEER, ta_spki_full, 1);
    dane_case("DANE-TA SPKI Full, the CA sent", bare, with_ca, v, "server.example", 0,
        SSL_VERIFY_PEER, ta_spki_full, 1);
    dane_case("DANE-TA, another name", bare, with_ca, v, "other.example", 0, SSL_VERIFY_PEER,
        ta_spki_256, 1);
    dane_case("DANE-TA, another name, no name checks", bare, with_ca, v, "other.example",
        DANE_FLAG_NO_DANE_EE_NAMECHECKS, SSL_VERIFY_PEER, ta_spki_256, 1);
    dane_case("DANE-TA, no match", bare, with_ca, v, "server.example", 0, SSL_VERIFY_PEER,
        ta_wrong, 1);
    dane_case("DANE-TA, no match, the CA in the store", store, with_ca, v, "server.example", 0,
        SSL_VERIFY_PEER, ta_wrong, 1);
    dane_case("PKIX-TA, the CA not in the store", bare, with_ca, v, "server.example", 0,
        SSL_VERIFY_PEER, pkix_ta, 1);
    dane_case("PKIX-TA, the CA sent and in the store", store, with_ca, v, "server.example", 0,
        SSL_VERIFY_PEER, pkix_ta, 1);
    dane_case("PKIX-TA, no match", store, leaf_only, v, "server.example", 0, SSL_VERIFY_PEER,
        pkix_ta_wrong, 1);
    dane_case("PKIX-EE SPKI SHA2-256", store, leaf_only, v, "server.example", 0, SSL_VERIFY_PEER,
        pkix_ee, 1);
    dane_case("PKIX-EE Cert Full", store, leaf_only, v, "server.example", 0, SSL_VERIFY_PEER,
        pkix_ee_full, 1);
    dane_case("PKIX-EE, the CA not in the store", bare, leaf_only, v, "server.example", 0,
        SSL_VERIFY_PEER, pkix_ee, 1);
    dane_case("PKIX-EE, another name", store, leaf_only, v, "other.example",
        DANE_FLAG_NO_DANE_EE_NAMECHECKS, SSL_VERIFY_PEER, pkix_ee, 1);
    dane_case("mixed: DANE-EE wrong, DANE-TA right, PKIX-EE wrong", bare, with_ca, v,
        "server.example", 0, SSL_VERIFY_PEER, mixed, 3);
    dane_case("mixed: DANE-EE wrong, PKIX-TA right", store, leaf_only, v, "server.example", 0,
        SSL_VERIFY_PEER, mixed_pkix, 2);
    dane_case("DANE-TA and DANE-EE both right", bare, with_ca, v, "server.example", 0,
        SSL_VERIFY_PEER, ta_then_ee, 2);

    direct(bare);

    SSL_CTX_free(bare);
    SSL_CTX_free(store);
    SSL_CTX_free(leaf_only);
    SSL_CTX_free(with_ca);
    EVP_PKEY_free(key);
    BIO_free(kb);
}

int main(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *s = SSL_new(ctx), *s2;
    X509 *ca = cert(CA_PEM), *leaf = cert(SERVER_PEM);
    unsigned char *ca_der = NULL, *spki = NULL, digest[64], junk[40];
    int ca_len = i2d_X509(ca, &ca_der), spki_len = i2d_PUBKEY(X509_get0_pubkey(leaf), &spki);
    unsigned int dlen = 0;
    const char *name;

    setvbuf(stdout, NULL, _IONBF, 0);
    memset(junk, 0x30, sizeof(junk));

    printf("# before enabling\n");
    report(s);
    check(SSL_get0_dane(s) != NULL, "SSL_get0_dane");
    check(add(s, 3, 1, 1, digest, 32, "a record") == -1, "a record needs DANE");
    check(SSL_dane_enable(s, "server.example") == 0, "the context isn't DANE-enabled");
    errors();

    printf("# the context\n");
    check(SSL_CTX_dane_enable(ctx) == 1, "SSL_CTX_dane_enable");
    check(SSL_CTX_dane_enable(ctx) == 1, "again");
    check(SSL_CTX_dane_mtype_set(ctx, EVP_sha256(), 0, 1) == 0, "Full(0) takes no digest");
    errors();
    check(SSL_CTX_dane_mtype_set(ctx, NULL, 0, 0) == 1, "Full(0) without one");
    check(SSL_CTX_dane_mtype_set(ctx, EVP_sha1(), 4, 3) == 1, "a private matching type");
    check(SSL_CTX_dane_mtype_set(ctx, NULL, 2, 5) == 1, "SHA2-512 disabled");
    printf("  ctx flags %lx", SSL_CTX_dane_set_flags(ctx, DANE_FLAG_NO_DANE_EE_NAMECHECKS));
    printf(" %lx", SSL_CTX_dane_set_flags(ctx, 0x10));
    printf(" %lx", SSL_CTX_dane_clear_flags(ctx, 0x10));
    printf(" %lx\n", SSL_CTX_dane_clear_flags(ctx, 0));

    printf("# a connection\n");
    s2 = SSL_new(ctx);
    printf("  ssl flags %lx", SSL_dane_set_flags(s2, 0x20));
    printf(" %lx", SSL_dane_clear_flags(s2, DANE_FLAG_NO_DANE_EE_NAMECHECKS));
    printf(" %lx\n", SSL_dane_clear_flags(s2, 0));
    check(SSL_set_tlsext_host_name(s2, "sni.example") == 1, "an SNI name first");
    check(SSL_dane_enable(s2, "server.example") == 1, "SSL_dane_enable");
    name = SSL_get_servername(s2, TLSEXT_NAMETYPE_host_name);
    printf("  SNI %s\n", name == NULL ? "(null)" : name);
    check(SSL_dane_enable(s2, "server.example") == 0, "already enabled");
    errors();
    report(s2);
    check(SSL_dane_enable(s, "server.example") == 1, "the first connection now");
    name = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    printf("  SNI %s\n", name == NULL ? "(null)" : name);
    {
        SSL *s3 = SSL_new(ctx);

        check(SSL_dane_enable(s3, "") == -1, "an empty base domain");
        errors();
        SSL_free(s3);
    }

    printf("# records\n");
    EVP_Digest(spki, (size_t)spki_len, digest, &dlen, EVP_sha256(), NULL);
    add(s, 3, 1, 1, digest, 32, "DANE-EE SPKI SHA2-256");
    add(s, 3, 1, 1, digest, 31, "a short digest");
    add(s, 3, 1, 1, NULL, 32, "no data");
    add(s, 3, 1, 1, NULL, 0, "no data, no length");
    add(s, 4, 1, 1, digest, 32, "a bad usage");
    add(s, 3, 2, 1, digest, 32, "a bad selector");
    add(s, 3, 1, 2, digest, 64, "a disabled matching type");
    add(s, 3, 1, 3, digest, 32, "an unknown matching type");
    EVP_Digest(spki, (size_t)spki_len, digest, &dlen, EVP_sha1(), NULL);
    add(s, 3, 1, 4, digest, 20, "the private matching type");
    add(s, 2, 0, 0, ca_der, (size_t)ca_len, "DANE-TA Cert Full");
    add(s, 2, 0, 0, ca_der, (size_t)ca_len - 1, "a truncated certificate");
    add(s, 0, 0, 0, junk, sizeof(junk), "not a certificate");
    add(s, 1, 0, 0, ca_der, (size_t)ca_len, "PKIX-EE Cert Full");
    add(s, 2, 1, 0, spki, (size_t)spki_len, "DANE-TA SPKI Full");
    add(s, 3, 1, 0, junk, sizeof(junk), "not a key");
    add(s, 2, 1, 0, spki, (size_t)spki_len + 1, "a key with trailing data");
    add(s, 0, 1, 1, digest, 32, "PKIX-TA SPKI SHA2-256");
    add(s, 1, 0, 0, NULL, 0, "Full with no data");
    report(s);
    check(SSL_dane_tlsa_add(NULL, 3, 1, 1, digest, 32) == 0, "a NULL connection");
    check(SSL_get0_dane_authority(NULL, NULL, NULL) == -1 && SSL_get0_dane_tlsa(NULL, NULL, NULL, NULL, NULL, NULL) == -1,
          "NULL connections");

    hs_ca = ca;
    hs_leaf = leaf;
    handshakes();

    OPENSSL_free(ca_der);
    OPENSSL_free(spki);
    X509_free(ca);
    X509_free(leaf);
    SSL_free(s);
    SSL_free(s2);
    SSL_CTX_free(ctx);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
