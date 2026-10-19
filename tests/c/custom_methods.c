/*
 * Conformance test for two custom methods end to end, in TAP format (the other method
 * families' end-to-end paths are in rsa_ops, evp_rsa_legacy, evp_ec_legacy, evp_dh_exch,
 * evp_dsa_sig, rand and ui):
 *
 * - An application's X509_LOOKUP_METHOD as the only source of a CA (X509_LOOKUP_meth_new(3)):
 *   X509_verify_cert finds the issuer through its get_by_subject, which then sits in the
 *   store's cache; the calls it gets, the chain, and the error when it has nothing.
 * - An application's default UI_METHOD (UI_set_default_method(3)) answering the pass phrase
 *   prompt when a PEM private key is read with no callback, in PKCS #8 and traditional form,
 *   with the right and a wrong pass phrase; the prompts it sees.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

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

/* ---- Certificates ---- */

static X509 *make_cert(const char *cn, EVP_PKEY *key, X509 *issuer, EVP_PKEY *ikey, int ca)
{
    X509 *x = X509_new();
    X509_NAME *name = X509_NAME_new();
    X509V3_CTX v3;
    X509_EXTENSION *ext;

    X509_set_version(x, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(x), ca ? 1 : 2);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_subject_name(x, name);
    X509_set_issuer_name(x, issuer != NULL ? X509_get_subject_name(issuer) : name);
    X509_NAME_free(name);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400L * 365);
    X509_set_pubkey(x, key);
    X509V3_set_ctx(&v3, issuer != NULL ? issuer : x, x, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &v3, NID_basic_constraints,
                              ca ? "critical,CA:TRUE" : "CA:FALSE");
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
    if (ca) {
        ext = X509V3_EXT_conf_nid(NULL, &v3, NID_key_usage, "critical,keyCertSign,cRLSign");
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    X509_sign(x, ikey != NULL ? ikey : key, EVP_sha256());
    return x;
}

/* ---- The lookup method: the CA, by its subject, when `serve` is set ---- */

static X509 *the_ca;
static int serve, by_subject_calls, init_calls, shutdown_calls;

static int lu_init(X509_LOOKUP *ctx)
{
    (void)ctx;
    init_calls++;
    return 1;
}
static int lu_shutdown(X509_LOOKUP *ctx)
{
    (void)ctx;
    shutdown_calls++;
    return 1;
}
static int lu_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const X509_NAME *name,
                         X509_OBJECT *ret)
{
    (void)ctx;
    by_subject_calls++;
    if (!serve || type != X509_LU_X509
        || X509_NAME_cmp(name, X509_get_subject_name(the_ca)) != 0)
        return 0;
    return X509_OBJECT_set1_X509(ret, the_ca);
}

static void verify(const char *label, X509_STORE *store, X509 *leaf)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int r;

    by_subject_calls = 0;
    X509_STORE_CTX_init(ctx, store, leaf, NULL);
    r = X509_verify_cert(ctx);
    printf("  %s: %d, error %d (%s), chain of %d, %d get_by_subject calls\n", label, r,
           X509_STORE_CTX_get_error(ctx),
           X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)),
           sk_X509_num(X509_STORE_CTX_get0_chain(ctx)), by_subject_calls);
    X509_STORE_CTX_free(ctx);
    ERR_clear_error();
}

static void test_lookup(void)
{
    EVP_PKEY *cakey = EVP_EC_gen("P-256"), *leafkey = EVP_EC_gen("P-256");
    X509 *leaf;
    X509_LOOKUP_METHOD *m = X509_LOOKUP_meth_new("application lookup");
    X509_STORE *store = X509_STORE_new(), *empty = X509_STORE_new();

    printf("# an application's lookup method as the only source of the CA\n");
    the_ca = make_cert("Lookup CA", cakey, NULL, NULL, 1);
    leaf = make_cert("leaf.example", leafkey, the_ca, cakey, 0);
    X509_LOOKUP_meth_set_init(m, lu_init);
    X509_LOOKUP_meth_set_shutdown(m, lu_shutdown);
    X509_LOOKUP_meth_set_get_by_subject(m, lu_by_subject);
    check(X509_STORE_add_lookup(store, m) != NULL, "the lookup added");
    printf("  init calls %d\n", init_calls);

    serve = 0;
    verify("with nothing served", store, leaf);
    check(sk_X509_OBJECT_num(X509_STORE_get0_objects(store)) == 0, "nothing cached");
    serve = 1;
    verify("with the CA served", store, leaf);
    printf("  %d objects cached\n", sk_X509_OBJECT_num(X509_STORE_get0_objects(store)));
    serve = 0;
    verify("again, from the cache", store, leaf);
    verify("a store without the lookup", empty, leaf);

    X509_STORE_free(store);
    printf("  shutdown calls %d\n", shutdown_calls);
    X509_STORE_free(empty);
    X509_LOOKUP_meth_free(m);
    X509_free(leaf);
    X509_free(the_ca);
    EVP_PKEY_free(cakey);
    EVP_PKEY_free(leafkey);
}

/* ---- The default UI method: answers a pass phrase prompt with `answer` ---- */

static const char *answer;
static int reads;

static int ui_reader(UI *ui, UI_STRING *uis)
{
    int type = UI_get_string_type(uis);

    reads++;
    printf("  the UI reads (type %d, %s): [%s]\n", type,
           (UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO) ? "echo" : "no echo",
           UI_get0_output_string(uis));
    if (type == UIT_PROMPT || type == UIT_VERIFY)
        return UI_set_result(ui, uis, answer) >= 0;
    return 1;
}
static int ui_writer(UI *ui, UI_STRING *uis)
{
    (void)ui;
    printf("  the UI writes (type %d): [%s]\n", UI_get_string_type(uis),
           UI_get0_output_string(uis));
    return 1;
}

static void read_back(const char *label, const char *pem, long len, EVP_PKEY *key,
                      const char *with)
{
    BIO *b = BIO_new_mem_buf(pem, (int)len);
    EVP_PKEY *got;

    answer = with;
    reads = 0;
    got = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    printf("  %s with [%s]: %s, %d reads\n", label, with, got != NULL ? "read" : "failed",
           reads);
    if (got != NULL)
        check(EVP_PKEY_eq(got, key) == 1, "the same key");
    else
        errors();
    EVP_PKEY_free(got);
    BIO_free(b);
}

static void test_ui(void)
{
    UI_METHOD *m = UI_create_method("application UI");
    EVP_PKEY *key = EVP_EC_gen("P-256");
    BIO *p8 = BIO_new(BIO_s_mem()), *trad = BIO_new(BIO_s_mem());
    char *pem;
    long len;

    printf("# the default UI method answering a PEM pass phrase\n");
    UI_method_set_reader(m, ui_reader);
    UI_method_set_writer(m, ui_writer);
    check(PEM_write_bio_PrivateKey(p8, key, EVP_aes_256_cbc(), (const unsigned char *)"secret",
                                   6, NULL, NULL) == 1,
          "a PKCS #8 key encrypted");
    check(PEM_write_bio_PrivateKey_traditional(trad, key, EVP_aes_128_cbc(),
                                               (const unsigned char *)"secret", 6, NULL, NULL)
              == 1,
          "a traditional key encrypted");
    UI_set_default_method(m);

    len = BIO_get_mem_data(p8, &pem);
    read_back("PKCS #8", pem, len, key, "secret");
    read_back("PKCS #8", pem, len, key, "wrong");
    len = BIO_get_mem_data(trad, &pem);
    read_back("traditional", pem, len, key, "secret");
    read_back("traditional", pem, len, key, "wrong");

    UI_set_default_method(NULL);
    UI_destroy_method(m);
    BIO_free(p8);
    BIO_free(trad);
    EVP_PKEY_free(key);
}

int main(void)
{
    test_lookup();
    test_ui();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
