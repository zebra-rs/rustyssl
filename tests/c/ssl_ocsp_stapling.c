/*
 * Conformance test for OpenSSL 3.6's OCSP stapling (SSL_CTX_set_tlsext_status_cb(3),
 * X509_STORE_CTX_set_ocsp_resp(3), X509_V_FLAG_OCSP_RESP_CHECK), in TAP format.
 *
 * A CA and a server certificate are made at run time, with OCSP responses the CA signs. The
 * server's status callback sets parsed responses (SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP_EX);
 * a response is stapled only when it is for the certificate (or isn't a successful one). The
 * client's callback reads what arrived, and with X509_V_FLAG_OCSP_RESP_CHECK a TLS 1.3
 * client's verification checks the leaf against it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
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
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static EVP_PKEY *ca_key, *leaf_key;
static X509 *ca, *leaf;

static void add_ext(X509 *x, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX v3;
    X509_EXTENSION *e;

    X509V3_set_ctx(&v3, issuer, x, NULL, NULL, 0);
    e = X509V3_EXT_conf_nid(NULL, &v3, nid, value);
    X509_add_ext(x, e, -1);
    X509_EXTENSION_free(e);
}

static X509 *make_cert(const char *cn, long serial, EVP_PKEY *k, X509 *issuer, EVP_PKEY *ik)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    X509_set_version(x, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, issuer != NULL ? X509_get_subject_name(issuer) : n);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_set_pubkey(x, k);
    if (issuer == NULL) {
        add_ext(x, x, NID_basic_constraints, "critical,CA:TRUE");
        add_ext(x, x, NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
        add_ext(x, x, NID_subject_key_identifier, "hash");
    } else {
        add_ext(x, issuer, NID_basic_constraints, "CA:FALSE");
        add_ext(x, issuer, NID_ext_key_usage, "serverAuth");
        add_ext(x, issuer, NID_authority_key_identifier, "keyid");
    }
    X509_sign(x, ik != NULL ? ik : k, EVP_sha256());
    X509_NAME_free(n);
    return x;
}

/* A response the CA signs: `status` for the certificate with serial `serial`. */
static OCSP_RESPONSE *response(long serial, int status)
{
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    X509 *subject = make_cert("other", serial, leaf_key, ca, ca_key);
    OCSP_CERTID *id = OCSP_cert_to_id(NULL, subject, ca);
    ASN1_TIME *now = X509_gmtime_adj(NULL, -60), *next = X509_gmtime_adj(NULL, 3600);
    ASN1_TIME *rev = X509_gmtime_adj(NULL, -120);
    OCSP_RESPONSE *r;

    OCSP_basic_add1_status(bs, id, status, status == V_OCSP_CERTSTATUS_REVOKED ? 1 : 0,
                           status == V_OCSP_CERTSTATUS_REVOKED ? rev : NULL, now, next);
    OCSP_basic_sign(bs, ca, ca_key, EVP_sha256(), NULL, OCSP_NOCERTS);
    r = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);
    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(bs);
    X509_free(subject);
    ASN1_TIME_free(now);
    ASN1_TIME_free(next);
    ASN1_TIME_free(rev);
    return r;
}

static OCSP_RESPONSE *to_staple;

static int server_status_cb(SSL *s, void *arg)
{
    STACK_OF(OCSP_RESPONSE) *sk;

    (void)arg;
    if (to_staple == NULL)
        return SSL_TLSEXT_ERR_OK;
    sk = sk_OCSP_RESPONSE_new_null();
    sk_OCSP_RESPONSE_push(sk, ASN1_item_dup(ASN1_ITEM_rptr(OCSP_RESPONSE), to_staple));
    SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP_EX, 0, sk);
    return SSL_TLSEXT_ERR_OK;
}

static int client_status_cb(SSL *s, void *arg)
{
    unsigned char *resp = NULL;
    STACK_OF(OCSP_RESPONSE) *sk = NULL;
    long len = SSL_get_tlsext_status_ocsp_resp(s, &resp);
    long n = SSL_ctrl(s, SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP_EX, 0, &sk);

    (void)arg;
    printf("  the client's status callback: %s, %ld parsed\n", len > 0 ? "a response" : "none", n);
    if (sk_OCSP_RESPONSE_num(sk) > 0)
        printf("  its status: %d\n", OCSP_response_status(sk_OCSP_RESPONSE_value(sk, 0)));
    return 1;
}

static int step(SSL *x, int *done, const char *who)
{
    int r, e;

    if (*done)
        return 1;
    r = SSL_do_handshake(x);
    if (r == 1) {
        *done = 1;
        return 1;
    }
    e = SSL_get_error(x, r);
    if (e == SSL_ERROR_WANT_READ)
        return 1;
    printf("  %s: SSL_get_error %d\n", who, e);
    return 0;
}

static int handshake(int version, unsigned long flags, const char *what)
{
    SSL_CTX *sctx = SSL_CTX_new(TLS_server_method()), *cctx = SSL_CTX_new(TLS_client_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;
    int cdone = 0, sdone = 0, round, ok = 1;

    printf("# %s\n", what);
    SSL_CTX_use_certificate(sctx, leaf);
    SSL_CTX_use_PrivateKey(sctx, leaf_key);
    SSL_CTX_set_tlsext_status_cb(sctx, server_status_cb);
    X509_STORE_add_cert(SSL_CTX_get_cert_store(cctx), ca);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_tlsext_status_type(cctx, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(cctx, client_status_cb);
    SSL_CTX_set_max_proto_version(cctx, version);
    X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(cctx), flags);
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    for (round = 0; round < 64 && ok && (!cdone || !sdone); round++)
        ok = step(c, &cdone, "client") && step(s, &sdone, "server");
    printf("  verify result %ld\n", SSL_get_verify_result(c));
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return ok && cdone && sdone;
}

/* X509_verify_cert of the leaf with `resp` as its stapled response (NULL: none). */
static void verify(OCSP_RESPONSE *resp, unsigned long flags, const char *what)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(OCSP_RESPONSE) *sk = sk_OCSP_RESPONSE_new_null();
    int r;

    if (resp != NULL)
        sk_OCSP_RESPONSE_push(sk, resp);
    X509_STORE_add_cert(store, ca);
    X509_STORE_CTX_init(ctx, store, leaf, NULL);
    X509_STORE_CTX_set_ocsp_resp(ctx, sk);
    X509_STORE_CTX_set_flags(ctx, flags);
    r = X509_verify_cert(ctx);
    printf("  %s: %d, error %d at depth %d\n", what, r, X509_STORE_CTX_get_error(ctx),
           X509_STORE_CTX_get_error_depth(ctx));
    ERR_clear_error();
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_OCSP_RESPONSE_free(sk);
}

int main(void)
{
    OCSP_RESPONSE *good, *revoked, *other;
    unsigned long flag = X509_V_FLAG_OCSP_RESP_CHECK;

    ca_key = EVP_EC_gen("P-256");
    leaf_key = EVP_EC_gen("P-256");
    ca = make_cert("OCSP Test CA", 1, ca_key, NULL, NULL);
    leaf = make_cert("server.example", 2, leaf_key, ca, ca_key);
    good = response(2, V_OCSP_CERTSTATUS_GOOD);
    revoked = response(2, V_OCSP_CERTSTATUS_REVOKED);
    other = response(3, V_OCSP_CERTSTATUS_GOOD);
    check(good != NULL && revoked != NULL && other != NULL, "responses made");

    to_staple = good;
    check(handshake(TLS1_3_VERSION, 0, "TLS 1.3, the leaf's response"), "stapled");
    check(handshake(TLS1_2_VERSION, 0, "TLS 1.2, the leaf's response"), "stapled");
    to_staple = other;
    check(handshake(TLS1_3_VERSION, 0, "TLS 1.3, another certificate's response"),
          "not stapled");
    check(handshake(TLS1_2_VERSION, 0, "TLS 1.2, another certificate's response"),
          "not stapled");
    to_staple = NULL;
    check(handshake(TLS1_3_VERSION, 0, "TLS 1.3, no response"), "nothing stapled");

    to_staple = good;
    check(handshake(TLS1_3_VERSION, flag, "TLS 1.3, checked: good"), "the check passes");
    to_staple = revoked;
    check(!handshake(TLS1_3_VERSION, flag, "TLS 1.3, checked: revoked"), "the check fails");
    to_staple = NULL;
    check(!handshake(TLS1_3_VERSION, flag, "TLS 1.3, checked: none"), "the check fails");
    to_staple = good;
    check(!handshake(TLS1_2_VERSION, flag, "TLS 1.2, checked: the response comes too late"),
          "the check fails");

    printf("# X509_STORE_CTX_set_ocsp_resp\n");
    verify(good, flag, "good");
    verify(revoked, flag, "revoked");
    verify(other, flag, "another certificate's");
    verify(NULL, flag, "none");
    verify(good, flag | X509_V_FLAG_OCSP_RESP_CHECK_ALL, "good, the whole chain (the root skipped)");
    verify(NULL, flag | X509_V_FLAG_CRL_CHECK, "none, then CRLs");
    verify(good, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL, "CRLs only, the root skipped");
    verify(good, 0, "unchecked");
    check(1, "verification with stapled responses");

    OCSP_RESPONSE_free(good);
    OCSP_RESPONSE_free(revoked);
    OCSP_RESPONSE_free(other);
    X509_free(ca);
    X509_free(leaf);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(leaf_key);
    printf("1..%d\n", number);
    return failures != 0;
}
