/*
 * CVE regression checks for CMP exchanges: a client and an in-process server (OSSL_CMP_SRV_CTX)
 * sharing a password, joined by a transfer callback that can rebuild the server's responses
 * (re-protected with OSSL_CMP_MSG_update_transactionID) the way a malicious server would send
 * them. Each check prints what both libraries must agree on: the session's result, and how
 * many certificates the server keeps.
 */
#include "cve.h"

#include <openssl/cmp.h>

/* PKIBody's rp alternative (RFC 4210); OpenSSL keeps its body-type names internal. */
#define BODY_RP 12

static OSSL_CMP_SRV_CTX *srv;

/* The rootCaKeyUpdate the server answers with, and whether rp responses get a CertId. */
static X509 *update_nwn, *update_nwo, *update_own;
static int rp_with_certid;

static OSSL_CMP_PKISI *srv_cert(OSSL_CMP_SRV_CTX *c, const OSSL_CMP_MSG *req, int id,
                                const OSSL_CRMF_MSG *crm, const X509_REQ *p10, X509 **out,
                                STACK_OF(X509) **chain, STACK_OF(X509) **caPubs)
{
    (void)c, (void)req, (void)id, (void)crm, (void)p10, (void)out, (void)chain, (void)caPubs;
    return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection, 0, NULL);
}

static OSSL_CMP_PKISI *srv_rr(OSSL_CMP_SRV_CTX *c, const OSSL_CMP_MSG *req,
                              const X509_NAME *issuer, const ASN1_INTEGER *serial)
{
    (void)c, (void)req, (void)issuer, (void)serial;
    return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_accepted, 0, NULL);
}

static int srv_genm(OSSL_CMP_SRV_CTX *c, const OSSL_CMP_MSG *req,
                    const STACK_OF(OSSL_CMP_ITAV) *in, STACK_OF(OSSL_CMP_ITAV) **out)
{
    (void)c, (void)req, (void)in;
    *out = sk_OSSL_CMP_ITAV_new_null();
    sk_OSSL_CMP_ITAV_push(*out, OSSL_CMP_ITAV_new_rootCaKeyUpdate(update_nwn, update_nwo,
                                                                   update_own));
    return 1;
}

static void srv_error(OSSL_CMP_SRV_CTX *c, const OSSL_CMP_MSG *req, const OSSL_CMP_PKISI *si,
                      const ASN1_INTEGER *code, const OSSL_CMP_PKIFREETEXT *details)
{
    (void)c, (void)req, (void)si, (void)code, (void)details;
}

static int srv_certconf(OSSL_CMP_SRV_CTX *c, const OSSL_CMP_MSG *req, int id,
                        const ASN1_OCTET_STRING *hash, const OSSL_CMP_PKISI *si)
{
    (void)c, (void)req, (void)id, (void)hash, (void)si;
    return 1;
}

static int srv_poll(OSSL_CMP_SRV_CTX *c, const OSSL_CMP_MSG *req, int id, OSSL_CMP_MSG **cr,
                    int64_t *check_after)
{
    (void)c, (void)req, (void)id, (void)cr, (void)check_after;
    return 0;
}

/* A DER element's header length and total length at `p`; 0 if malformed. */
static size_t tlv(const unsigned char *p, size_t n, size_t *hdr)
{
    size_t len, h = 2;

    if (n < 2)
        return 0;
    len = p[1];
    if (len & 0x80) {
        size_t k = len & 0x7f;

        if (k == 0 || k > 3 || n < 2 + k)
            return 0;
        len = 0;
        for (size_t i = 0; i < k; i++)
            len = (len << 8) | p[2 + i];
        h += k;
    }
    if (h + len > n)
        return 0;
    *hdr = h;
    return h + len;
}

/* An rp rebuilt with a revCerts CertId (issuer CN=Somewhere, serial 5), re-protected. */
static OSSL_CMP_MSG *add_certid(OSSL_CMP_MSG *rp)
{
    unsigned char *der = NULL;
    int len = i2d_OSSL_CMP_MSG(rp, &der);
    size_t h, total, header_len, body_len, body_h, content_h, status_len, status_h;
    const unsigned char *p;
    OSSL_CMP_MSG *out = NULL;
    buf certid = {0}, rrc = {0}, body = {0}, inner = {0}, msg = {0}, gn = {0}, revcerts = {0};
    X509_NAME *issuer = X509_NAME_new();
    unsigned char *name = NULL;
    int name_len;

    if (len <= 0 || (total = tlv(der, (size_t)len, &h)) == 0)
        goto end;
    p = der + h;
    /* header, then the body [12] { RevRepContent SEQUENCE { status, ... } } */
    if ((header_len = tlv(p, total - h, &content_h)) == 0
        || (body_len = tlv(p + header_len, total - h - header_len, &body_h)) == 0
        || p[header_len] != 0xac
        || tlv(p + header_len + body_h, body_len - body_h, &content_h) == 0
        || (status_len = tlv(p + header_len + body_h + content_h,
                             body_len - body_h - content_h, &status_h)) == 0)
        goto end;
    X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC, (const unsigned char *)"Somewhere",
                               -1, -1, 0);
    name_len = i2d_X509_NAME(issuer, &name);
    put_raw_tlv(&gn, 0xa4, name, (size_t)name_len);
    put(&certid, gn.p, gn.n);
    put(&certid, "\x02\x01\x05", 3);
    put_tlv(&inner, 0x30, &certid);
    put_tlv(&revcerts, 0x30, &inner);
    put(&rrc, p + header_len + body_h + content_h, status_len);
    put_tlv(&rrc, 0xa0, &revcerts);
    {
        buf seq = {0};

        put_tlv(&seq, 0x30, &rrc);
        put_tlv(&body, 0xac, &seq);
        free_buf(&seq);
    }
    {
        buf content = {0};
        const unsigned char *q;

        put(&content, p, header_len);
        put(&content, body.p, body.n);
        put_tlv(&msg, 0x30, &content);
        free_buf(&content);
        q = msg.p;
        out = d2i_OSSL_CMP_MSG(NULL, &q, (long)msg.n);
    }
    /* The server's transaction ended with the rp; re-protect under the same transactionID. */
    if (out != NULL
        && (!OSSL_CMP_CTX_set1_transactionID(OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv),
               OSSL_CMP_HDR_get0_transactionID(OSSL_CMP_MSG_get0_header(rp)))
            || !OSSL_CMP_MSG_update_transactionID(OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv), out))) {
        OSSL_CMP_MSG_free(out);
        out = NULL;
    }
end:
    note("rp rebuilt with a CertId: %s", out != NULL ? "yes" : "no");
    OPENSSL_free(der);
    OPENSSL_free(name);
    X509_NAME_free(issuer);
    free_buf(&certid);
    free_buf(&inner);
    free_buf(&revcerts);
    free_buf(&rrc);
    free_buf(&body);
    free_buf(&msg);
    free_buf(&gn);
    return out;
}

static OSSL_CMP_MSG *transfer(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *rsp = OSSL_CMP_SRV_process_request(srv, req);

    (void)ctx;
    if (rsp != NULL && rp_with_certid && OSSL_CMP_MSG_get_bodytype(rsp) == BODY_RP) {
        OSSL_CMP_MSG *changed = add_certid(rsp);

        OSSL_CMP_MSG_free(rsp);
        rsp = changed;
    }
    return rsp;
}

static void make_server(void)
{
    OSSL_CMP_CTX *sctx;

    srv = OSSL_CMP_SRV_CTX_new(NULL, NULL);
    OSSL_CMP_SRV_CTX_init(srv, NULL, srv_cert, srv_rr, srv_genm, srv_error, srv_certconf,
                          srv_poll);
    sctx = OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv);
    OSSL_CMP_CTX_set_log_verbosity(sctx, OSSL_CMP_LOG_EMERG);
    OSSL_CMP_CTX_set1_referenceValue(sctx, (const unsigned char *)"user", 4);
    OSSL_CMP_CTX_set1_secretValue(sctx, (const unsigned char *)"password", 8);
}

/* A client sharing the server's password (or a wrong one). */
static OSSL_CMP_CTX *client(const char *password)
{
    OSSL_CMP_CTX *ctx = OSSL_CMP_CTX_new(NULL, NULL);

    OSSL_CMP_CTX_set_log_verbosity(ctx, OSSL_CMP_LOG_EMERG);
    OSSL_CMP_CTX_set_transfer_cb(ctx, transfer);
    OSSL_CMP_CTX_set1_referenceValue(ctx, (const unsigned char *)"user", 4);
    OSSL_CMP_CTX_set1_secretValue(ctx, (const unsigned char *)password, strlen(password));
    return ctx;
}

/* CVE-2026-42769: a rootCaKeyUpdate whose newWithOld wasn't signed by the old root's key. */
static void root_ca_key_update(void)
{
    EVP_PKEY *old_key = ec_key(), *new_key = ec_key(), *evil_key = ec_key();
    X509 *old = ca_cert("Root", old_key, NULL, NULL);
    X509 *nwn = ca_cert("Root", new_key, NULL, NULL);
    X509 *nwo = ca_cert("Root", new_key, old, old_key);
    X509 *own = ca_cert("Root", old_key, nwn, new_key);
    X509 *ewe = ca_cert("Root", evil_key, NULL, NULL);
    X509 *ewo = ca_cert("Root", evil_key, old, evil_key); /* names the old root, signed by evil */
    X509 *owe = ca_cert("Root", old_key, ewe, evil_key);
    int r[2];

    for (int evil = 0; evil < 2; evil++) {
        OSSL_CMP_CTX *ctx = client("password");
        X509 *got = NULL, *got_nwo = NULL, *got_own = NULL;

        update_nwn = evil ? ewe : nwn;
        update_nwo = evil ? ewo : nwo;
        update_own = evil ? owe : own;
        r[evil] = OSSL_CMP_get1_rootCaKeyUpdate(ctx, old, &got, &got_nwo, &got_own);
        /* The outputs are only defined on success (OpenSSL's dangle after a failure). */
        note("rootCaKeyUpdate %s: %d, new root %s", evil ? "with a forged newWithOld"
             : "signed by the old root", r[evil], r[evil] != 1 ? "not given" : got == NULL
             ? "none" : X509_cmp(got, update_nwn) == 0 ? "the one sent" : "another");
        errors("rootCaKeyUpdate");
        if (evil)
            check(r[evil] == 0, "CVE-2026-42769: a new root CA certificate whose newWithOld the "
                  "old root never signed is refused");
        if (r[evil] == 1) {
            X509_free(got);
            X509_free(got_nwo);
            X509_free(got_own);
        }
        OSSL_CMP_CTX_free(ctx);
    }
    check(r[0] == 1, "CVE-2026-42769: a genuine root CA key update is accepted");
    X509_free(old);
    X509_free(nwn);
    X509_free(nwo);
    X509_free(own);
    X509_free(ewe);
    X509_free(ewo);
    X509_free(owe);
    EVP_PKEY_free(old_key);
    EVP_PKEY_free(new_key);
    EVP_PKEY_free(evil_key);
}

/* CVE-2026-75805: revoking on the basis of a PKCS#10 CSR, the rp carries a CertId the client
 * has no issuer or serial to compare with. */
static void revocation_by_csr(void)
{
    OSSL_CMP_CTX *ctx = client("password");
    EVP_PKEY *key = ec_key();
    X509_REQ *csr = X509_REQ_new();
    X509_NAME *subject = X509_NAME_new();
    int r;

    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char *)"revoked", -1,
                               -1, 0);
    X509_REQ_set_subject_name(csr, subject);
    X509_REQ_set_pubkey(csr, key);
    X509_REQ_sign(csr, key, EVP_sha256());
    OSSL_CMP_CTX_set1_p10CSR(ctx, csr);
    rp_with_certid = 1;
    r = OSSL_CMP_exec_RR_ses(ctx);
    rp_with_certid = 0;
    note("revocation by CSR, rp with a CertId: %d, status %d", r, OSSL_CMP_CTX_get_status(ctx));
    errors("revocation by CSR");
    check(r == 1, "CVE-2026-75805: an rp with a CertId, for a revocation requested by CSR, is "
          "handled without a NULL dereference");
    X509_NAME_free(subject);
    X509_REQ_free(csr);
    EVP_PKEY_free(key);
    OSSL_CMP_CTX_free(ctx);
}

/* CVE-2026-63074: requests the server can't validate, each with a new extra certificate, to one
 * reused server context: none of the certificates stays cached. */
static void extra_certs_cache(void)
{
    EVP_PKEY *key = ec_key();
    OSSL_CMP_CTX *sctx = OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv);
    int before = sk_X509_num(OSSL_CMP_CTX_get0_untrusted(sctx)), after;

    update_nwn = update_nwo = update_own = NULL;
    for (int i = 0; i < 50; i++) {
        OSSL_CMP_CTX *ctx = client("wrong");
        STACK_OF(X509) *extra = sk_X509_new_null();
        char cn[32];

        snprintf(cn, sizeof(cn), "extra %d", i);
        sk_X509_push(extra, leaf_cert(cn, key, NULL, NULL));
        OSSL_CMP_CTX_set1_extraCertsOut(ctx, extra);
        sk_X509_pop_free(extra, X509_free);
        OSSL_CMP_exec_GENM_ses(ctx);
        OSSL_CMP_CTX_free(ctx);
    }
    ERR_clear_error();
    after = sk_X509_num(OSSL_CMP_CTX_get0_untrusted(sctx));
    note("extraCerts cached by the server: %d before, %d after 50 refused requests", before,
         after);
    check(after <= (before < 0 ? 0 : before), "CVE-2026-63074: extraCerts of requests that fail "
          "validation aren't cached by a reused server context");
    EVP_PKEY_free(key);
}

int main(void)
{
    make_server();
    root_ca_key_update();
    revocation_by_csr();
    extra_certs_cache();
    OSSL_CMP_SRV_CTX_free(srv);
    return finish();
}
