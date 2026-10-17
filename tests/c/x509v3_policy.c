/*
 * Conformance test for policies and constraints (CERTIFICATEPOLICIES_new(3), POLICYINFO_new(3),
 * POLICY_MAPPING_new(3), POLICY_CONSTRAINTS_new(3), PROXY_CERT_INFO_EXTENSION_new(3),
 * NAME_CONSTRAINTS_new(3)), in TAP format: certificate policies made from text and sections
 * (CPS and user notice qualifiers, notice references, explicit text of each type, IA5
 * organizations) and printed; policy mappings and constraints; proxy certificate information
 * (each policy form); name constraints of each name type (IP networks of both families),
 * with the attribute certificates' holder and delegated ones; decoded values and the errors of
 * bad input.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
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

static void hex(const char *label, const unsigned char *p, long n)
{
    long i;

    printf("  %s (%ld):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : " ", p[i]);
    printf("\n");
}

static BIO *out;

static void flush_out(void)
{
    char *data;
    long n = BIO_get_mem_data(out, &data);

    fwrite(data, 1, (size_t)n, stdout);
    (void)BIO_reset(out);
}


static const char CONF_TEXT[] =
    "[pol1]\n"
    "policyIdentifier=1.2.3.4\n"
    "CPS.1=http://cps.example/one\n"
    "CPS.2=http://cps.example/two\n"
    "userNotice.1=@notice\n"
    "[notice]\n"
    "explicitText=UTF8:Some UTF8 text\n"
    "organization=Org Name\n"
    "noticeNumbers=1,2,3\n"
    "[notice2]\n"
    "explicitText=BMP:bmp text\n"
    "[notice3]\n"
    "explicitText=plain visible\n"
    "[notice4]\n"
    "organization=Only Org\n"
    "[notice5]\n"
    "noticeNumbers=x\n"
    "[pol2]\n"
    "policyIdentifier=anyPolicy\n"
    "userNotice=@notice2\n"
    "userNotice.2=@notice3\n"
    "[pol3]\n"
    "CPS=http://no.id/\n"
    "[pol4]\n"
    "policyIdentifier=1.2.3.5\n"
    "userNotice=@notice4\n"
    "[pol5]\n"
    "policyIdentifier=1.2.3.6\n"
    "userNotice=notice\n"
    "[pol6]\n"
    "policyIdentifier=1.2.3.7\n"
    "bogus=x\n"
    "[pol7]\n"
    "policyIdentifier=1.2.3.8\n"
    "userNotice=@notice5\n"
    "[dir]\n"
    "CN=dir\n"
    "[pci]\n"
    "language=id-ppl-anyLanguage\n"
    "pathlen=3\n"
    "policy=text:from a section\n";

static void print_out(const char *label)
{
    printf("  %s: [", label);
    flush_out();
    printf("]\n");
}

static void show_ext(X509_EXTENSION *e)
{
    unsigned char *der = NULL;
    int len;

    if (e == NULL) {
        printf("  none\n");
        errors();
        return;
    }
    len = i2d_X509_EXTENSION(e, &der);
    hex("extension", der, len);
    OPENSSL_free(der);
    printf("  print %d", X509V3_EXT_print(out, e, 0, 2));
    print_out("");
}

static void free_value(const X509V3_EXT_METHOD *m, void *v)
{
    ASN1_item_free(v, ASN1_ITEM_ptr(m->it));
}

/* Through the method's v2i, or its r2i. */
static void make(const char *label, int nid, X509V3_CTX *ctx, const char *text)
{
    const X509V3_EXT_METHOD *m = X509V3_EXT_get_nid(nid);
    void *v;
    X509_EXTENSION *e;

    printf("# %s\n", label);
    if (m->v2i != NULL) {
        STACK_OF(CONF_VALUE) *in = X509V3_parse_list(text);

        v = m->v2i(m, ctx, in);
        sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    } else {
        v = m->r2i(m, ctx, text);
    }
    e = v == NULL ? NULL : X509V3_EXT_i2d(nid, 0, v);
    show_ext(e);
    X509_EXTENSION_free(e);
    if (v != NULL)
        free_value(m, v);
}

static void decoded(const char *label, int nid, const char *der, int len)
{
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    X509_EXTENSION *e;

    ASN1_OCTET_STRING_set(os, (const unsigned char *)der, len);
    e = X509_EXTENSION_create_by_NID(NULL, nid, 0, os);
    ASN1_OCTET_STRING_free(os);
    printf("# decoded %s\n", label);
    printf("  print %d", X509V3_EXT_print(out, e, X509V3_EXT_ERROR_UNKNOWN, 2));
    print_out("");
    X509_EXTENSION_free(e);
}

int main(void)
{
    BIO *b;
    CONF *conf = NCONF_new(NULL);
    long eline = 0;
    X509V3_CTX ctx;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    out = BIO_new(BIO_s_mem());
    b = BIO_new_mem_buf(CONF_TEXT, -1);
    check(NCONF_load_bio(conf, b, &eline) == 1, "a configuration");
    BIO_free(b);
    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
    X509V3_set_nconf(&ctx, conf);

    make("policies, objects", NID_certificate_policies, &ctx, "1.2.3.4,anyPolicy,2.5.29.32.0");
    make("policies, sections", NID_certificate_policies, &ctx, "@pol1,@pol2");
    make("policies, ia5org", NID_certificate_policies, &ctx, "ia5org,@pol1");
    make("policies, no identifier", NID_certificate_policies, &ctx, "@pol3");
    make("policies, organization alone", NID_certificate_policies, &ctx, "@pol4");
    make("policies, notice not a section", NID_certificate_policies, &ctx, "@pol5");
    make("policies, bad option", NID_certificate_policies, &ctx, "@pol6");
    make("policies, bad numbers", NID_certificate_policies, &ctx, "@pol7");
    make("policies, no such section", NID_certificate_policies, &ctx, "@nosuch");
    make("policies, a value", NID_certificate_policies, &ctx, "1.2.3:x");
    make("policies, bad object", NID_certificate_policies, &ctx, "not.an.oid");
    make("mappings", NID_policy_mappings, &ctx, "1.2.3:1.2.4,anyPolicy:1.5.6");
    make("mappings, no value", NID_policy_mappings, &ctx, "1.2.3");
    make("mappings, bad object", NID_policy_mappings, &ctx, "1.2.3:bogus");
    make("constraints", NID_policy_constraints, &ctx, "requireExplicitPolicy:0,inhibitPolicyMapping:2");
    make("constraints, one", NID_policy_constraints, &ctx, "inhibitPolicyMapping:1");
    make("constraints, none", NID_policy_constraints, &ctx, "");
    make("constraints, bad name", NID_policy_constraints, &ctx, "requireSomething:1");
    make("constraints, bad number", NID_policy_constraints, &ctx, "requireExplicitPolicy:x");
    make("proxy", NID_proxyCertInfo, &ctx, "language:id-ppl-anyLanguage,pathlen:1,policy:text:some text,policy:hex:41:42");
    make("proxy, section", NID_proxyCertInfo, &ctx, "@pci");
    make("proxy, inherit all", NID_proxyCertInfo, &ctx, "language:id-ppl-inheritAll");
    make("proxy, inherit all with a policy", NID_proxyCertInfo, &ctx, "language:id-ppl-inheritAll,policy:text:x");
    make("proxy, no language", NID_proxyCertInfo, &ctx, "pathlen:1");
    make("proxy, two languages", NID_proxyCertInfo, &ctx, "language:id-ppl-anyLanguage,language:id-ppl-independent");
    make("proxy, two path lengths", NID_proxyCertInfo, &ctx, "language:id-ppl-anyLanguage,pathlen:1,pathlen:2");
    make("proxy, bad policy tag", NID_proxyCertInfo, &ctx, "language:id-ppl-anyLanguage,policy:raw:x");
    make("proxy, bad hex", NID_proxyCertInfo, &ctx, "language:id-ppl-anyLanguage,policy:hex:zz");
    make("proxy, no such file", NID_proxyCertInfo, &ctx, "language:id-ppl-anyLanguage,policy:file:/nonexistent/rustyssl");
    make("proxy, no value", NID_proxyCertInfo, &ctx, "language");
    make("name constraints", NID_name_constraints, &ctx,
         "permitted;DNS:example.com,permitted;email:@example.com,permitted;IP:10.0.0.0/255.0.0.0,"
         "excluded;URI:.bad.example,excluded;IP:2001:db8::/ffff:ffff::,excluded;dirName:dir");
    make("name constraints, address without mask", NID_name_constraints, &ctx, "permitted;IP:10.0.0.1");
    make("name constraints, bad syntax", NID_name_constraints, &ctx, "allowed;DNS:x");
    make("name constraints, bare word", NID_name_constraints, &ctx, "permitted");
    make("holder name constraints", NID_holder_name_constraints, &ctx, "permitted;DNS:holder.example");
    make("delegated name constraints", NID_delegated_name_constraints, &ctx, "excluded.1:DNS:deleg.example");
    decoded("policies, unknown qualifier", NID_certificate_policies,
            "\x30\x13\x30\x11\x06\x03\x2a\x03\x04\x30\x0a\x30\x08\x06\x03\x2a\x03\x05\x02\x01\x07", 21);
    decoded("policies, notice of a NULL number", NID_certificate_policies,
            "\x30\x1d\x30\x1b\x06\x03\x2a\x03\x04\x30\x14\x30\x12\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x02\x30\x06\x30\x04\x16\x00\x30\x00", 31);
    decoded("policies, bad", NID_certificate_policies, "\x30\x03\x30\x01\x06", 5);
    decoded("proxy without a path length", NID_proxyCertInfo,
            "\x30\x0d\x30\x0b\x06\x08\x2b\x06\x01\x05\x05\x07\x15\x00\x04\x00", 15);
    decoded("name constraints, odd address", NID_name_constraints, "\x30\x07\xa0\x05\x30\x03\x87\x01\x7f", 9);
    decoded("name constraints, min and max", NID_name_constraints,
            "\x30\x0f\xa1\x0d\x30\x0b\x82\x03\x61\x2e\x62\x80\x01\x00\x81\x01\x02", 17);
    {
        CERTIFICATEPOLICIES *cp = CERTIFICATEPOLICIES_new();
        POLICYINFO *pi = POLICYINFO_new();
        POLICYQUALINFO *pq = POLICYQUALINFO_new();
        USERNOTICE *un = USERNOTICE_new();
        NOTICEREF *nr = NOTICEREF_new();
        PROXY_POLICY *pp = PROXY_POLICY_new();
        PROXY_CERT_INFO_EXTENSION *pci = PROXY_CERT_INFO_EXTENSION_new();
        POLICY_MAPPING *pm = POLICY_MAPPING_new();
        POLICY_CONSTRAINTS *pc = POLICY_CONSTRAINTS_new();
        GENERAL_SUBTREE *gs = GENERAL_SUBTREE_new();
        NAME_CONSTRAINTS *nc = NAME_CONSTRAINTS_new();
        unsigned char *der = NULL;
        int len;
        const unsigned char *q;

        printf("# items\n");
        len = i2d_CERTIFICATEPOLICIES(cp, &der);
        hex("empty policies", der, len);
        q = der;
        CERTIFICATEPOLICIES_free(d2i_CERTIFICATEPOLICIES(NULL, &q, len));
        OPENSSL_free(der);
        der = NULL;
        len = i2d_USERNOTICE(un, &der);
        hex("empty notice", der, len);
        q = der;
        USERNOTICE_free(d2i_USERNOTICE(NULL, &q, len));
        OPENSSL_free(der);
        der = NULL;
        printf("  empty: policy %d, qualifier %d, reference %d, proxy policy %d, proxy %d\n",
               i2d_POLICYINFO(pi, NULL), i2d_POLICYQUALINFO(pq, NULL), i2d_NOTICEREF(nr, NULL),
               i2d_PROXY_POLICY(pp, NULL), i2d_PROXY_CERT_INFO_EXTENSION(pci, NULL));
        errors();
        q = (const unsigned char *)"\x30\x05\x06\x03\x2a\x03\x04";
        POLICYINFO_free(d2i_POLICYINFO(NULL, &q, 7));
        q = (const unsigned char *)"\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x01";
        printf("  a CPS without its URI: %p\n", (void *)d2i_POLICYQUALINFO(NULL, &q, 12));
        errors();
        q = (const unsigned char *)"\x30\x06\x16\x01\x6f\x30\x01\x02";
        printf("  a bad reference: %p\n", (void *)d2i_NOTICEREF(NULL, &q, 8));
        errors();
        q = (const unsigned char *)"\x30\x05\x06\x03\x2a\x03\x04";
        PROXY_POLICY_free(d2i_PROXY_POLICY(NULL, &q, 7));
        q = (const unsigned char *)"\x30\x07\x30\x05\x06\x03\x2a\x03\x04";
        PROXY_CERT_INFO_EXTENSION_free(d2i_PROXY_CERT_INFO_EXTENSION(NULL, &q, 9));
        check(ASN1_ITEM_rptr(CERTIFICATEPOLICIES) && ASN1_ITEM_rptr(POLICYINFO) && ASN1_ITEM_rptr(POLICYQUALINFO)
                  && ASN1_ITEM_rptr(USERNOTICE) && ASN1_ITEM_rptr(NOTICEREF) && ASN1_ITEM_rptr(PROXY_POLICY)
                  && ASN1_ITEM_rptr(PROXY_CERT_INFO_EXTENSION) && ASN1_ITEM_rptr(POLICY_MAPPING)
                  && ASN1_ITEM_rptr(POLICY_MAPPINGS) && ASN1_ITEM_rptr(POLICY_CONSTRAINTS)
                  && ASN1_ITEM_rptr(GENERAL_SUBTREE) && ASN1_ITEM_rptr(NAME_CONSTRAINTS),
              "the items");
        CERTIFICATEPOLICIES_free(cp);
        POLICYINFO_free(pi);
        POLICYQUALINFO_free(pq);
        USERNOTICE_free(un);
        NOTICEREF_free(nr);
        PROXY_POLICY_free(pp);
        PROXY_CERT_INFO_EXTENSION_free(pci);
        POLICY_MAPPING_free(pm);
        POLICY_CONSTRAINTS_free(pc);
        GENERAL_SUBTREE_free(gs);
        NAME_CONSTRAINTS_free(nc);
    }
    NCONF_free(conf);
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
