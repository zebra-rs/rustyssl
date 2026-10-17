/*
 * Conformance test for verification parameters (X509_VERIFY_PARAM_new(3),
 * X509_VERIFY_PARAM_set_flags(3), X509_VERIFY_PARAM_inherit, and the table of named
 * parameters), in TAP format: every setter and getter, host names with and without NULs,
 * email and IP addresses, policies, each inheritance flag, and the table's built-in and added
 * parameters, with the errors of bad input.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/objects.h>
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

static const char *str(const char *s)
{
    return s == NULL ? "(none)" : s;
}

static void show(const char *label, const X509_VERIFY_PARAM *p)
{
    printf("  %s: name %s, flags %#lx, inh %#x, purpose %d, depth %d, level %d, time %ld\n", label,
           str(X509_VERIFY_PARAM_get0_name(p)), X509_VERIFY_PARAM_get_flags(p),
           (unsigned)X509_VERIFY_PARAM_get_inh_flags(p), X509_VERIFY_PARAM_get_purpose(p),
           X509_VERIFY_PARAM_get_depth(p), X509_VERIFY_PARAM_get_auth_level(p),
           (long)X509_VERIFY_PARAM_get_time(p));
}

static void show_ids(const char *label, X509_VERIFY_PARAM *p)
{
    int i;
    char *ip;

    printf("  %s: hostflags %#x, hosts", label, X509_VERIFY_PARAM_get_hostflags(p));
    for (i = 0; X509_VERIFY_PARAM_get0_host(p, i) != NULL; i++)
        printf(" [%s]", X509_VERIFY_PARAM_get0_host(p, i));
    printf(", email %s, peername %s", str(X509_VERIFY_PARAM_get0_email(p)),
           str(X509_VERIFY_PARAM_get0_peername(p)));
    ip = X509_VERIFY_PARAM_get1_ip_asc(p);
    printf(", ip %s\n", str(ip));
    OPENSSL_free(ip);
    ERR_clear_error();
}

static void test_setters(void)
{
    X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_new();
    STACK_OF(ASN1_OBJECT) *pols = sk_ASN1_OBJECT_new_null();
    static const unsigned char v4[4] = { 192, 0, 2, 1 };
    static const unsigned char v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    printf("# setters\n");
    show("new", p);
    show_ids("new", p);
    check(X509_VERIFY_PARAM_set1_name(p, "mine") == 1, "set a name");
    check(X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_CRL_CHECK) == 1, "set a flag");
    show("flag", p);
    check(X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_EXPLICIT_POLICY) == 1, "a policy flag");
    show("policy flag", p);
    check(X509_VERIFY_PARAM_clear_flags(p, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_POLICY_CHECK) == 1, "clear");
    show("cleared", p);
    check(X509_VERIFY_PARAM_set_inh_flags(p, X509_VP_FLAG_ONCE) == 1, "inheritance flags");
    check(X509_VERIFY_PARAM_set_purpose(p, X509_PURPOSE_SSL_SERVER) == 1, "a purpose");
    check(X509_VERIFY_PARAM_set_purpose(p, 999) == 0, "an unknown purpose");
    errors();
    check(X509_VERIFY_PARAM_set_trust(p, X509_TRUST_EMAIL) == 1, "a trust");
    check(X509_VERIFY_PARAM_set_trust(p, 999) == 0, "an unknown trust");
    errors();
    X509_VERIFY_PARAM_set_depth(p, 5);
    X509_VERIFY_PARAM_set_auth_level(p, 2);
    X509_VERIFY_PARAM_set_time(p, 1700000000);
    show("set", p);

    printf("# policies\n");
    sk_ASN1_OBJECT_push(pols, OBJ_txt2obj("1.2.3.4", 1));
    sk_ASN1_OBJECT_push(pols, OBJ_nid2obj(NID_any_policy));
    check(X509_VERIFY_PARAM_set1_policies(p, pols) == 1, "set policies");
    check(X509_VERIFY_PARAM_add0_policy(p, OBJ_txt2obj("1.2.3.5", 1)) == 1, "add one");
    check(X509_VERIFY_PARAM_set1_policies(p, NULL) == 1, "clear them");
    check(X509_VERIFY_PARAM_set1_policies(NULL, pols) == 0, "no parameter");
    errors();
    show("policies", p);
    sk_ASN1_OBJECT_pop_free(pols, ASN1_OBJECT_free);

    printf("# hosts\n");
    check(X509_VERIFY_PARAM_set1_host(p, "example.com", 0) == 1, "set a host");
    check(X509_VERIFY_PARAM_add1_host(p, "b.example.netXX", 13) == 1, "add one of 13 octets");
    check(X509_VERIFY_PARAM_add1_host(p, "c.example\0", 10) == 1, "a trailing NUL");
    check(X509_VERIFY_PARAM_add1_host(p, "a\0b", 3) == 0, "a NUL inside");
    check(X509_VERIFY_PARAM_add1_host(p, "\0", 1) == 0, "only a NUL");
    check(X509_VERIFY_PARAM_add1_host(p, "", 0) == 1, "empty adds nothing");
    check(X509_VERIFY_PARAM_add1_host(p, NULL, 5) == 1, "NULL adds nothing");
    X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    show_ids("hosts", p);
    check(X509_VERIFY_PARAM_set1_host(p, NULL, 0) == 1, "clear them");
    show_ids("cleared", p);
    check(X509_VERIFY_PARAM_set1_host(p, "only.example", 0) == 1, "set one");

    printf("# email and IP\n");
    check(X509_VERIFY_PARAM_set1_email(p, "user@example.com", 0) == 1, "an email");
    show_ids("email", p);
    check(X509_VERIFY_PARAM_set1_email(p, "someone@example.org", 7) == 1, "seven octets");
    check(X509_VERIFY_PARAM_set1_ip(p, v4, 4) == 1, "IPv4");
    show_ids("IPv4", p);
    check(X509_VERIFY_PARAM_set1_ip(p, v6, 16) == 1, "IPv6");
    show_ids("IPv6", p);
    check(X509_VERIFY_PARAM_set1_ip(p, v4, 5) == 0, "five octets");
    errors();
    check(X509_VERIFY_PARAM_set1_ip_asc(p, "10.1.2.3") == 1, "from text");
    show_ids("text", p);
    check(X509_VERIFY_PARAM_set1_ip_asc(p, "fe80::1") == 1, "IPv6 from text");
    show_ids("IPv6 text", p);
    check(X509_VERIFY_PARAM_set1_ip_asc(p, "10.1.2") == 0, "bad text");
    errors();
    check(X509_VERIFY_PARAM_set1_ip(p, NULL, 0) == 1, "clear the address");
    check(X509_VERIFY_PARAM_set1_email(p, NULL, 0) == 1, "clear the email");
    show_ids("cleared", p);
    errors();
    {
        X509_VERIFY_PARAM *q = X509_VERIFY_PARAM_new();

        X509_VERIFY_PARAM_move_peername(q, p);
        X509_VERIFY_PARAM_move_peername(q, NULL);
        show_ids("moved", q);
        X509_VERIFY_PARAM_free(q);
    }
    check(X509_VERIFY_PARAM_set1_name(p, NULL) == 0, "no name");
    show("unnamed", p);
    X509_VERIFY_PARAM_free(p);
    X509_VERIFY_PARAM_free(NULL);
}

static X509_VERIFY_PARAM *sample(void)
{
    X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_new();
    STACK_OF(ASN1_OBJECT) *pols = sk_ASN1_OBJECT_new_null();

    X509_VERIFY_PARAM_set1_name(p, "sample");
    X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_X509_STRICT);
    X509_VERIFY_PARAM_set_purpose(p, X509_PURPOSE_SSL_CLIENT);
    X509_VERIFY_PARAM_set_depth(p, 3);
    X509_VERIFY_PARAM_set_time(p, 1234567);
    X509_VERIFY_PARAM_set1_host(p, "src.example", 0);
    X509_VERIFY_PARAM_set1_email(p, "src@example", 0);
    X509_VERIFY_PARAM_set1_ip_asc(p, "192.0.2.9");
    X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NO_WILDCARDS);
    sk_ASN1_OBJECT_push(pols, OBJ_txt2obj("1.2.3.4", 1));
    X509_VERIFY_PARAM_set1_policies(p, pols);
    sk_ASN1_OBJECT_pop_free(pols, ASN1_OBJECT_free);
    return p;
}

static void inherit_with(const char *label, unsigned int dest_inh, unsigned int src_inh)
{
    X509_VERIFY_PARAM *src = sample(), *dest = X509_VERIFY_PARAM_new();

    X509_VERIFY_PARAM_set_trust(dest, X509_TRUST_SSL_SERVER);
    X509_VERIFY_PARAM_set_depth(dest, 7);
    X509_VERIFY_PARAM_set_flags(dest, X509_V_FLAG_CRL_CHECK);
    X509_VERIFY_PARAM_set1_host(dest, "dest.example", 0);
    X509_VERIFY_PARAM_set_inh_flags(dest, dest_inh);
    X509_VERIFY_PARAM_set_inh_flags(src, src_inh);
    printf("# inherit, %s\n", label);
    printf("  result %d\n", X509_VERIFY_PARAM_inherit(dest, src));
    show("dest", dest);
    show_ids("dest", dest);
    X509_VERIFY_PARAM_free(src);
    X509_VERIFY_PARAM_free(dest);
}

static void test_inherit(void)
{
    X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_new(), *s = sample();

    inherit_with("plain", 0, 0);
    inherit_with("default", X509_VP_FLAG_DEFAULT, 0);
    inherit_with("overwrite", 0, X509_VP_FLAG_OVERWRITE);
    inherit_with("reset flags", X509_VP_FLAG_RESET_FLAGS, 0);
    inherit_with("locked", X509_VP_FLAG_LOCKED, 0);
    inherit_with("once", X509_VP_FLAG_ONCE | X509_VP_FLAG_DEFAULT, 0);
    printf("# set1\n");
    check(X509_VERIFY_PARAM_inherit(p, NULL) == 1, "inherit from nothing");
    check(X509_VERIFY_PARAM_set1(p, s) == 1, "set1");
    show("set1", p);
    show_ids("set1", p);
    check(X509_VERIFY_PARAM_set1(p, X509_VERIFY_PARAM_lookup("ssl_server")) == 1, "set1 from the table");
    show("ssl_server", p);
    check(X509_VERIFY_PARAM_set1(NULL, s) == 0, "set1 into nothing");
    errors();
    X509_VERIFY_PARAM_free(p);
    X509_VERIFY_PARAM_free(s);
}

static void show_table(const char *label)
{
    int i, n = X509_VERIFY_PARAM_get_count();

    printf("  %s: %d:", label, n);
    for (i = 0; i < n; i++)
        printf(" %s", str(X509_VERIFY_PARAM_get0_name(X509_VERIFY_PARAM_get0(i))));
    printf("\n");
}

static void test_table(void)
{
    static const char *const names[] = { "default", "pkcs7", "smime_sign", "ssl_client", "ssl_server",
                                         "code_sign", "custom", "nope" };
    X509_VERIFY_PARAM *a = X509_VERIFY_PARAM_new(), *b = X509_VERIFY_PARAM_new(), *c = X509_VERIFY_PARAM_new();
    size_t i;

    printf("# table\n");
    show_table("built in");
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_lookup(names[i]);

        if (p == NULL)
            printf("  %s: none\n", names[i]);
        else
            show(names[i], p);
    }
    check(X509_VERIFY_PARAM_get0(-1) == NULL, "a negative id");
    errors();
    check(X509_VERIFY_PARAM_get0(100) == NULL, "past the end");
    X509_VERIFY_PARAM_set1_name(a, "custom");
    X509_VERIFY_PARAM_set_depth(a, 9);
    X509_VERIFY_PARAM_set1_name(b, "another");
    X509_VERIFY_PARAM_set1_name(c, "custom");
    X509_VERIFY_PARAM_set_depth(c, 11);
    check(X509_VERIFY_PARAM_add0_table(a) == 1, "add custom");
    show_table("added");
    check(X509_VERIFY_PARAM_add0_table(b) == 1, "add another");
    show_table("added");
    show("custom", X509_VERIFY_PARAM_lookup("custom"));
    show_table("looked up");
    check(X509_VERIFY_PARAM_add0_table(c) == 1, "replace custom");
    show_table("replaced");
    show("custom", X509_VERIFY_PARAM_lookup("custom"));
    show("default", X509_VERIFY_PARAM_lookup("default"));
    X509_VERIFY_PARAM_table_cleanup();
    show_table("cleaned up");
    X509_VERIFY_PARAM_table_cleanup();
}

int main(void)
{
    test_setters();
    test_inherit();
    test_table();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
