/*
 * Conformance test for the built-in ASN.1 item table (ASN1_ITEM_get, ASN1_ITEM_lookup in
 * asn1.h), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both (TEST_PLAN.md, layer L4). Every item is printed in the
 * table's order, with its type and template count, so the two tables must agree entry for
 * entry.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/*
 * Items over structures no header defines, whose type, templates, and size describe each
 * library's own layout (docs/DEVIATIONS.md, "Items over opaque handles").
 */
static int opaque(const char *name)
{
    static const char *const names[] = { "X509", "DHparams", "RSAPrivateKey", "RSAPublicKey" };
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (strcmp(name, names[i]) == 0)
            return 1;
    return 0;
}

int main(void)
{
    const ASN1_ITEM *it;
    size_t i, found = 0;

    for (i = 0; (it = ASN1_ITEM_get(i)) != NULL; i++) {
        if (opaque(it->sname))
            printf("  %zu: %s utype %ld (an opaque structure)\n", i, it->sname, it->utype);
        else
            printf("  %zu: %s itype %d utype %ld templates %ld size %ld\n", i, it->sname, it->itype,
                   it->utype, it->tcount, it->size);
        if (ASN1_ITEM_lookup(it->sname) == it)
            found++;
    }
    printf("  %zu items\n", i);
    check(i > 100, "the table has the built-in items");
    check(found == i, "ASN1_ITEM_lookup finds each by its name");
    check(ASN1_ITEM_get(i) == NULL && ASN1_ITEM_get((size_t)-1) == NULL, "NULL past the end");
    check(ASN1_ITEM_lookup("X509") != NULL, "X509 is in the table");
    check(ASN1_ITEM_lookup("no such item") == NULL, "an unknown name");
    check(ASN1_ITEM_lookup("") == NULL, "an empty name");
    check(ASN1_ITEM_lookup("x509") == NULL, "names are case-sensitive");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
