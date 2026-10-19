/*
 * Conformance test for objects (OBJ_nid2obj(3), OBJ_obj2txt(3), OBJ_create(3), OBJ_bsearch_,
 * the ASN1_OBJECT functions, a2d_ASN1_OBJECT and i2a_ASN1_OBJECT), the name registry
 * (OBJ_NAME_add(3) and the rest), and the signature-algorithm table (OBJ_find_sigid_algs(3)),
 * in TAP format. Names, texts, and visiting orders are printed as comments, so they're
 * compared too.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Prints the newest error as library/reason and clears the queue. */
static void show_error(const char *what)
{
    unsigned long code = ERR_peek_last_error();

    printf("# %s: error %d/%d\n", what, ERR_GET_LIB(code), ERR_GET_REASON(code));
    ERR_clear_error();
}

static void text_of(const char *what, const ASN1_OBJECT *o, int no_name)
{
    char buf[128];
    int n = OBJ_obj2txt(buf, sizeof(buf), o, no_name);

    printf("# %s: %d \"%s\"\n", what, n, buf);
}

static void lookups(void)
{
    ASN1_OBJECT *o = OBJ_nid2obj(NID_sha256);
    int ok = 1, nid;

    check(o != NULL && o == OBJ_nid2obj(NID_sha256) && OBJ_obj2nid(o) == NID_sha256,
          "OBJ_nid2obj shares the built-in object");
    check(strcmp(OBJ_nid2sn(NID_sha256), "SHA256") == 0 && strcmp(OBJ_nid2ln(NID_sha256), "sha256") == 0,
          "names");
    check(OBJ_length(o) == 9 && memcmp(OBJ_get0_data(o), "\x60\x86\x48\x01\x65\x03\x04\x02\x01", 9) == 0,
          "OBJ_length and OBJ_get0_data");
    check(OBJ_sn2nid("SHA256") == NID_sha256 && OBJ_ln2nid("sha256") == NID_sha256 && OBJ_sn2nid("sha256") == 0
              && OBJ_ln2nid("SHA256") == 0 && OBJ_sn2nid("") == 0,
          "OBJ_sn2nid and OBJ_ln2nid match exactly");
    printf("# duplicate names: sn NULL=%d ln NULL=%d, sn UNDEF=%d ln undefined=%d\n", OBJ_sn2nid("NULL"),
           OBJ_ln2nid("NULL"), OBJ_sn2nid("UNDEF"), OBJ_ln2nid("undefined"));
    for (nid = 0; nid < 1500; nid++) {
        ASN1_OBJECT *x = OBJ_nid2obj(nid);

        if (x == NULL) {
            if (ERR_GET_REASON(ERR_get_error()) != OBJ_R_UNKNOWN_NID)
                ok = 0;
            continue;
        }
        if (OBJ_obj2nid(x) != nid || (nid != 0 && OBJ_sn2nid(OBJ_nid2sn(nid)) == 0)
            || (nid != 0 && OBJ_ln2nid(OBJ_nid2ln(nid)) == 0))
            ok = 0;
    }
    check(ok, "every NID maps to an object whose names map back");
    ERR_clear_error();
    check(OBJ_nid2obj(-1) == NULL && OBJ_nid2sn(99999) == NULL && OBJ_nid2ln(1480 + 6) != NULL,
          "unknown NIDs");
    show_error("unknown NID");
    check(OBJ_nid2obj(0) != NULL && OBJ_obj2nid(OBJ_nid2obj(0)) == 0 && OBJ_length(OBJ_nid2obj(0)) == 0
              && OBJ_get0_data(OBJ_nid2obj(0)) == NULL,
          "NID 0 is the undefined object, without data");
    check(OBJ_obj2nid(NULL) == 0 && OBJ_length(NULL) == 0 && OBJ_get0_data(NULL) == NULL && OBJ_dup(NULL) == NULL,
          "NULL objects");
}

static void texts(void)
{
    ASN1_OBJECT *o;
    char small[6];
    int n;
    static const char *const inputs[] = {
        "2.5.4.3", "1.2.840.113549.1.1.11", "1.3", "1.2.3.4.5", "2.999.1", "0.0", "1 2 3", "1.2..3", "1.2.",
        "1. ", "1.", "12", "1", "3.1", "1.40", "1-2", "1.2a", "2.25.329800735698586629295641978511506172918",
        "1.2.18446744073709551616", "2.18446744073709551535", "commonName", "CN", "sha256", "SHA256", "nope",
        "", "UNDEF", "undefined", "NULL",
    };
    size_t i;

    for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        for (n = 0; n <= 1; n++) {
            char label[160];

            o = OBJ_txt2obj(inputs[i], n);
            snprintf(label, sizeof(label), "txt2obj(\"%s\", %d) nid=%d", inputs[i], n, OBJ_obj2nid(o));
            if (o == NULL) {
                show_error(label);
                continue;
            }
            text_of(label, o, 0);
            text_of("  no_name", o, 1);
            ASN1_OBJECT_free(o);
        }
        printf("# txt2nid(\"%s\") = %d\n", inputs[i], OBJ_txt2nid(inputs[i]));
        ERR_clear_error();
    }
    o = OBJ_txt2obj("1.2.840.113549.1.1.11", 1);
    check(o == OBJ_nid2obj(NID_sha256WithRSAEncryption), "a known OID gives the shared object");
    n = OBJ_obj2txt(small, sizeof(small), o, 0);
    check(n == 23 && strcmp(small, "sha25") == 0, "OBJ_obj2txt truncates, returning the whole length");
    n = OBJ_obj2txt(small, sizeof(small), o, 1);
    check(n == 21 && strcmp(small, "1.2.8") == 0, "also as numbers");
    check(OBJ_obj2txt(NULL, 0, o, 1) == 21 && OBJ_obj2txt(small, 0, o, 1) == 21 && OBJ_obj2txt(small, 1, o, 1) == 21
              && small[0] == '\0',
          "and only measures without room");
    check(i2t_ASN1_OBJECT(small, sizeof(small), o) == 23, "i2t_ASN1_OBJECT names it");
    o = OBJ_nid2obj(NID_iso);
    n = OBJ_obj2txt(small, sizeof(small), o, 0);
    check(n == 0 && small[0] == '\0', "an object without data has no text, even with a name");
}

static void encodings(void)
{
    unsigned char out[64];
    int n, i;
    static const char *const inputs[] = {
        "1.2.840.113549", "2.999", "1 2 3", "0.39", "0.40", "2.100000000000000000000000000", "1.2.x", "4", "", "1",
    };

    for (i = 0; i < (int)(sizeof(inputs) / sizeof(inputs[0])); i++) {
        int j;

        n = a2d_ASN1_OBJECT(out, sizeof(out), inputs[i], -1);
        printf("# a2d(\"%s\") = %d (measured %d):", inputs[i], n, a2d_ASN1_OBJECT(NULL, 0, inputs[i], -1));
        for (j = 0; j < n; j++)
            printf(" %02x", out[j]);
        printf("\n");
        show_error("  a2d");
    }
    check(a2d_ASN1_OBJECT(out, 2, "1.2.840", -1) == 0, "a2d_ASN1_OBJECT fails when the output is too small");
    show_error("too small");
    check(a2d_ASN1_OBJECT(out, sizeof(out), "1.2.3garbage", 5) == 2 && out[0] == 0x2a && out[1] == 0x03,
          "a2d_ASN1_OBJECT reads only num bytes");
    check(a2d_ASN1_OBJECT(out, sizeof(out), "1.2", 0) == 0 && a2d_ASN1_OBJECT(out, sizeof(out), "1.2", -5) == 0,
          "num 0 is nothing, and a negative num reads one character");
    show_error("negative num");
}

static void printing(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    ASN1_OBJECT *o;
    char *data;
    long len;
    unsigned char bad[] = { 0x2a, 0x86 };

    o = OBJ_txt2obj("1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20.21.22.23.24.25.26.27.28.29.30.31.32", 1);
    check(i2a_ASN1_OBJECT(mem, OBJ_nid2obj(NID_commonName)) == 10 && i2a_ASN1_OBJECT(mem, NULL) == 4
              && i2a_ASN1_OBJECT(mem, OBJ_nid2obj(NID_iso)) == 4,
          "i2a_ASN1_OBJECT writes names, and NULL for no object or no content");
    printf("# i2a of a long OID: %d\n", i2a_ASN1_OBJECT(mem, o));
    ASN1_OBJECT_free(o);
    o = ASN1_OBJECT_create(0, bad, sizeof(bad), NULL, NULL);
    printf("# i2a of bad content: %d\n", i2a_ASN1_OBJECT(mem, o));
    text_of("bad content", o, 1);
    ASN1_OBJECT_free(o);
    len = BIO_get_mem_data(mem, &data);
    printf("# i2a wrote %ld: \"", len);
    fwrite(data, 1, (size_t)len, stdout);
    printf("\"\n");
    BIO_free(mem);
}

static void dynamic(void)
{
    unsigned char data[] = { 0x2a, 0x03, 0x04 };
    ASN1_OBJECT *a = ASN1_OBJECT_create(5000, data, sizeof(data), "short", "long"), *b, *c;

    check(a != NULL && OBJ_obj2nid(a) == 5000 && OBJ_length(a) == 3 && OBJ_get0_data(a) != data,
          "ASN1_OBJECT_create copies");
    b = OBJ_dup(a);
    check(b != NULL && b != a && OBJ_cmp(a, b) == 0 && OBJ_obj2nid(b) == 5000, "OBJ_dup copies a dynamic object");
    check(OBJ_dup(OBJ_nid2obj(NID_sha1)) == OBJ_nid2obj(NID_sha1), "and shares a built-in one");
    text_of("unknown NID", a, 0);
    show_error("unknown NID in obj2txt");
    c = OBJ_txt2obj("1.2.3.5", 1);
    check(OBJ_cmp(a, c) < 0 && OBJ_cmp(c, a) > 0 && OBJ_cmp(a, OBJ_nid2obj(NID_sha1)) < 0, "OBJ_cmp orders by length, then bytes");
    ASN1_OBJECT_free(a);
    ASN1_OBJECT_free(b);
    ASN1_OBJECT_free(c);
    a = ASN1_OBJECT_new();
    check(a != NULL && OBJ_length(a) == 0 && OBJ_obj2nid(a) == 0 && OBJ_obj2txt(NULL, 0, a, 0) == 0,
          "ASN1_OBJECT_new is empty");
    ASN1_OBJECT_free(a);
    ASN1_OBJECT_free(NULL);
    ASN1_OBJECT_free(OBJ_nid2obj(NID_sha1));
    check(OBJ_nid2obj(NID_sha1) != NULL && OBJ_length(OBJ_nid2obj(NID_sha1)) == 5, "freeing a built-in object does nothing");
}

static void creating(void)
{
    BIO *in;
    ASN1_OBJECT *o, *added;
    int nid, first;

    first = OBJ_new_nid(0);
    printf("# first new NID: %d\n", first);
    nid = OBJ_create("1.2.3.4.5.6.7", "mySN", "my long name");
    check(nid == first && OBJ_new_nid(0) == first + 1, "OBJ_create takes the next NID");
    check(OBJ_sn2nid("mySN") == nid && OBJ_ln2nid("my long name") == nid && OBJ_txt2nid("1.2.3.4.5.6.7") == nid
              && OBJ_txt2nid("mySN") == nid,
          "and the new object is found by name and OID");
    o = OBJ_nid2obj(nid);
    text_of("created", o, 0);
    check(o != NULL && OBJ_txt2obj("1.2.3.4.5.6.7", 1) == o, "OBJ_txt2obj shares it");
    ASN1_OBJECT_free(o);
    check(OBJ_nid2obj(nid) == o, "and freeing it does nothing");
    check(OBJ_create("1.2.3.4.5.6.8", "mySN", NULL) == 0, "a short name can't be reused");
    show_error("existing name");
    check(OBJ_create("1.2.3.4.5.6.7", "other", NULL) == 0, "nor an OID");
    show_error("existing OID");
    check(OBJ_create("2.5.4.3", NULL, NULL) == 0 && OBJ_create("CN", NULL, NULL) == 0, "nor a built-in one");
    show_error("built-in OID");
    check(OBJ_create(NULL, NULL, NULL) == 0, "OBJ_create needs something");
    show_error("nothing");
    nid = OBJ_create(NULL, "nameOnly", NULL);
    check(nid == first + 1 && OBJ_nid2ln(nid) == NULL && strcmp(OBJ_nid2sn(nid), "nameOnly") == 0,
          "an object can have only a name");
    text_of("name only", OBJ_nid2obj(nid), 0);
    check(OBJ_create("1.2.3.4.5.6.9", NULL, "only long") == first + 2 && OBJ_sn2nid("only long") == 0,
          "or only a long name");
    text_of("long only", OBJ_nid2obj(first + 2), 0);

    o = ASN1_OBJECT_create(OBJ_new_nid(1), (unsigned char *)"\x2a\x03\x05\x07", 4, "addedSN", NULL);
    nid = OBJ_add_object(o);
    added = OBJ_nid2obj(nid);
    check(nid == first + 3 && added != o && OBJ_sn2nid("addedSN") == nid && OBJ_txt2nid("1.2.3.5.7") == nid,
          "OBJ_add_object adds a copy");
    ASN1_OBJECT_free(o);
    check(OBJ_add_object(added) == nid, "adding an added object again is harmless");
    o = ASN1_OBJECT_create(nid, (unsigned char *)"\x2a\x03\x05\x08", 4, "replacingSN", NULL);
    check(OBJ_add_object(o) == NID_undef && OBJ_nid2obj(nid) == added && OBJ_txt2nid("1.2.3.5.7") == nid
              && OBJ_txt2nid("1.2.3.5.8") == NID_undef && OBJ_sn2nid("replacingSN") == NID_undef,
          "a different object under an added NID is refused");
    ASN1_OBJECT_free(o);
    o = ASN1_OBJECT_create(OBJ_new_nid(1), (unsigned char *)"\x2a\x03\x05\x07", 4, "otherSN", NULL);
    check(OBJ_add_object(o) == NID_undef && OBJ_sn2nid("otherSN") == NID_undef,
          "so is an added OID under another NID");
    ASN1_OBJECT_free(o);
    o = ASN1_OBJECT_create(OBJ_new_nid(1), (unsigned char *)"\x55\x04\x03", 3, "cnAgain", NULL);
    check(OBJ_add_object(o) == NID_undef && OBJ_sn2nid("cnAgain") == NID_undef, "and a built-in OID");
    ASN1_OBJECT_free(o);
    check(OBJ_add_object(OBJ_nid2obj(NID_commonName)) == NID_undef, "and a built-in object");

    in = BIO_new(BIO_s_mem());
    BIO_puts(in, "1.2.3.6.1 fileSN1 file long name 1\n"
                 "1.2.3.6.2  fileSN2\n"
                 "1.2.3.6.3\n"
                 "1.2.3.6.4 fileSN4 file long 4\n"
                 "# a comment ends it\n"
                 "1.2.3.6.5 never\n");
    printf("# OBJ_create_objects: %d\n", OBJ_create_objects(in));
    show_error("create_objects");
    BIO_free(in);
    /* A line without a long name after one with: OpenSSL reuses what's left in its buffer. */
    in = BIO_new(BIO_s_mem());
    BIO_puts(in, "1.2.3.7.1 sn71 long seven one\n1.2.3.7.2\n1.2.3.7.3 sn73\n");
    printf("# OBJ_create_objects with a stale long name: %d, 1.2.3.7.2=%d\n", OBJ_create_objects(in),
           OBJ_txt2nid("1.2.3.7.2"));
    show_error("stale long name");
    printf("# fileSN1=%d fileSN2=%d (ln %s) 1.2.3.6.3=%d fileSN4=%d never=%d\n", OBJ_sn2nid("fileSN1"),
           OBJ_sn2nid("fileSN2"), OBJ_sn2nid("fileSN2") ? OBJ_nid2ln(OBJ_sn2nid("fileSN2")) : "-",
           OBJ_txt2nid("1.2.3.6.3"), OBJ_sn2nid("fileSN4"), OBJ_sn2nid("never"));
    ERR_clear_error();
    BIO_free(in);
}

static int compare_ints(const void *a, const void *b)
{
    return *(const int *)a - *(const int *)b;
}

static void searching(void)
{
    static const int sorted[] = { 1, 3, 3, 3, 5, 7, 9, 9 };
    int key, i;

    for (key = 0; key <= 10; key++) {
        const int *p = OBJ_bsearch_(&key, sorted, 8, sizeof(int), compare_ints);
        const int *f = OBJ_bsearch_ex_(&key, sorted, 8, sizeof(int), compare_ints, OBJ_BSEARCH_FIRST_VALUE_ON_MATCH);
        const int *v = OBJ_bsearch_ex_(&key, sorted, 8, sizeof(int), compare_ints, OBJ_BSEARCH_VALUE_ON_NOMATCH);

        printf("# bsearch %d: %d %d %d\n", key, p ? (int)(p - sorted) : -1, f ? (int)(f - sorted) : -1,
               v ? (int)(v - sorted) : -1);
    }
    key = 3;
    i = (int)((const int *)OBJ_bsearch_ex_(&key, sorted, -2, sizeof(int), compare_ints,
                                         OBJ_BSEARCH_FIRST_VALUE_ON_MATCH) - sorted);
    check(OBJ_bsearch_(&key, sorted, 0, sizeof(int), compare_ints) == NULL && i == 0
              && OBJ_bsearch_(&key, sorted, -2, sizeof(int), compare_ints) == NULL,
          "empty and negative counts");
}

static void sigids(void)
{
    int dig = -1, pkey = -1, sig = -1;

    check(OBJ_find_sigid_algs(NID_sha256WithRSAEncryption, &dig, &pkey) == 1 && dig == NID_sha256
              && pkey == NID_rsaEncryption,
          "OBJ_find_sigid_algs");
    check(OBJ_find_sigid_algs(NID_ecdsa_with_Recommended, &dig, NULL) == 1 && dig == NID_undef
              && OBJ_find_sigid_algs(NID_sha256, NULL, NULL) == 0 && OBJ_find_sigid_algs(0, NULL, NULL) == 0,
          "algorithms without a digest, and non-signatures");
    check(OBJ_find_sigid_by_algs(&sig, NID_sha256, NID_rsaEncryption) == 1 && sig == NID_sha256WithRSAEncryption
              && OBJ_find_sigid_by_algs(&sig, NID_sha1, NID_dsa) == 1 && sig == NID_dsaWithSHA1
              && OBJ_find_sigid_by_algs(NULL, NID_undef, NID_X9_62_id_ecPublicKey) == 0
              && OBJ_find_sigid_by_algs(NULL, NID_sha256, NID_undef) == 0,
          "OBJ_find_sigid_by_algs");
    check(OBJ_add_sigid(NID_sha256WithRSAEncryption, NID_sha256, NID_rsaEncryption) == 1
              && OBJ_add_sigid(NID_sha256WithRSAEncryption, NID_sha1, NID_rsaEncryption) == 0
              && OBJ_add_sigid(0, NID_sha1, NID_rsaEncryption) == 0 && OBJ_add_sigid(5001, NID_sha1, 0) == 0,
          "OBJ_add_sigid of known or incomplete algorithms");
    check(OBJ_add_sigid(5001, NID_sha3_256, NID_ED25519) == 1 && OBJ_add_sigid(5002, NID_undef, NID_X448) == 1
              && OBJ_add_sigid(5003, NID_sha3_512, NID_X448) == 1 && OBJ_add_sigid(5001, NID_sha3_256, NID_ED25519) == 1,
          "OBJ_add_sigid of new ones");
    check(OBJ_find_sigid_algs(5001, &dig, &pkey) == 1 && dig == NID_sha3_256 && pkey == NID_ED25519,
          "they're found by signature");
    sig = 0;
    OBJ_find_sigid_by_algs(&sig, NID_sha3_256, NID_ED25519);
    printf("# by algorithms: sha3-256/ED25519=%d", sig);
    sig = 0;
    OBJ_find_sigid_by_algs(&sig, NID_sha3_512, NID_X448);
    printf(" sha3-512/X448=%d", sig);
    sig = 0;
    OBJ_find_sigid_by_algs(&sig, NID_md5, NID_X448);
    printf(" md5/X448=%d\n", sig);
    /* After OBJ_sigid_free, OpenSSL crashes on any search that reaches the added ones. */
    OBJ_sigid_free();
    check(OBJ_find_sigid_algs(NID_sha1WithRSAEncryption, NULL, NULL) == 1
              && OBJ_find_sigid_by_algs(NULL, NID_sha1, NID_rsaEncryption) == 1,
          "OBJ_sigid_free leaves the built-in ones");
}

static void visit(const OBJ_NAME *name, void *arg)
{
    printf(" %s%s=%s", name->alias ? "@" : "", name->name, name->data);
    (*(int *)arg)++;
}

static int freed = 0;

static void free_name(const char *name, int type, const char *data)
{
    printf("# freed %s (%d) %s\n", name, type, data);
    freed++;
}

static unsigned long first_char_hash(const char *name)
{
    return (unsigned char)name[0];
}

static void names(void)
{
    static const char *const words[] = { "alpha", "Bravo", "charlie", "DELTA", "echo", "foxtrot", "Golf",
                                         "hotel", "india", "Juliet", "kilo", "lima", "Mike", "november" };
    int count = 0, type, i;

    check(OBJ_NAME_init() == 1, "OBJ_NAME_init");
    for (i = 0; i < 14; i++)
        OBJ_NAME_add(words[i], i % 2 + 1, words[13 - i]);
    check(OBJ_NAME_add("ALIAS", OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS, "CHARLIE") == 1, "OBJ_NAME_add");
    check(OBJ_NAME_get("ALPHA", OBJ_NAME_TYPE_MD_METH) != NULL && strcmp(OBJ_NAME_get("ALPHA", 1), "november") == 0
              && OBJ_NAME_get("alpha", 2) == NULL,
          "names are found without regard to case, by type");
    check(OBJ_NAME_get("alias", 1) != NULL && strcmp(OBJ_NAME_get("alias", 1), "lima") == 0,
          "aliases are followed");
    check(strcmp(OBJ_NAME_get("alias", 1 | OBJ_NAME_ALIAS), "CHARLIE") == 0, "unless asked not to");
    printf("# type 1:");
    OBJ_NAME_do_all(1, visit, &count);
    printf("\n# type 2 sorted:");
    OBJ_NAME_do_all_sorted(2, visit, &count);
    printf("\n");
    check(count == 15, "OBJ_NAME_do_all and OBJ_NAME_do_all_sorted visit each name of the type");
    check(OBJ_NAME_add("ALPHA", 1, "replaced") == 1 && strcmp(OBJ_NAME_get("alpha", 1), "replaced") == 0,
          "adding again replaces");
    check(OBJ_NAME_remove("Alpha", 1) == 1 && OBJ_NAME_get("alpha", 1) == NULL && OBJ_NAME_remove("alpha", 1) == 0,
          "OBJ_NAME_remove");
    OBJ_NAME_add("loop1", 3 | OBJ_NAME_ALIAS, "loop2");
    OBJ_NAME_add("loop2", 3 | OBJ_NAME_ALIAS, "loop1");
    check(OBJ_NAME_get("loop1", 3) == NULL && OBJ_NAME_get(NULL, 3) == NULL, "alias loops end");
    OBJ_NAME_cleanup(1);
    OBJ_NAME_cleanup(2);
    OBJ_NAME_cleanup(3);
    count = 0;
    OBJ_NAME_do_all(1, visit, &count);
    OBJ_NAME_do_all(2, visit, &count);
    check(count == 0 && OBJ_NAME_get("Bravo", 2) == NULL, "OBJ_NAME_cleanup removes a type's names");

    /* After OBJ_NAME_new_index, OpenSSL calls the (NULL) free function of the built-in types. */
    type = OBJ_NAME_new_index(first_char_hash, strcmp, free_name);
    check(type == OBJ_NAME_TYPE_NUM && OBJ_NAME_new_index(NULL, NULL, NULL) == OBJ_NAME_TYPE_NUM + 1,
          "OBJ_NAME_new_index hands out types");
    for (i = 0; i < 14; i++)
        OBJ_NAME_add(words[i], type, words[13 - i]);
    check(OBJ_NAME_get("alpha", type) != NULL && OBJ_NAME_get("ALPHA", type) == NULL,
          "a type's comparison is its own");
    OBJ_NAME_add("alpha", type, "again");
    check(freed == 1, "replacing calls the type's free function");
    count = 0;
    printf("# new type:");
    OBJ_NAME_do_all(type, visit, &count);
    printf("\n");
    check(count == 14, "its names are visited in the table's order");
    OBJ_NAME_cleanup(type);
    check(freed == 15, "and OBJ_NAME_cleanup frees them");
}

int main(void)
{
    lookups();
    texts();
    encodings();
    printing();
    dynamic();
    creating();
    searching();
    sigids();
    names();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
