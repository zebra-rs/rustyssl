/*
 * Conformance test for DH's ASN.1, PEM, and printing (d2i_DHparams(3), PEM_read_bio_DHparams(3),
 * DHparams_print(3)), in TAP format: PKCS #3 DHparameter (with and without the private key
 * length) and X9.42 DomainParameters (with and without j and the validation parameters)
 * encoded and decoded, reusing a key or not, as the item through ASN1_item_d2i and
 * ASN1_item_i2d, and refused when malformed or truncated; the named group a decoded key is; PEM
 * written and read through BIOs and FILEs; and the printed text of every kind.
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
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

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
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && *data != '\0')
            printf(" (%s)", data);
    }
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, int n)
{
    unsigned char d[32];
    unsigned int dl = 0;
    int i;

    if (n <= 0) {
        printf("  %s: %d\n", label, n);
        return;
    }
    EVP_Digest(p, n, d, &dl, EVP_sha256(), NULL);
    printf("  %s (%d): ", label, n);
    for (i = 0; i < n && i < 12; i++)
        printf("%02x", p[i]);
    printf(" sha256 ");
    for (i = 0; i < 8; i++)
        printf("%02x", d[i]);
    printf("\n");
}

static void show(const char *label, const DH *dh)
{
    const BIGNUM *p, *q, *g;

    if (dh == NULL) {
        printf("  %s: (none)\n", label);
        return;
    }
    DH_get0_pqg(dh, &p, &q, &g);
    printf("  %s: bits %d q %d g %d length %ld nid %d flags %#x\n", label, DH_bits(dh),
           q == NULL ? -1 : BN_num_bits(q), g == NULL ? -1 : BN_num_bits(g), DH_get_length(dh),
           DH_get_nid(dh), DH_test_flags(dh, ~0));
}

static void print_bio(const char *label, const DH *dh)
{
    BIO *b = BIO_new(BIO_s_mem());
    char *data = NULL;
    long n;
    int r = DHparams_print(b, dh);

    n = BIO_get_mem_data(b, &data);
    printf("  %s print %d (%ld):\n%.*s", label, r, n, (int)n, data);
    BIO_free(b);
}

/* p, q, g of a small made-up group (not a real group, just numbers to encode). */
static DH *made_up(int with_q, int with_j, int with_seed, long length)
{
    DH *dh = DH_new();
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&g, "05");
    if (with_q)
        BN_hex2bn(&q, "7BF3AFEE234833FF");
    DH_set0_pqg(dh, p, q, g);
    if (length != 0)
        DH_set_length(dh, length);
    (void)with_j;
    (void)with_seed;
    return dh;
}

static void roundtrip(const char *label, DH *dh, int x942)
{
    unsigned char *der = NULL;
    const unsigned char *pp;
    int n;
    DH *back;

    n = x942 ? i2d_DHxparams(dh, &der) : i2d_DHparams(dh, &der);
    hex(label, der, n);
    if (n > 0) {
        pp = der;
        back = x942 ? d2i_DHxparams(NULL, &pp, n) : d2i_DHparams(NULL, &pp, n);
        printf("  consumed %ld\n", (long)(pp - der));
        show("decoded", back);
        print_bio("decoded", back);
        DH_free(back);
    }
    OPENSSL_free(der);
    errors();
}

static void test_encode(void)
{
    DH *ff = DH_new_by_nid(NID_ffdhe2048), *r = DH_get_2048_256(), *dh;

    check(ff != NULL && r != NULL, "encoding and decoding");
    roundtrip("ffdhe2048", ff, 0);
    roundtrip("ffdhe2048 X9.42", ff, 1);
    roundtrip("2048_256", r, 0);
    roundtrip("2048_256 X9.42", r, 1);
    dh = made_up(0, 0, 0, 0);
    roundtrip("made up", dh, 0);
    roundtrip("made up X9.42 (no q)", dh, 1);
    DH_free(dh);
    dh = made_up(1, 0, 0, 100);
    roundtrip("made up, length 100", dh, 0);
    roundtrip("made up X9.42", dh, 1);
    DH_free(dh);
    dh = made_up(0, 0, 0, -5);
    roundtrip("made up, length -5", dh, 0);
    DH_free(dh);
    dh = DH_new();
    roundtrip("empty", dh, 0);
    DH_free(dh);
    DH_free(ff);
    DH_free(r);
}

/* Hand-made encodings: the validation parameters, j, and broken ones. */
static void decode(const char *label, const char *hexder, int x942)
{
    unsigned char buf[600];
    const unsigned char *pp = buf;
    long n = 0;
    DH *dh;
    unsigned char *re = NULL;
    int rn;

    while (hexder[2 * n] != '\0' && hexder[2 * n + 1] != '\0') {
        unsigned int b;

        sscanf(hexder + 2 * n, "%2x", &b);
        buf[n++] = (unsigned char)b;
    }
    dh = x942 ? d2i_DHxparams(NULL, &pp, n) : d2i_DHparams(NULL, &pp, n);
    printf("  %s: %s consumed %ld\n", label, dh == NULL ? "fails" : "ok", (long)(pp - buf));
    if (dh != NULL) {
        show("decoded", dh);
        rn = x942 ? i2d_DHxparams(dh, &re) : i2d_DHparams(dh, &re);
        printf("  re-encodes the same %d\n", rn == n && memcmp(re, buf, n) == 0);
        OPENSSL_free(re);
        print_bio("decoded", dh);
    }
    DH_free(dh);
    errors();
}

static void test_decode(void)
{
    check(1, "hand-made encodings");
    /* SEQUENCE { p, g } and with a length. */
    decode("p g", "30060201170201 05", 0);
    decode("p g", "3006020117020105", 0);
    decode("p g length", "3009020117020105020164", 0);
    decode("p g length 0", "3009020117020105020100", 0);
    decode("p g negative length", "30090201170201050201ff", 0);
    decode("p g huge length", "300d02011702010502050100000000", 0);
    decode("p only", "3003020117", 0);
    decode("trailing field", "300c020117020105020164020101", 0);
    decode("negative p", "30060201e9020105", 0);
    decode("truncated", "3009020117020105", 0);
    decode("not a sequence", "3106020117020105", 0);
    /* X9.42: p, g, q, then j and { seed, counter }. */
    decode("x9.42 p g q", "3009020117020105020102", 1);
    decode("x9.42 p g q j", "300c02011702010502010b020102", 1);
    decode("x9.42 p g q seed counter", "301302011702010502010b30080303000102020107", 1);
    decode("x9.42 p g q j seed counter",
           "301602011702010502010b02010230080303000102020107", 1);
    decode("x9.42 bits unused in the seed", "301302011702010502010b30080303040102020107", 1);
    decode("x9.42 missing q", "3006020117020105", 1);
    decode("x9.42 empty seed", "301102011702010502010b3006030100020107", 1);
    decode("x9.42 counter 0", "301302011702010502010b30080303000102020100", 1);
    decode("x9.42 vparams missing the counter", "301002011702010502010b30050303000102", 1);
}

static void test_item(void)
{
    DH *ff = DH_new_by_nid(NID_ffdhe3072), *dh;
    unsigned char *der = NULL;
    const unsigned char *pp;
    int n;

    check(ff != NULL, "the item");
    n = ASN1_item_i2d((ASN1_VALUE *)ff, &der, ASN1_ITEM_rptr(DHparams));
    hex("item encoding", der, n);
    pp = der;
    dh = (DH *)ASN1_item_d2i(NULL, &pp, n, ASN1_ITEM_rptr(DHparams));
    show("item decoded", dh);
    printf("  same as i2d_DHparams %d\n", n == i2d_DHparams(ff, NULL));
    /* Decoding into a key reuses it. */
    pp = der;
    printf("  into the key %d\n", d2i_DHparams(&dh, &pp, n) == dh);
    show("reused", dh);
    DH_free(dh);
    OPENSSL_free(der);
    DH_free(ff);
    errors();
}

static void test_pem(void)
{
    DH *ff = DH_new_by_nid(NID_ffdhe2048), *r = DH_get_2048_256(), *back;
    BIO *b = BIO_new(BIO_s_mem());
    char *data;
    long n;
    FILE *f;

    check(ff != NULL && b != NULL, "PEM");
    printf("  write %d", PEM_write_bio_DHparams(b, ff));
    n = BIO_get_mem_data(b, &data);
    printf(" (%ld):\n%.*s", n, (int)n, data);
    back = PEM_read_bio_DHparams(b, NULL, NULL, NULL);
    show("read back", back);
    DH_free(back);
    BIO_reset(b);
    printf("  write x %d", PEM_write_bio_DHxparams(b, r));
    n = BIO_get_mem_data(b, &data);
    printf(" (%ld):\n%.*s", n, (int)n, data);
    back = PEM_read_bio_DHparams(b, NULL, NULL, NULL);
    show("read back", back);
    DH_free(back);
    errors();
    BIO_reset(b);
    back = PEM_read_bio_DHparams(b, NULL, NULL, NULL);
    printf("  read empty %d", back != NULL);
    errors();

    f = tmpfile();
    printf("  file write %d %d", PEM_write_DHparams(f, ff), PEM_write_DHxparams(f, r));
    rewind(f);
    back = PEM_read_DHparams(f, NULL, NULL, NULL);
    show("file read", back);
    DH_free(back);
    back = PEM_read_DHparams(f, NULL, NULL, NULL);
    show("file read second", back);
    DH_free(back);
    fclose(f);
    BIO_free(b);
    DH_free(ff);
    DH_free(r);
    errors();
}

static void test_print(void)
{
    DH *ff = DH_new_by_nid(NID_ffdhe2048), *r = DH_get_2048_256(), *m;
    FILE *f;
    char line[256];

    check(ff != NULL, "printing");
    print_bio("ffdhe2048", ff);
    print_bio("2048_256", r);
    m = made_up(1, 0, 0, 160);
    print_bio("made up", m);
    DH_free(m);
    m = DH_new();
    print_bio("empty", m);
    errors();
    DH_free(m);
    f = tmpfile();
    printf("  print_fp %d\n", DHparams_print_fp(f, r));
    rewind(f);
    while (fgets(line, sizeof(line), f) != NULL)
        printf("  | %s", line);
    fclose(f);
    DH_free(ff);
    DH_free(r);
    errors();
}

int main(void)
{
    test_encode();
    test_decode();
    test_item();
    test_pem();
    test_print();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
