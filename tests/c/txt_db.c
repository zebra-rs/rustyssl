/*
 * Conformance test for TXT_DB (TXT_DB_read, TXT_DB_write, TXT_DB_create_index,
 * TXT_DB_get_by_index, TXT_DB_insert, TXT_DB_free): rows of tab-separated fields with comments
 * and escaped tabs, the reader's piecewise lines (a long comment line goes on as a row), a wrong
 * number of fields, indexes with and without a qualifier, index clashes on creation and on
 * insertion, rows the application builds, and the text written back.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/txt_db.h>

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

/* The key of an index on field 0, and its comparison. */
static unsigned long hash0(const void *a)
{
    return OPENSSL_LH_strhash(((const OPENSSL_STRING *)a)[0]);
}

static int cmp0(const void *a, const void *b)
{
    return strcmp(((const OPENSSL_STRING *)a)[0], ((const OPENSSL_STRING *)b)[0]);
}

static unsigned long hash2(const void *a)
{
    return OPENSSL_LH_strhash(((const OPENSSL_STRING *)a)[2]);
}

static int cmp2(const void *a, const void *b)
{
    return strcmp(((const OPENSSL_STRING *)a)[2], ((const OPENSSL_STRING *)b)[2]);
}

/* Rows whose first field starts with 'V' are indexed. */
static int valid_only(OPENSSL_STRING *row)
{
    return row[0][0] == 'V';
}

static void dump(TXT_DB *db)
{
    BIO *out = BIO_new(BIO_s_mem());
    char *p;
    long n = TXT_DB_write(out, db), m = BIO_get_mem_data(out, &p);

    printf("  %ld octets written (%ld held):\n", n, m);
    fwrite(p, 1, (size_t)m, stdout);
    BIO_free(out);
}

static void show(const char *label, OPENSSL_STRING *row, int n)
{
    int i;

    printf("  %s:", label);
    if (row == NULL) {
        printf(" (none)\n");
        return;
    }
    for (i = 0; i < n; i++)
        printf(" [%s]", row[i] == NULL ? "(null)" : row[i]);
    printf("\n");
}

static TXT_DB *read_text(const char *text, int len, int num)
{
    BIO *b = BIO_new_mem_buf(text, len);
    TXT_DB *db = TXT_DB_read(b, num);

    BIO_free(b);
    return db;
}

int main(void)
{
    static const char text[] = "# a comment\n"
                               "V\tone\talpha\n"
                               "R\ttwo\tbe\\\ttab\n"
                               "V\tthree\t\n"
                               "V\tfour\tdelta\textra\n"
                               "V\tfive\techo";
    char longline[1400];
    TXT_DB *db;
    OPENSSL_STRING key[3], *r, *row;
    size_t i;

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("# reading\n");
    db = read_text(text, -1, 3);
    check(db == NULL, "a row with four fields fails the read");
    errors();
    db = read_text(text, (int)(strstr(text, "V\tfour") - text), 3);
    check(db != NULL && sk_OPENSSL_PSTRING_num(db->data) == 3, "three rows");
    printf("  fields %d, error %ld\n", db->num_fields, db->error);
    for (i = 0; i < (size_t)sk_OPENSSL_PSTRING_num(db->data); i++)
        show("row", sk_OPENSSL_PSTRING_value(db->data, (int)i), 3);
    dump(db);

    printf("# indexes\n");
    key[0] = "R";
    key[1] = key[2] = NULL;
    check(TXT_DB_get_by_index(db, 0, key) == NULL && db->error == DB_ERROR_NO_INDEX, "no index yet");
    check(TXT_DB_get_by_index(db, 3, key) == NULL && db->error == DB_ERROR_INDEX_OUT_OF_RANGE, "index out of range");
    check(TXT_DB_create_index(db, 3, NULL, hash0, cmp0) == 0 && db->error == DB_ERROR_INDEX_OUT_OF_RANGE,
          "create out of range");
    check(TXT_DB_create_index(db, 0, NULL, hash0, cmp0) == 0 && db->error == DB_ERROR_INDEX_CLASH,
          "field 0 clashes");
    printf("  arg1 %ld, arg2 %ld\n", db->arg1, db->arg2);
    db->error = 0;
    check(TXT_DB_create_index(db, 0, valid_only, hash2, cmp2) == 1, "an index of the valid rows by field 2");
    key[0] = "V";
    key[2] = "alpha";
    r = TXT_DB_get_by_index(db, 0, key);
    show("alpha", r, 3);
    check(r != NULL && db->error == DB_ERROR_OK, "found");
    key[2] = "be\ttab";
    check(TXT_DB_get_by_index(db, 0, key) == NULL && db->error == DB_ERROR_OK, "a revoked row isn't indexed");
    check(TXT_DB_create_index(db, 1, NULL, hash0, cmp0) == 0, "field 1 by field 0 clashes too");
    check(TXT_DB_create_index(db, 2, NULL, hash2, cmp2) == 1, "field 2 by itself");

    printf("# inserting\n");
    row = OPENSSL_malloc(4 * sizeof(*row));
    row[0] = OPENSSL_strdup("V");
    row[1] = OPENSSL_strdup("six");
    row[2] = OPENSSL_strdup("alpha");
    row[3] = NULL;
    check(TXT_DB_insert(db, row) == 0 && db->error == DB_ERROR_INDEX_CLASH, "a clash on field 0's index");
    printf("  arg1 %ld\n", db->arg1);
    show("clashed with", db->arg_row, 3);
    OPENSSL_free(row[2]);
    row[2] = OPENSSL_strdup("six\tseven");
    check(TXT_DB_insert(db, row) == 1, "inserted");
    key[2] = "six\tseven";
    show("by field 2", TXT_DB_get_by_index(db, 2, key), 3);
    r = sk_OPENSSL_PSTRING_value(db->data, 1);
    r[1] = OPENSSL_strdup("TWO");
    dump(db);
    TXT_DB_free(db);

    printf("# long lines\n");
    memset(longline, 'x', sizeof(longline));
    longline[0] = '#';
    memcpy(longline + 600, "\tmid\tend\n", 9);
    longline[609] = '\0';
    db = read_text(longline, -1, 3);
    check(db != NULL && sk_OPENSSL_PSTRING_num(db->data) == 1, "a long comment line's rest is a row");
    if (db != NULL) {
        r = sk_OPENSSL_PSTRING_value(db->data, 0);
        printf("  field 0 has %zu octets: %s|%s\n", strlen(r[0]), r[1], r[2]);
    }
    TXT_DB_free(db);
    memset(longline, 'y', sizeof(longline));
    memcpy(longline + 1300, "\tb\tc\n", 5);
    db = read_text(longline, 1305, 3);
    check(db != NULL && sk_OPENSSL_PSTRING_num(db->data) == 1, "a row read in three pieces");
    if (db != NULL)
        printf("  field 0 has %zu octets\n", strlen(sk_OPENSSL_PSTRING_value(db->data, 0)[0]));
    {
        BIO *out = BIO_new(BIO_s_mem());

        printf("  %ld octets written\n", TXT_DB_write(out, db));
        BIO_free(out);
    }
    TXT_DB_free(db);

    printf("# edge cases\n");
    check(read_text("a\n", -1, 0) == NULL, "no fields");
    errors();
    db = read_text("\n\n", -1, 1);
    check(db != NULL && sk_OPENSSL_PSTRING_num(db->data) == 2, "empty lines are rows of one field");
    dump(db);
    TXT_DB_free(db);
    db = read_text("a\tb\t\n", -1, 2);
    check(db != NULL && sk_OPENSSL_PSTRING_num(db->data) == 1, "a trailing tab after the last field");
    dump(db);
    TXT_DB_free(db);
    db = read_text("a\\\tb\tc\\\n", -1, 2);
    show("escapes", db == NULL ? NULL : sk_OPENSSL_PSTRING_value(db->data, 0), 2);
    TXT_DB_free(db);
    db = read_text("", 0, 2);
    check(db != NULL && sk_OPENSSL_PSTRING_num(db->data) == 0, "nothing to read");
    dump(db);
    TXT_DB_free(db);
    TXT_DB_free(NULL);
    errors();

    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
