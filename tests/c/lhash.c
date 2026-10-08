/*
 * Conformance test for the hash table (OPENSSL_LH_COMPFUNC(3), DEFINE_LHASH_OF_EX), in TAP
 * format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). The order in which
 * OPENSSL_LH_doall visits items follows from OpenSSL's linear hashing (when buckets split and
 * merge), so the test prints visiting orders, call counts, and statistics as comments, which the
 * harness compares between the two runs.
 */
/* The statistics functions are deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Items keyed by number, with a hash that is the number itself. */
typedef struct {
    int key;
    int tag;
} ITEM;

DEFINE_LHASH_OF_EX(ITEM);

static int hashes, comparisons;

static unsigned long item_hash(const ITEM *item)
{
    hashes++;
    return (unsigned long)item->key;
}

static int item_compare(const ITEM *a, const ITEM *b)
{
    comparisons++;
    return a->key != b->key;
}

static ITEM items[300];
static char order[4096];

static void note(const ITEM *item)
{
    size_t n = strlen(order);

    if (n + 8 < sizeof(order))
        snprintf(order + n, sizeof(order) - n, "%d ", item->key);
}

static void visit(ITEM *item)
{
    note(item);
}

static void print_order(const char *label, LHASH_OF(ITEM) *lh)
{
    order[0] = '\0';
    lh_ITEM_doall(lh, visit);
    printf("# %s: %s\n", label, order);
}

static void counting(void)
{
    LHASH_OF(ITEM) *lh = lh_ITEM_new(item_hash, item_compare);
    ITEM other = { 7, 1 }, missing = { 1000, 0 };
    int ok = 1;

    for (int i = 0; i < 300; i++) {
        items[i].key = i * 3;
        items[i].tag = 0;
    }
    check(lh != NULL && lh_ITEM_num_items(lh) == 0 && lh_ITEM_error(lh) == 0, "lh_ITEM_new");
    hashes = comparisons = 0;
    for (int i = 0; i < 40; i++)
        ok = ok && lh_ITEM_insert(lh, &items[i]) == NULL;
    check(ok && lh_ITEM_num_items(lh) == 40 && hashes == 40 && comparisons == 0,
          "inserting new keys: one hash each, no comparisons for distinct hashes");
    print_order("after 40 inserts", lh);
    hashes = comparisons = 0;
    ok = 1;
    for (int i = 0; i < 40; i++)
        ok = ok && lh_ITEM_retrieve(lh, &items[i]) == &items[i];
    check(ok && hashes == 40 && comparisons == 40, "retrieving each: one comparison each");
    other.key = items[5].key;
    check(lh_ITEM_retrieve(lh, &other) == &items[5], "retrieving by an equal key");
    check(lh_ITEM_insert(lh, &other) == &items[5] && lh_ITEM_num_items(lh) == 40
          && lh_ITEM_retrieve(lh, &items[5]) == &other,
          "inserting an equal key replaces the item and returns the old one");
    check(lh_ITEM_retrieve(lh, &missing) == NULL && lh_ITEM_delete(lh, &missing) == NULL,
          "a missing key");
    check(lh_ITEM_delete(lh, &items[5]) == &other && lh_ITEM_num_items(lh) == 39
          && lh_ITEM_retrieve(lh, &items[5]) == NULL, "lh_ITEM_delete returns the item");
    print_order("after a delete", lh);
    for (int i = 40; i < 300; i++)
        lh_ITEM_insert(lh, &items[i]);
    print_order("after 300 inserts", lh);
    printf("# down load %lu\n", lh_ITEM_get_down_load(lh));
    for (int i = 0; i < 300; i += 2)
        lh_ITEM_delete(lh, &items[i]);
    check(lh_ITEM_num_items(lh) == 149, "deleting half");
    print_order("after deleting half", lh);
    for (int i = 1; i < 260; i += 2)
        lh_ITEM_delete(lh, &items[i]);
    print_order("after deleting most", lh);
    lh_ITEM_set_down_load(lh, 0);
    check(lh_ITEM_get_down_load(lh) == 0, "lh_ITEM_set_down_load");
    lh_ITEM_flush(lh);
    check(lh_ITEM_num_items(lh) == 0 && lh_ITEM_retrieve(lh, &items[1]) == NULL,
          "lh_ITEM_flush empties the table");
    check(lh_ITEM_insert(lh, &items[1]) == NULL && lh_ITEM_num_items(lh) == 1,
          "a flushed table takes new items");
    lh_ITEM_free(lh);
    lh_ITEM_free(NULL);
    check(1, "lh_ITEM_free, including null");
}

/* Deleting the item being visited, as OpenSSL's own session cache does. */
static LHASH_OF(ITEM) *current;
static int visited;

static void delete_visited(ITEM *item, void *arg)
{
    (void)arg;
    visited++;
    note(item);
    lh_ITEM_delete(current, item);
}

IMPLEMENT_LHASH_DOALL_ARG(ITEM, void);

static void deleting(void)
{
    current = lh_ITEM_new(item_hash, item_compare);
    for (int i = 0; i < 100; i++)
        lh_ITEM_insert(current, &items[i]);
    lh_ITEM_set_down_load(current, 0);
    visited = 0;
    order[0] = '\0';
    lh_ITEM_doall_void(current, delete_visited, NULL);
    check(visited == 100 && lh_ITEM_num_items(current) == 0,
          "doall: the callback may delete what it visits (with down load 0)");
    for (int i = 0; i < 100; i++)
        lh_ITEM_insert(current, &items[i]);
    lh_ITEM_set_down_load(current, 256);
    visited = 0;
    order[0] = '\0';
    lh_ITEM_doall_void(current, delete_visited, NULL);
    printf("# deleting while the table shrinks: visited %d, %lu left: %s\n", visited,
           lh_ITEM_num_items(current), order);
    check(visited > 0, "doall: deleting while the table shrinks");
    lh_ITEM_free(current);
}

/* The raw functions, with OPENSSL_LH_new's string defaults. */
static int seen;

static void count_arg(void *item, void *arg)
{
    (void)item;
    *(int *)arg += 1;
}

static void count_item(ITEM *item, void *arg)
{
    note(item);
    *(int *)arg += 1;
}

static void doall_arg(void)
{
    LHASH_OF(ITEM) *lh = lh_ITEM_new(item_hash, item_compare);

    for (int i = 0; i < 20; i++)
        lh_ITEM_insert(lh, &items[i]);
    seen = 0;
    order[0] = '\0';
    lh_ITEM_doall_arg(lh, count_item, &seen);
    printf("# doall_arg: %s\n", order);
    check(seen == 20, "lh_ITEM_doall_arg: OPENSSL_LH_doall_arg passes the argument");
    lh_ITEM_free(lh);
}

static void strings(void)
{
    OPENSSL_LHASH *lh = OPENSSL_LH_new(NULL, NULL);
    char apple[] = "apple", pear[] = "pear", apple2[] = "apple";
    FILE *f;
    char line[256];

    check(lh != NULL && OPENSSL_LH_insert(lh, apple) == NULL && OPENSSL_LH_insert(lh, pear) == NULL,
          "OPENSSL_LH_new(NULL, NULL): strings");
    check(OPENSSL_LH_retrieve(lh, apple2) == apple,
          "the default comparison is strcmp, the default hash OPENSSL_LH_strhash");
    check(OPENSSL_LH_num_items(lh) == 2 && OPENSSL_LH_num_items(NULL) == 0
          && OPENSSL_LH_error(lh) == 0, "OPENSSL_LH_num_items and OPENSSL_LH_error");
    /* Without thunks (only the typed wrappers set them), OpenSSL's doall would crash. */
    seen = 0;
    OPENSSL_LH_doall(NULL, NULL);
    OPENSSL_LH_doall_arg(NULL, count_arg, &seen);
    check(seen == 0, "OPENSSL_LH_doall and _doall_arg: null table");
    check(OPENSSL_LH_delete(lh, apple2) == apple && OPENSSL_LH_num_items(lh) == 1,
          "OPENSSL_LH_delete by an equal string");

    f = tmpfile();
    if (f != NULL) {
        OPENSSL_LH_stats(lh, f);
        OPENSSL_LH_node_stats(lh, f);
        OPENSSL_LH_node_usage_stats(lh, f);
        rewind(f);
        while (fgets(line, sizeof(line), f) != NULL)
            printf("# %s", line);
        fclose(f);
    }
    check(f != NULL, "OPENSSL_LH_stats, _node_stats, _node_usage_stats");
    {
        BIO *out = BIO_new(BIO_s_mem());
        char *text = NULL;
        long len;

        OPENSSL_LH_stats_bio(lh, out);
        OPENSSL_LH_node_stats_bio(lh, out);
        OPENSSL_LH_node_usage_stats_bio(lh, out);
        len = BIO_get_mem_data(out, &text);
        printf("# the BIO statistics: %ld bytes\n", len);
        check(len > 0 && memcmp(text, "num_items             = 1\n", 26) == 0,
              "OPENSSL_LH_stats_bio, _node_stats_bio, _node_usage_stats_bio");
        BIO_free(out);
    }
    OPENSSL_LH_flush(lh);
    OPENSSL_LH_flush(NULL);
    OPENSSL_LH_free(lh);

    check(OPENSSL_LH_strhash(NULL) == 0 && OPENSSL_LH_strhash("") == 0,
          "OPENSSL_LH_strhash: null and empty are 0");
    printf("# strhash: %lu %lu %lu %lu\n", OPENSSL_LH_strhash("a"),
           OPENSSL_LH_strhash("apple"), OPENSSL_LH_strhash("The quick brown fox"),
           OPENSSL_LH_strhash("\x80\xff\x7f"));
    check(OPENSSL_LH_strhash("apple") != OPENSSL_LH_strhash("Apple"),
          "OPENSSL_LH_strhash: case matters");
}

int main(void)
{
    counting();
    deleting();
    doall_arg();
    strings();
    printf("1..%d\n", number);
    return failures != 0;
}
