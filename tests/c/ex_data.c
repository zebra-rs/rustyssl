/*
 * Conformance test for application data on objects (CRYPTO_get_ex_new_index(3)), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). The callbacks
 * record the order they run in; free callbacks of equal priority run in the order the C
 * library's qsort leaves them, which both implementations share.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/stack.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static char log_text[1024];

static void record(const char *what, int idx, long argl)
{
    size_t n = strlen(log_text);

    if (n + 32 < sizeof(log_text))
        snprintf(log_text + n, sizeof(log_text) - n, "%s%d:%ld ", what, idx, argl);
}

static int parent;
static int values[8];

static void new_cb(void *p, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    record(ptr == NULL ? "new" : "new?", idx, argl);
    if (p == &parent && argp == &parent)
        CRYPTO_set_ex_data(ad, idx, &values[idx]);
}

static int dup_cb(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from, void **from_d, int idx,
                  long argl, void *argp)
{
    (void)to;
    (void)from;
    (void)argp;
    record("dup", idx, argl);
    if (argl == 99)
        return 0;
    if (*from_d == &values[idx])
        *from_d = &values[idx + 4];
    return 1;
}

static void free_cb(void *p, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)p;
    (void)ad;
    (void)argp;
    record(ptr == &values[idx] ? "free" : "free?", idx, argl);
}

static int stack_num(const CRYPTO_EX_DATA *ad)
{
    return OPENSSL_sk_num((const OPENSSL_STACK *)ad->sk);
}

static void indexes(void)
{
    int a = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 10, &parent, new_cb, dup_cb, free_cb);
    int b = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 11, &parent, new_cb, dup_cb, free_cb);
    int c = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 12, NULL, NULL, NULL, NULL);

    check(a == 1 && b == 2 && c == 3, "CRYPTO_get_ex_new_index: from 1, index 0 is reserved");
    check(CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI_METHOD, 0, NULL, NULL, NULL, NULL) == 1,
          "CRYPTO_get_ex_new_index: each class counts on its own");
    ERR_clear_error();
    check(CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX__COUNT, 0, NULL, NULL, NULL, NULL) == -1
          && ERR_get_error() == ERR_PACK(ERR_LIB_CRYPTO, 0, ERR_R_PASSED_INVALID_ARGUMENT)
          && CRYPTO_get_ex_new_index(-1, 0, NULL, NULL, NULL, NULL) == -1,
          "CRYPTO_get_ex_new_index: a class out of range");
    ERR_clear_error();
}

static void lifecycle(void)
{
    CRYPTO_EX_DATA ad, copy, other;

    memset(&ad, 0xff, sizeof(ad));
    log_text[0] = '\0';
    check(CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad) == 1 && ad.ctx == NULL,
          "CRYPTO_new_ex_data");
    check(strcmp(log_text, "new1:10 new2:11 ") == 0,
          "CRYPTO_new_ex_data: each new callback, in index order, with no value yet");
    check(CRYPTO_get_ex_data(&ad, 1) == &values[1] && CRYPTO_get_ex_data(&ad, 2) == &values[2]
          && CRYPTO_get_ex_data(&ad, 3) == NULL && CRYPTO_get_ex_data(&ad, 50) == NULL
          && CRYPTO_get_ex_data(&ad, -1) == NULL, "CRYPTO_get_ex_data");
    check(stack_num(&ad) == 3, "the values are a stack in the public struct");
    check(CRYPTO_set_ex_data(&ad, 6, &values[6]) == 1 && stack_num(&ad) == 7
          && CRYPTO_get_ex_data(&ad, 6) == &values[6] && CRYPTO_get_ex_data(&ad, 5) == NULL,
          "CRYPTO_set_ex_data: grows the stack");
    check(CRYPTO_set_ex_data(&ad, -1, NULL) == 1 && ERR_get_error() != 0,
          "CRYPTO_set_ex_data(-1, NULL): succeeds, leaving an error");
    ERR_clear_error();
    check(CRYPTO_set_ex_data(&ad, -1, &values[0]) == 0
          && ERR_get_error() == ERR_PACK(ERR_LIB_CRYPTO, 0, ERR_R_PASSED_INVALID_ARGUMENT)
          && ERR_get_error() == ERR_PACK(ERR_LIB_CRYPTO, 0, ERR_R_PASSED_INVALID_ARGUMENT),
          "CRYPTO_set_ex_data(-1, value): fails with two errors");

    memset(&copy, 0, sizeof(copy));
    log_text[0] = '\0';
    check(CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, &copy, &ad) == 1,
          "CRYPTO_dup_ex_data");
    check(strcmp(log_text, "dup1:10 dup2:11 ") == 0,
          "CRYPTO_dup_ex_data: each dup callback, for the indexes that exist");
    check(CRYPTO_get_ex_data(&copy, 1) == &values[5] && CRYPTO_get_ex_data(&copy, 2) == &values[6]
          && CRYPTO_get_ex_data(&copy, 6) == NULL && stack_num(&copy) == 4,
          "CRYPTO_dup_ex_data: copies what the callbacks return, up to the last index");

    log_text[0] = '\0';
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad);
    printf("# free order: %s\n", log_text);
    check(ad.sk == NULL && ad.ctx == NULL && strstr(log_text, "free1:10") != NULL
          && strstr(log_text, "free2:11") != NULL, "CRYPTO_free_ex_data");
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, &parent, &copy);

    memset(&other, 0, sizeof(other));
    check(CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, &copy, &other) == 1 && copy.sk == NULL,
          "CRYPTO_dup_ex_data: nothing to copy");
}

static void allocating(void)
{
    CRYPTO_EX_DATA ad;

    memset(&ad, 0, sizeof(ad));
    log_text[0] = '\0';
    check(CRYPTO_alloc_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad, 2) == 1
          && strcmp(log_text, "new2:11 ") == 0 && CRYPTO_get_ex_data(&ad, 2) == &values[2],
          "CRYPTO_alloc_ex_data: runs the new callback for a missing value");
    log_text[0] = '\0';
    check(CRYPTO_alloc_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad, 2) == 1 && log_text[0] == '\0',
          "CRYPTO_alloc_ex_data: nothing to do for a value that's there");
    check(CRYPTO_alloc_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad, 3) == 0,
          "CRYPTO_alloc_ex_data: 0 without a new callback");
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad);
}

static void freeing_indexes(void)
{
    CRYPTO_EX_DATA ad, copy;
    int idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 99, &parent, new_cb, dup_cb, free_cb);

    check(idx == 4, "a fourth index");
    memset(&ad, 0, sizeof(ad));
    memset(&copy, 0, sizeof(copy));
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad);
    log_text[0] = '\0';
    check(CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, &copy, &ad) == 0
          && strcmp(log_text, "dup1:10 dup2:11 dup4:99 ") == 0,
          "CRYPTO_dup_ex_data: fails when a dup callback does");
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, &parent, &copy);
    check(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, idx) == 1,
          "CRYPTO_free_ex_index");
    check(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, 50) == 0
          && CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, 0) == 0
          && CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, -1) == 0,
          "CRYPTO_free_ex_index: an index that doesn't exist, or the reserved one");
    log_text[0] = '\0';
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad);
    printf("# free order: %s\n", log_text);
    check(strstr(log_text, ":99") == NULL, "a freed index's callbacks no longer run");
    log_text[0] = '\0';
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad);
    check(strcmp(log_text, "new1:10 new2:11 ") == 0, "nor its new callback");
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, &parent, &ad);
    check(CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 0, NULL, NULL, NULL, NULL) == 5,
          "freed indexes aren't reused");
}

/* Many indexes: the free callbacks' order comes from qsort. */
static void many(void)
{
    CRYPTO_EX_DATA ad;

    for (int i = 0; i < 12; i++)
        CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, 100 + i, NULL, NULL, NULL, free_cb);
    memset(&ad, 0, sizeof(ad));
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DH, &parent, &ad);
    log_text[0] = '\0';
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, &parent, &ad);
    printf("# free order with 12 indexes: %s\n", log_text);
    check(strstr(log_text, "free?1:100") != NULL && strstr(log_text, "free?12:111") != NULL,
          "CRYPTO_free_ex_data: every free callback, with a null value");
    CRYPTO_free_ex_data(-1, &parent, &ad);
    check(ad.sk == NULL, "CRYPTO_free_ex_data: a bad class still frees the values");
    ERR_clear_error();
}

int main(void)
{
    indexes();
    lifecycle();
    allocating();
    freeing_indexes();
    many();
    printf("1..%d\n", number);
    return failures != 0;
}
