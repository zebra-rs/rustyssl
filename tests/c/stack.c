/*
 * Conformance test for the generic stack (OPENSSL_sk_new(3), DEFINE_STACK_OF(3)), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). Sorting uses the
 * C library's qsort in both, so the test compares a sorted stack with qsort's own result rather
 * than with a fixed order.
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
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

static int same(const char *a, const char *b)
{
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

/* The elements are pointers into `values`; the comparator compares what they point to. */
static int values[32];
static int compared;

static int by_value(const void *a, const void *b)
{
    const int *x = *(const int *const *)a, *y = *(const int *const *)b;

    compared++;
    if (x == NULL || y == NULL)
        return (x != NULL) - (y != NULL);
    return *x < *y ? -1 : *x > *y;
}

static int reversed(const void *a, const void *b)
{
    return -by_value(a, b);
}

static void *v(int i)
{
    return &values[i];
}

/* The values of a stack's elements, as "3 1 2". */
static const char *contents(const OPENSSL_STACK *st)
{
    static char text[512];
    size_t used = 0;

    text[0] = '\0';
    for (int i = 0; i < OPENSSL_sk_num(st) && used + 12 < sizeof(text); i++) {
        const int *p = OPENSSL_sk_value(st, i);

        used += (size_t)snprintf(text + used, sizeof(text) - used, "%s%d", i ? " " : "",
                                 p == NULL ? -1 : *p);
    }
    return text;
}

static void basics(void)
{
    OPENSSL_STACK *st = OPENSSL_sk_new_null();

    check(st != NULL && OPENSSL_sk_num(st) == 0 && OPENSSL_sk_value(st, 0) == NULL
          && OPENSSL_sk_is_sorted(st) == 0, "OPENSSL_sk_new_null: empty, not sorted");
    check(OPENSSL_sk_num(NULL) == -1 && OPENSSL_sk_value(NULL, 0) == NULL
          && OPENSSL_sk_is_sorted(NULL) == 1, "OPENSSL_sk_num, _value, _is_sorted: null");
    check(OPENSSL_sk_push(st, v(1)) == 1 && OPENSSL_sk_push(st, v(2)) == 2
          && OPENSSL_sk_unshift(st, v(0)) == 3 && same(contents(st), "0 1 2"),
          "OPENSSL_sk_push and _unshift: return the new count");
    check(OPENSSL_sk_insert(st, v(5), 1) == 4 && OPENSSL_sk_insert(st, v(6), -1) == 5
          && OPENSSL_sk_insert(st, v(7), 99) == 6 && same(contents(st), "0 5 1 2 6 7"),
          "OPENSSL_sk_insert: in the middle, and at the end for -1 or past it");
    check(OPENSSL_sk_value(st, -1) == NULL && OPENSSL_sk_value(st, 6) == NULL
          && OPENSSL_sk_value(st, 5) == v(7), "OPENSSL_sk_value: out of range is null");
    check(OPENSSL_sk_delete(st, 1) == v(5) && OPENSSL_sk_delete(st, -1) == NULL
          && OPENSSL_sk_delete(st, 5) == NULL && same(contents(st), "0 1 2 6 7"),
          "OPENSSL_sk_delete");
    check(OPENSSL_sk_delete_ptr(st, v(6)) == v(6) && OPENSSL_sk_delete_ptr(st, v(9)) == NULL
          && same(contents(st), "0 1 2 7"), "OPENSSL_sk_delete_ptr: by identity");
    check(OPENSSL_sk_shift(st) == v(0) && OPENSSL_sk_pop(st) == v(7)
          && same(contents(st), "1 2"), "OPENSSL_sk_shift and _pop");
    ERR_clear_error();
    check(OPENSSL_sk_set(st, 1, v(3)) == v(3) && same(contents(st), "1 3")
          && ERR_peek_error() == 0, "OPENSSL_sk_set: returns the new element");
    check(OPENSSL_sk_set(st, 2, v(3)) == NULL, "OPENSSL_sk_set: out of range fails");
    {
        const char *data = NULL;
        int flags = 0;

        check(ERR_get_error_all(NULL, NULL, NULL, &data, &flags)
                  == ERR_PACK(ERR_LIB_CRYPTO, 0, ERR_R_PASSED_INVALID_ARGUMENT)
              && same(data, "i=2") && flags == (ERR_TXT_MALLOCED | ERR_TXT_STRING),
              "OPENSSL_sk_set: the error names the index");
    }
    check(OPENSSL_sk_set(NULL, 0, v(1)) == NULL
          && ERR_get_error() == ERR_PACK(ERR_LIB_CRYPTO, 0, ERR_R_PASSED_NULL_PARAMETER),
          "OPENSSL_sk_set: null stack");
    check(OPENSSL_sk_insert(NULL, v(1), 0) == 0
          && ERR_get_error() == ERR_PACK(ERR_LIB_CRYPTO, 0, ERR_R_PASSED_NULL_PARAMETER)
          && OPENSSL_sk_push(NULL, v(1)) == 0 && ERR_peek_error() == 0,
          "OPENSSL_sk_insert: null stack raises; OPENSSL_sk_push doesn't");
    check(OPENSSL_sk_shift(NULL) == NULL && OPENSSL_sk_pop(NULL) == NULL
          && OPENSSL_sk_delete(NULL, 0) == NULL && OPENSSL_sk_delete_ptr(NULL, v(1)) == NULL,
          "null stacks: nothing to remove");
    OPENSSL_sk_zero(st);
    check(OPENSSL_sk_num(st) == 0 && OPENSSL_sk_shift(st) == NULL && OPENSSL_sk_pop(st) == NULL,
          "OPENSSL_sk_zero; shifting and popping an empty stack");
    OPENSSL_sk_zero(NULL);
    OPENSSL_sk_free(st);
    OPENSSL_sk_free(NULL);
    check(1, "OPENSSL_sk_free, including null");
}

static void reserving(void)
{
    OPENSSL_STACK *st = OPENSSL_sk_new_reserve(by_value, 10);

    check(st != NULL && OPENSSL_sk_num(st) == 0, "OPENSSL_sk_new_reserve");
    check(OPENSSL_sk_reserve(st, -1) == 1 && OPENSSL_sk_reserve(st, 100) == 1,
          "OPENSSL_sk_reserve: negative is a no-op");
    OPENSSL_sk_push(st, v(1));
    ERR_clear_error();
    check(OPENSSL_sk_reserve(st, INT_MAX) == 0
          && ERR_get_error() == ERR_PACK(ERR_LIB_CRYPTO, 0, CRYPTO_R_TOO_MANY_RECORDS),
          "OPENSSL_sk_reserve: past the limit");
    check(OPENSSL_sk_reserve(NULL, 1) == 0
          && ERR_get_error() == ERR_PACK(ERR_LIB_CRYPTO, 0, ERR_R_PASSED_NULL_PARAMETER),
          "OPENSSL_sk_reserve: null stack");
    check(OPENSSL_sk_new_reserve(NULL, -5) != NULL, "OPENSSL_sk_new_reserve: negative");
    OPENSSL_sk_free(st);
}

static void finding(void)
{
    OPENSSL_STACK *st = OPENSSL_sk_new(by_value);
    int key, count = -1, at;

    for (int i = 0; i < 32; i++)
        values[i] = i;
    check(OPENSSL_sk_find(st, v(3)) == -1 && OPENSSL_sk_find(NULL, v(3)) == -1,
          "OPENSSL_sk_find: empty or null stack");
    /* 5 3 9 3 7 1 3, with the 3s at different addresses. */
    values[20] = 3;
    values[21] = 3;
    OPENSSL_sk_push(st, v(5));
    OPENSSL_sk_push(st, v(3));
    OPENSSL_sk_push(st, v(9));
    OPENSSL_sk_push(st, v(20));
    OPENSSL_sk_push(st, v(7));
    OPENSSL_sk_push(st, v(1));
    OPENSSL_sk_push(st, v(21));
    key = 3;
    {
        int *k = &key;

        compared = 0;
        check(OPENSSL_sk_find(st, k) == 1 && compared == 2,
              "OPENSSL_sk_find: unsorted, a linear search stopping at the first match");
        compared = 0;
        count = 10;
        check(OPENSSL_sk_find_all(st, k, &count) == 1 && count == 13 && compared == 7,
              "OPENSSL_sk_find_all: unsorted, adds every match to the caller's count");
        check(OPENSSL_sk_is_sorted(st) == 0, "finding doesn't sort");
        check(OPENSSL_sk_find(st, NULL) == -1, "OPENSSL_sk_find: null data with a comparator");
        OPENSSL_sk_sort(st);
        check(OPENSSL_sk_is_sorted(st) == 1 && same(contents(st), "1 3 3 3 5 7 9"),
              "OPENSSL_sk_sort");
        compared = 0;
        at = OPENSSL_sk_find(st, k);
        printf("# OPENSSL_sk_find: %d comparisons\n", compared);
        check(at == 1, "OPENSSL_sk_find: sorted, the first match");
        count = 0;
        check(OPENSSL_sk_find_all(st, k, &count) == 1 && count == 3,
              "OPENSSL_sk_find_all: sorted, counts the run of matches");
        key = 4;
        count = 7;
        check(OPENSSL_sk_find(st, k) == -1 && OPENSSL_sk_find_all(st, k, &count) == -1
              && count == 0, "a missing value");
        compared = 0;
        at = OPENSSL_sk_find_ex(st, k);
        printf("# OPENSSL_sk_find_ex(4) = %d after %d comparisons\n", at, compared);
        check(at >= 0, "OPENSSL_sk_find_ex: a nearby index when nothing matches");
        key = 100;
        printf("# OPENSSL_sk_find_ex(100) = %d\n", OPENSSL_sk_find_ex(st, k));
        key = -100;
        printf("# OPENSSL_sk_find_ex(-100) = %d\n", OPENSSL_sk_find_ex(st, k));
        key = 7;
        check(OPENSSL_sk_find_ex(st, k) == 5, "OPENSSL_sk_find_ex: a match");
    }
    check(OPENSSL_sk_set_cmp_func(st, by_value) == by_value && OPENSSL_sk_is_sorted(st) == 1,
          "OPENSSL_sk_set_cmp_func: the same function keeps the order");
    check(OPENSSL_sk_set_cmp_func(st, reversed) == by_value && OPENSSL_sk_is_sorted(st) == 0,
          "OPENSSL_sk_set_cmp_func: another function unsorts");
    OPENSSL_sk_sort(st);
    check(same(contents(st), "9 7 5 3 3 3 1"), "OPENSSL_sk_sort: with the new comparator");
    OPENSSL_sk_push(st, v(2));
    check(OPENSSL_sk_is_sorted(st) == 0, "adding an element unsorts");
    OPENSSL_sk_sort(st);
    OPENSSL_sk_set(st, 0, v(9));
    check(OPENSSL_sk_is_sorted(st) == 0, "OPENSSL_sk_set unsorts");
    OPENSSL_sk_free(st);

    st = OPENSSL_sk_new_null();
    OPENSSL_sk_push(st, v(4));
    OPENSSL_sk_push(st, v(4));
    check(OPENSSL_sk_find(st, v(4)) == 0 && OPENSSL_sk_find(st, &key) == -1
          && OPENSSL_sk_find_all(st, v(4), &count) == 0 && count == 1,
          "without a comparator, find compares pointers");
    OPENSSL_sk_sort(st);
    check(OPENSSL_sk_is_sorted(st) == 0, "OPENSSL_sk_sort: nothing to sort by");
    OPENSSL_sk_free(st);
    st = OPENSSL_sk_new(by_value);
    OPENSSL_sk_sort(st);
    check(OPENSSL_sk_is_sorted(st) == 1, "OPENSSL_sk_sort: an empty stack is sorted");
    OPENSSL_sk_free(st);
}

/* Sorting many equal keys: the stack ends up in the order qsort gives. */
static void sorting(void)
{
    OPENSSL_STACK *st = OPENSSL_sk_new(by_value);
    const void *expected[32];
    int ok = 1;

    for (int i = 0; i < 32; i++) {
        values[i] = (i * 7) % 5;
        expected[i] = v(i);
        OPENSSL_sk_push(st, v(i));
    }
    qsort(expected, 32, sizeof(expected[0]), by_value);
    OPENSSL_sk_sort(st);
    for (int i = 0; i < 32; i++)
        ok = ok && OPENSSL_sk_value(st, i) == expected[i];
    check(ok, "OPENSSL_sk_sort: the C library's qsort");
    OPENSSL_sk_free(st);
}

static int copies, frees, fail_at = -1;
static char freed[64];

static void *copy_value(const void *p)
{
    int *c;

    if (copies++ == fail_at)
        return NULL;
    c = malloc(sizeof(*c));
    if (c != NULL)
        *c = *(const int *)p + 100;
    return c;
}

static void free_value(void *p)
{
    size_t n = strlen(freed);

    frees++;
    if (n + 2 < sizeof(freed))
        snprintf(freed + n, sizeof(freed) - n, "%d,", *(int *)p);
    free(p);
}

static void copying(void)
{
    OPENSSL_STACK *st = OPENSSL_sk_new(by_value), *copy;

    for (int i = 0; i < 4; i++)
        values[i] = i;
    OPENSSL_sk_push(st, v(2));
    OPENSSL_sk_push(st, NULL);
    OPENSSL_sk_push(st, v(1));
    OPENSSL_sk_sort(st);
    copy = OPENSSL_sk_dup(st);
    check(copy != NULL && copy != st && same(contents(copy), contents(st))
          && OPENSSL_sk_is_sorted(copy) == 1 && OPENSSL_sk_value(copy, 1) == OPENSSL_sk_value(st, 1),
          "OPENSSL_sk_dup: the same pointers, comparator, and order");
    OPENSSL_sk_free(copy);
    copy = OPENSSL_sk_dup(NULL);
    check(copy != NULL && OPENSSL_sk_num(copy) == 0, "OPENSSL_sk_dup(NULL): an empty stack");
    OPENSSL_sk_free(copy);

    copies = 0;
    copy = OPENSSL_sk_deep_copy(st, copy_value, free_value);
    check(copy != NULL && copies == 2 && same(contents(copy), "-1 101 102")
          && OPENSSL_sk_is_sorted(copy) == 1,
          "OPENSSL_sk_deep_copy: copies each element, keeping nulls");
    frees = 0;
    freed[0] = '\0';
    OPENSSL_sk_pop_free(copy, free_value);
    check(frees == 2 && same(freed, "101,102,"), "OPENSSL_sk_pop_free: frees each element in order");

    OPENSSL_sk_push(st, v(3));
    copies = 0;
    fail_at = 2;
    frees = 0;
    freed[0] = '\0';
    check(OPENSSL_sk_deep_copy(st, copy_value, free_value) == NULL && frees == 2
          && same(freed, "102,101,"),
          "OPENSSL_sk_deep_copy: a failed copy frees the copies made, newest first");
    fail_at = -1;
    copy = OPENSSL_sk_deep_copy(NULL, copy_value, free_value);
    check(copy != NULL && OPENSSL_sk_num(copy) == 0, "OPENSSL_sk_deep_copy(NULL): an empty stack");
    OPENSSL_sk_free(copy);
    OPENSSL_sk_pop_free(NULL, free_value);
    OPENSSL_sk_free(st);
}

/* The typed wrappers from safestack.h, on strings. */
static int by_string(const char *const *a, const char *const *b)
{
    return strcmp(*a, *b);
}

static void typed(void)
{
    STACK_OF(OPENSSL_CSTRING) *names = sk_OPENSSL_CSTRING_new(by_string);

    sk_OPENSSL_CSTRING_push(names, "pear");
    sk_OPENSSL_CSTRING_push(names, "apple");
    sk_OPENSSL_CSTRING_push(names, "fig");
    sk_OPENSSL_CSTRING_sort(names);
    check(sk_OPENSSL_CSTRING_num(names) == 3 && same(sk_OPENSSL_CSTRING_value(names, 0), "apple")
          && sk_OPENSSL_CSTRING_find(names, "fig") == 1
          && sk_OPENSSL_CSTRING_find(names, "kiwi") == -1,
          "STACK_OF(OPENSSL_CSTRING): sorting and finding by content");
    sk_OPENSSL_CSTRING_free(names);
}

int main(void)
{
    for (int i = 0; i < 32; i++)
        values[i] = i;
    basics();
    reserving();
    finding();
    sorting();
    copying();
    typed();
    printf("1..%d\n", number);
    return failures != 0;
}
