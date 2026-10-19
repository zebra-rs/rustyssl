/* What tests/c/provider_ext.c and the test provider (test_prov.c) share. */

#ifndef TEST_PROV_H
#define TEST_PROV_H

#include <stddef.h>

/*
 * The provider's own function, beyond OpenSSL's ids: it makes one kind of upcall (`which`) and
 * writes a report into `out` (`len` octets). `arg` is a path for TEST_PROV_RUN_BIO.
 */
#define TEST_PROV_RUN 9001
typedef int test_prov_run_fn(void *provctx, int which, char *out, size_t len, const char *arg);

#define TEST_PROV_RUN_CORE 1
#define TEST_PROV_RUN_ERRORS 2
#define TEST_PROV_RUN_MARKS 3
#define TEST_PROV_RUN_BIO 4
#define TEST_PROV_RUN_MEMORY 5
#define TEST_PROV_RUN_SEEDS 6
#define TEST_PROV_RUN_OBJECTS 7
#define TEST_PROV_RUN_PROVIDER 8
#define TEST_PROV_RUN_CALLBACKS 9
#define TEST_PROV_RUN_THREADS 10
#define TEST_PROV_RUN_CHILDREN 11
#define TEST_PROV_RUN_CHILD_CTX 12

/* The provider's reasons (no library: the core gives the provider one). */
#define TEST_PROV_R_ONE 1
#define TEST_PROV_R_TWO 2

/* A parameter of the provider: how often its thread-stop handler ran. */
#define TEST_PROV_PARAM_THREAD_STOPS "thread-stops"

#endif
