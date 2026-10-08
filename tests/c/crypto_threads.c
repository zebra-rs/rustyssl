/*
 * Conformance test for locks, run-once, thread-local storage, thread IDs, the atomics, and the
 * thread-pool setting (CRYPTO_THREAD_run_once(3), CRYPTO_atomic_add(3),
 * OSSL_set_max_threads(3)), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). The concurrent
 * checks run 8 threads at once, so a lock or an atomic that doesn't work loses updates.
 */
#define _POSIX_C_SOURCE 200809L
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/thread.h>

#define THREADS 8
#define ROUNDS 20000

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int run_all(void *(*body)(void *))
{
    pthread_t threads[THREADS];
    int ok = 1;

    for (int i = 0; i < THREADS; i++)
        ok = ok && pthread_create(&threads[i], NULL, body, NULL) == 0;
    for (int i = 0; i < THREADS; i++)
        pthread_join(threads[i], NULL);
    return ok;
}

/* Locks. */

static CRYPTO_RWLOCK *lock;
static long locked_counter;

static void *count_under_lock(void *unused)
{
    (void)unused;
    for (int i = 0; i < ROUNDS; i++) {
        if (!CRYPTO_THREAD_write_lock(lock))
            return NULL;
        locked_counter++;
        CRYPTO_THREAD_unlock(lock);
    }
    return NULL;
}

static void locks(void)
{
    lock = CRYPTO_THREAD_lock_new();
    check(lock != NULL, "CRYPTO_THREAD_lock_new");
    check(CRYPTO_THREAD_read_lock(lock) == 1 && CRYPTO_THREAD_read_lock(lock) == 1
          && CRYPTO_THREAD_unlock(lock) == 1 && CRYPTO_THREAD_unlock(lock) == 1,
          "CRYPTO_THREAD_read_lock: readers share the lock");
    check(CRYPTO_THREAD_write_lock(lock) == 1 && CRYPTO_THREAD_unlock(lock) == 1,
          "CRYPTO_THREAD_write_lock and CRYPTO_THREAD_unlock");
    check(run_all(count_under_lock) && locked_counter == (long)THREADS * ROUNDS,
          "CRYPTO_THREAD_write_lock: excludes the other threads");
    CRYPTO_THREAD_lock_free(lock);
    CRYPTO_THREAD_lock_free(NULL);
    check(1, "CRYPTO_THREAD_lock_free, including null");
}

/* Run-once. */

static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
static int initialized;
static int once_results;

static void init_once(void)
{
    initialized++;
}

static void *run_once(void *unused)
{
    (void)unused;
    if (CRYPTO_THREAD_run_once(&once, init_once))
        __atomic_add_fetch(&once_results, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static void running_once(void)
{
    check(run_all(run_once) && initialized == 1 && once_results == THREADS,
          "CRYPTO_THREAD_run_once: one initialization for all threads, 1 for each");
    check(CRYPTO_THREAD_run_once(&once, init_once) == 1 && initialized == 1,
          "CRYPTO_THREAD_run_once: later calls return 1 without running it");
}

/* Thread-local storage and thread IDs. */

static CRYPTO_THREAD_LOCAL key;
static int cleaned;
static void *seen_before;
static int same_id_inside;
static CRYPTO_THREAD_ID main_id, thread_id;
static int thread_value;

static void cleanup(void *value)
{
    if (value == &thread_value)
        cleaned++;
}

static void *use_local(void *unused)
{
    (void)unused;
    seen_before = CRYPTO_THREAD_get_local(&key);
    CRYPTO_THREAD_set_local(&key, &thread_value);
    thread_id = CRYPTO_THREAD_get_current_id();
    same_id_inside = CRYPTO_THREAD_compare_id(thread_id, CRYPTO_THREAD_get_current_id()) != 0;
    OPENSSL_thread_stop();
    return NULL;
}

static void locals(void)
{
    pthread_t thread;
    int main_value;

    check(CRYPTO_THREAD_init_local(&key, cleanup) == 1, "CRYPTO_THREAD_init_local");
    check(CRYPTO_THREAD_get_local(&key) == NULL, "CRYPTO_THREAD_get_local: null at first");
    check(CRYPTO_THREAD_set_local(&key, &main_value) == 1
          && CRYPTO_THREAD_get_local(&key) == &main_value,
          "CRYPTO_THREAD_set_local and _get_local");
    main_id = CRYPTO_THREAD_get_current_id();
    check(pthread_create(&thread, NULL, use_local, NULL) == 0 && pthread_join(thread, NULL) == 0,
          "a second thread");
    check(seen_before == NULL && CRYPTO_THREAD_get_local(&key) == &main_value,
          "CRYPTO_THREAD_get_local: each thread has its own value");
    check(cleaned == 1, "CRYPTO_THREAD_init_local: the cleanup runs on the thread's value at exit");
    check(same_id_inside && CRYPTO_THREAD_compare_id(main_id, CRYPTO_THREAD_get_current_id())
          && !CRYPTO_THREAD_compare_id(main_id, thread_id),
          "CRYPTO_THREAD_get_current_id and CRYPTO_THREAD_compare_id");
    CRYPTO_THREAD_set_local(&key, NULL);
    check(CRYPTO_THREAD_cleanup_local(&key) == 1, "CRYPTO_THREAD_cleanup_local");
}

/* Atomics. */

static int shared_int;
static uint64_t shared_u64;

static void *count_atomically(void *unused)
{
    int ret;
    uint64_t ret64;

    (void)unused;
    for (int i = 0; i < ROUNDS; i++) {
        CRYPTO_atomic_add(&shared_int, 1, &ret, NULL);
        CRYPTO_atomic_add64(&shared_u64, 2, &ret64, NULL);
    }
    return NULL;
}

static void atomics(void)
{
    int i = INT_MAX, ret = 0;
    uint64_t v = 0xf0, ret64 = 0;
    CRYPTO_RWLOCK *l = CRYPTO_THREAD_lock_new();

    check(CRYPTO_atomic_add(&i, 1, &ret, NULL) == 1 && i == INT_MIN && ret == INT_MIN,
          "CRYPTO_atomic_add: wraps, without a lock");
    check(CRYPTO_atomic_add(&i, -1, &ret, l) == 1 && i == INT_MAX && ret == INT_MAX,
          "CRYPTO_atomic_add: with a lock, a negative amount");
    check(CRYPTO_atomic_add64(&v, UINT64_MAX, &ret64, NULL) == 1 && v == 0xef && ret64 == 0xef,
          "CRYPTO_atomic_add64: wraps");
    check(CRYPTO_atomic_or(&v, 0x100, &ret64, NULL) == 1 && v == 0x1ef && ret64 == 0x1ef,
          "CRYPTO_atomic_or: returns the new value");
    check(CRYPTO_atomic_and(&v, 0x10f, &ret64, l) == 1 && v == 0x10f && ret64 == 0x10f,
          "CRYPTO_atomic_and: returns the new value");
    check(CRYPTO_atomic_store(&v, 77, NULL) == 1 && CRYPTO_atomic_load(&v, &ret64, NULL) == 1
          && ret64 == 77, "CRYPTO_atomic_store and CRYPTO_atomic_load");
    check(CRYPTO_atomic_load_int(&i, &ret, NULL) == 1 && ret == INT_MAX,
          "CRYPTO_atomic_load_int");
    check(run_all(count_atomically) && shared_int == THREADS * ROUNDS
          && shared_u64 == 2ull * THREADS * ROUNDS,
          "CRYPTO_atomic_add and _add64: no update is lost between threads");
    CRYPTO_THREAD_lock_free(l);
}

/* The thread pool setting, and thread state. */

static void *stop_twice(void *unused)
{
    (void)unused;
    OPENSSL_thread_stop();
    OPENSSL_thread_stop_ex(NULL);
    OPENSSL_thread_stop();
    return NULL;
}

static void pool(void)
{
    check(OSSL_get_thread_support_flags()
          == (OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL | OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN),
          "OSSL_get_thread_support_flags: a thread pool that spawns by default");
    check(OSSL_get_max_threads(NULL) == 0, "OSSL_get_max_threads: 0 at first");
    check(OSSL_set_max_threads(NULL, 4) == 1 && OSSL_get_max_threads(NULL) == 4,
          "OSSL_set_max_threads: the default context");
    check(run_all(stop_twice), "OPENSSL_thread_stop and _ex: on any thread, any number of times");
}

int main(void)
{
    locks();
    running_once();
    locals();
    atomics();
    pool();
    printf("1..%d\n", number);
    return failures != 0;
}
