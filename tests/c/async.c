/*
 * Conformance test for ASYNC (ASYNC_start_job(3), ASYNC_WAIT_CTX_new(3)): jobs run to
 * completion with a copy of their arguments, their result and wait context; the current job,
 * blocked pauses (which return at once on every platform), the default library context a job
 * sets being put back, the thread's job pool and its sizes; and the wait context's descriptors,
 * changes, callback, status, and cleanups.
 *
 * What differs between platforms is left out: whether jobs can really pause (ASYNC_is_capable,
 * the stack functions) is only called, not printed. rustyssl's jobs run synchronously
 * (docs/DEVIATIONS.md).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/async.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

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

struct args {
    int value;
    char text[16];
    ASYNC_WAIT_CTX *expected;
};

static int saw_job, saw_wctx, paused;
static OSSL_LIB_CTX *job_libctx;

static void cleanup(ASYNC_WAIT_CTX *ctx, const void *key, OSSL_ASYNC_FD fd, void *data)
{
    (void)ctx;
    printf("  cleanup of %s: fd %d, data %s\n", (const char *)key, (int)fd, (const char *)data);
}

static int job_fn(void *arg)
{
    struct args *a = arg;
    ASYNC_JOB *job = ASYNC_get_current_job();

    saw_job = job != NULL;
    saw_wctx = job != NULL && ASYNC_get_wait_ctx(job) == a->expected;
    a->value += 1;
    strcpy(a->text, "changed");
    ASYNC_block_pause();
    paused = ASYNC_pause_job();
    ASYNC_unblock_pause();
    if (a->expected != NULL)
        ASYNC_WAIT_CTX_set_wait_fd(a->expected, "job", 7, "from the job", cleanup);
    return a->value * 2;
}

static int no_args(void *arg)
{
    return arg == NULL ? 5 : 6;
}

static int switch_libctx(void *arg)
{
    (void)arg;
    (void)OSSL_LIB_CTX_set0_default(job_libctx);
    return 1;
}

static int callback(void *arg)
{
    printf("  callback %s\n", (const char *)arg);
    return 1;
}

int main(void)
{
    ASYNC_JOB *job = NULL;
    ASYNC_WAIT_CTX *w = ASYNC_WAIT_CTX_new();
    struct args a = { 20, "original", NULL };
    int ret = -1, r;
    OSSL_ASYNC_FD fds[4];
    size_t n, nadd, ndel;
    void *data;
    ASYNC_callback_fn cb = NULL;
    void *cbarg = NULL;
    ASYNC_stack_alloc_fn af;
    ASYNC_stack_free_fn ff;

    setvbuf(stdout, NULL, _IONBF, 0);
    (void)ASYNC_is_capable();
    ASYNC_get_mem_functions(&af, &ff);
    (void)ASYNC_set_mem_functions(af, ff);

    printf("# outside a job\n");
    check(ASYNC_get_current_job() == NULL, "no current job");
    check(ASYNC_pause_job() == 1, "a pause outside a job succeeds");
    ASYNC_block_pause();
    ASYNC_unblock_pause();

    printf("# the pool\n");
    check(ASYNC_init_thread(1, 2) == 0, "more jobs than the pool holds");
    errors();
    check(ASYNC_init_thread(2, 1) == 1, "a pool of two");

    printf("# jobs\n");
    a.expected = w;
    r = ASYNC_start_job(&job, w, &ret, job_fn, &a, sizeof(a));
    check(r == ASYNC_FINISH && job == NULL, "the job finished");
    printf("  ret %d, saw job %d, wait ctx %d, blocked pause %d\n", ret, saw_job, saw_wctx, paused);
    printf("  arguments after: %d %s\n", a.value, a.text);
    check(ASYNC_get_current_job() == NULL, "no current job after");
    r = ASYNC_start_job(&job, NULL, &ret, no_args, NULL, 0);
    check(r == ASYNC_FINISH && ret == 5, "no arguments");
    r = ASYNC_start_job(&job, NULL, &ret, no_args, &a, 0);
    check(r == ASYNC_FINISH && ret == 5, "arguments of size 0 are none");
    job_libctx = OSSL_LIB_CTX_new();
    r = ASYNC_start_job(&job, NULL, &ret, switch_libctx, NULL, 0);
    check(r == ASYNC_FINISH && ret == 1, "a job that sets a default library context");
    check(OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX_get0_global_default()) == OSSL_LIB_CTX_get0_global_default(),
          "the caller's default is put back");
    OSSL_LIB_CTX_free(job_libctx);
    ASYNC_cleanup_thread();
    r = ASYNC_start_job(&job, NULL, &ret, no_args, NULL, 0);
    check(r == ASYNC_FINISH && ret == 5, "a job after the thread's cleanup");
    ASYNC_cleanup_thread();

    printf("# the wait context\n");
    check(ASYNC_WAIT_CTX_get_all_fds(w, NULL, &n) == 1 && n == 1, "the job's descriptor");
    check(ASYNC_WAIT_CTX_set_wait_fd(w, "one", 3, "data one", cleanup) == 1, "ASYNC_WAIT_CTX_set_wait_fd");
    check(ASYNC_WAIT_CTX_set_wait_fd(w, "two", 4, "data two", NULL) == 1, "two, without a cleanup");
    check(ASYNC_WAIT_CTX_get_all_fds(w, fds, &n) == 1 && n == 3, "three descriptors");
    printf("  fds %d %d %d\n", fds[0], fds[1], fds[2]);
    check(ASYNC_WAIT_CTX_get_fd(w, "one", &fds[0], &data) == 1 && fds[0] == 3 && strcmp(data, "data one") == 0,
          "ASYNC_WAIT_CTX_get_fd");
    check(ASYNC_WAIT_CTX_get_fd(w, "none", &fds[0], &data) == 0, "no such key");
    check(ASYNC_WAIT_CTX_get_changed_fds(w, NULL, &nadd, NULL, &ndel) == 1, "ASYNC_WAIT_CTX_get_changed_fds");
    printf("  added %zu, deleted %zu\n", nadd, ndel);
    check(ASYNC_WAIT_CTX_get_changed_fds(w, fds, &nadd, NULL, &ndel) == 1, "the added descriptors");
    printf("  added %d %d %d\n", fds[0], fds[1], fds[2]);
    check(ASYNC_WAIT_CTX_clear_fd(w, "two") == 1, "clearing one just added");
    check(ASYNC_WAIT_CTX_clear_fd(w, "two") == 0, "it's gone");
    check(ASYNC_WAIT_CTX_get_changed_fds(w, NULL, &nadd, NULL, &ndel) == 1 && nadd == 2 && ndel == 0,
          "one fewer added");
    check(ASYNC_WAIT_CTX_get_callback(w, &cb, &cbarg) == 0, "no callback yet");
    check(ASYNC_WAIT_CTX_set_callback(w, callback, "arg") == 1, "ASYNC_WAIT_CTX_set_callback");
    check(ASYNC_WAIT_CTX_get_callback(w, &cb, &cbarg) == 1 && cb == callback, "ASYNC_WAIT_CTX_get_callback");
    (void)cb(cbarg);
    check(ASYNC_WAIT_CTX_set_callback(NULL, callback, NULL) == 0, "no context");
    check(ASYNC_WAIT_CTX_get_status(w) == ASYNC_STATUS_UNSUPPORTED, "the status at first");
    check(ASYNC_WAIT_CTX_set_status(w, ASYNC_STATUS_EAGAIN) == 1 && ASYNC_WAIT_CTX_get_status(w) == ASYNC_STATUS_EAGAIN,
          "ASYNC_WAIT_CTX_set_status");
    ASYNC_WAIT_CTX_free(w);
    ASYNC_WAIT_CTX_free(NULL);
    errors();

    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
