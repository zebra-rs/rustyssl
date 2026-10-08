/*
 * Conformance test for directory listing (OPENSSL_DIR_read, from OpenSSL's internal o_dir.h,
 * which libcrypto exports), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). Entries come in
 * the order readdir returns them, so the test checks the set of names.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

/* Exported, but declared only in OpenSSL's internal headers. */
typedef struct OPENSSL_dir_context_st OPENSSL_DIR_CTX;
const char *OPENSSL_DIR_read(OPENSSL_DIR_CTX **ctx, const char *directory);
int OPENSSL_DIR_end(OPENSSL_DIR_CTX **ctx);

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static const char *const names[] = { "alpha", "beta.pem", "gamma", ".hidden" };

int main(void)
{
    char dir[64];
    char path[256];
    OPENSSL_DIR_CTX *ctx = NULL;
    const char *entry;
    int seen[4] = { 0 }, others = 0, count = 0, ok = 1;

    snprintf(dir, sizeof(dir), "/tmp/rustssl-dir-%ld", (long)getpid());
    if (mkdir(dir, 0700) != 0) {
        printf("Bail out! mkdir\n");
        return 1;
    }
    for (int i = 0; i < 4; i++) {
        int fd;

        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        fd = open(path, O_CREAT | O_WRONLY, 0600);
        if (fd >= 0)
            close(fd);
    }

    errno = 5;
    while ((entry = OPENSSL_DIR_read(&ctx, dir)) != NULL) {
        int known = 0;

        count++;
        for (int i = 0; i < 4; i++)
            if (strcmp(entry, names[i]) == 0) {
                seen[i]++;
                known = 1;
            }
        if (!known && strcmp(entry, ".") != 0 && strcmp(entry, "..") != 0)
            others++;
    }
    for (int i = 0; i < 4; i++)
        ok = ok && seen[i] == 1;
    check(ok && others == 0 && count == 6, "OPENSSL_DIR_read: every entry once, with . and ..");
    check(errno == 0 && ctx != NULL, "OPENSSL_DIR_read: the end, with errno 0");
    check(OPENSSL_DIR_read(&ctx, dir) == NULL, "OPENSSL_DIR_read: still at the end");
    check(OPENSSL_DIR_end(&ctx) == 1, "OPENSSL_DIR_end");

    ctx = NULL;
    snprintf(path, sizeof(path), "%s/missing", dir);
    check(OPENSSL_DIR_read(&ctx, path) == NULL && errno == ENOENT && ctx == NULL,
          "OPENSSL_DIR_read: a missing directory");
    errno = 0;
    check(OPENSSL_DIR_read(NULL, dir) == NULL && errno == EINVAL, "OPENSSL_DIR_read: null context");
    errno = 0;
    check(OPENSSL_DIR_read(&ctx, NULL) == NULL && errno == EINVAL,
          "OPENSSL_DIR_read: null directory");
    errno = 0;
    check(OPENSSL_DIR_end(&ctx) == 0 && errno == EINVAL, "OPENSSL_DIR_end: nothing to end");
    errno = 0;
    check(OPENSSL_DIR_end(NULL) == 0 && errno == EINVAL, "OPENSSL_DIR_end: null");

    for (int i = 0; i < 4; i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        unlink(path);
    }
    rmdir(dir);
    printf("1..%d\n", number);
    return failures != 0;
}
