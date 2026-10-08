/*
 * Conformance test for the version and build information (OpenSSL_version(3), OPENSSL_info(3))
 * and the small process helpers in crypto.h, in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). The numbers must
 * match the headers exactly. The text may differ where the builds do (directories, compiler,
 * build metadata), so the checks pin down how the strings relate to each other instead.
 */
#define _POSIX_C_SOURCE 200809L
/* The fork handlers are deprecated, and the test calls them anyway. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int starts_with(const char *s, const char *prefix)
{
    return s != NULL && strncmp(s, prefix, strlen(prefix)) == 0;
}

/* `s` is `label: "<dir>"`. */
static int quotes(const char *s, const char *label, const char *dir)
{
    char expected[1024];

    snprintf(expected, sizeof(expected), "%s: \"%s\"", label, dir == NULL ? "" : dir);
    return dir != NULL && strcmp(s, expected) == 0;
}

static void numbers(void)
{
    check(OpenSSL_version_num() == OPENSSL_VERSION_NUMBER,
          "OpenSSL_version_num: the headers' OPENSSL_VERSION_NUMBER");
    check(OPENSSL_version_major() == OPENSSL_VERSION_MAJOR
          && OPENSSL_version_minor() == OPENSSL_VERSION_MINOR
          && OPENSSL_version_patch() == OPENSSL_VERSION_PATCH,
          "OPENSSL_version_major/minor/patch: the headers' numbers");
    check(strcmp(OPENSSL_version_pre_release(), OPENSSL_VERSION_PRE_RELEASE) == 0,
          "OPENSSL_version_pre_release: the headers' (a release has none)");
}

static void strings(void)
{
    char full[256], text[512];
    const char *meta = OPENSSL_version_build_metadata();

    check(meta[0] == '\0' || meta[0] == '+',
          "OPENSSL_version_build_metadata: empty or starting with +");
    check(strcmp(OpenSSL_version(OPENSSL_VERSION_STRING), OPENSSL_VERSION_STR) == 0,
          "OpenSSL_version(OPENSSL_VERSION_STRING): MAJOR.MINOR.PATCH");
    snprintf(full, sizeof(full), "%s%s%s", OPENSSL_VERSION_STR, OPENSSL_version_pre_release(),
             meta);
    check(strcmp(OpenSSL_version(OPENSSL_FULL_VERSION_STRING), full) == 0,
          "OpenSSL_version(OPENSSL_FULL_VERSION_STRING): version, pre-release, metadata");
    snprintf(text, sizeof(text), "OpenSSL %s %s", full, OPENSSL_RELEASE_DATE);
    check(strcmp(OpenSSL_version(OPENSSL_VERSION), text) == 0,
          "OpenSSL_version(OPENSSL_VERSION): \"OpenSSL\", full version, release date");
    check(starts_with(OpenSSL_version(OPENSSL_CFLAGS), "compiler: "),
          "OpenSSL_version(OPENSSL_CFLAGS)");
    check(starts_with(OpenSSL_version(OPENSSL_BUILT_ON), "built on: "),
          "OpenSSL_version(OPENSSL_BUILT_ON)");
    check(starts_with(OpenSSL_version(OPENSSL_PLATFORM), "platform: "),
          "OpenSSL_version(OPENSSL_PLATFORM)");
    check(strcmp(OpenSSL_version(OPENSSL_WINCTX), "OSSL_WINCTX: Undefined") == 0,
          "OpenSSL_version(OPENSSL_WINCTX): undefined outside Windows");
    check(strcmp(OpenSSL_version(-1), "not available") == 0
          && strcmp(OpenSSL_version(11), "not available") == 0
          && strcmp(OpenSSL_version(1000), "not available") == 0,
          "OpenSSL_version: \"not available\" for unknown types");
}

static void directories(void)
{
    const char *cpu = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS);
    char expected[512];

    check(quotes(OpenSSL_version(OPENSSL_DIR), "OPENSSLDIR", OPENSSL_info(OPENSSL_INFO_CONFIG_DIR)),
          "OPENSSL_DIR quotes OPENSSL_INFO_CONFIG_DIR");
    check(quotes(OpenSSL_version(OPENSSL_ENGINES_DIR), "ENGINESDIR",
                 OPENSSL_info(OPENSSL_INFO_ENGINES_DIR)),
          "OPENSSL_ENGINES_DIR quotes OPENSSL_INFO_ENGINES_DIR");
    check(quotes(OpenSSL_version(OPENSSL_MODULES_DIR), "MODULESDIR",
                 OPENSSL_info(OPENSSL_INFO_MODULES_DIR)),
          "OPENSSL_MODULES_DIR quotes OPENSSL_INFO_MODULES_DIR");
    if (cpu == NULL)
        snprintf(expected, sizeof(expected), "CPUINFO: N/A");
    else
        snprintf(expected, sizeof(expected), "CPUINFO: %s", cpu);
    check(strcmp(OpenSSL_version(OPENSSL_CPU_INFO), expected) == 0,
          "OPENSSL_CPU_INFO agrees with OPENSSL_INFO_CPU_SETTINGS");
    printf("# OPENSSL_INFO_DSO_EXTENSION: %s\n", OPENSSL_info(OPENSSL_INFO_DSO_EXTENSION));
    check(strcmp(OPENSSL_info(OPENSSL_INFO_DIR_FILENAME_SEPARATOR), "/") == 0
          && strcmp(OPENSSL_info(OPENSSL_INFO_LIST_SEPARATOR), ":") == 0,
          "OPENSSL_info: the POSIX separators");
    check(strcmp(OPENSSL_info(OPENSSL_INFO_SEED_SOURCE), "os-specific") == 0,
          "OPENSSL_info(OPENSSL_INFO_SEED_SOURCE): the operating system");
    check(strcmp(OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT), "Undefined") == 0,
          "OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT): undefined outside Windows");
    check(OPENSSL_info(0) == NULL && OPENSSL_info(1000) == NULL && OPENSSL_info(1010) == NULL,
          "OPENSSL_info: null for unknown types");
}

static void process(void)
{
    OPENSSL_init();
    OPENSSL_fork_prepare();
    OPENSSL_fork_parent();
    OPENSSL_fork_child();
    check(1, "OPENSSL_init and the fork handlers do nothing");
    check(OPENSSL_isservice() == 0, "OPENSSL_isservice: 0 outside Windows");
    check(OPENSSL_issetugid() == 0, "OPENSSL_issetugid: 0 for an ordinary process");
}

static void dying(void)
{
    int fds[2], status = 0;
    char output[256] = { 0 };
    size_t used = 0;
    ssize_t n;
    pid_t pid;

    if (pipe(fds) != 0) {
        check(0, "OPENSSL_die: pipe");
        return;
    }
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        dup2(fds[1], 2);
        close(fds[0]);
        OPENSSL_die("something broke", "dying.c", 42);
        _exit(0);
    }
    close(fds[1]);
    while (used < sizeof(output) - 1
           && (n = read(fds[0], output + used, sizeof(output) - 1 - used)) > 0)
        used += (size_t)n;
    close(fds[0]);
    waitpid(pid, &status, 0);
    check(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT, "OPENSSL_die: aborts");
    check(strcmp(output, "dying.c:42: OpenSSL internal error: something broke\n") == 0,
          "OPENSSL_die: prints file, line, and message to stderr");
}

int main(void)
{
    numbers();
    strings();
    directories();
    process();
    dying();
    printf("1..%d\n", number);
    return failures != 0;
}
