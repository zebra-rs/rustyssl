/*
 * Conformance test for the FILE and file descriptor BIOs (BIO_s_file(3), BIO_s_fd(3),
 * BIO_new_file, BIO_new_fp, BIO_new_fd, BIO_fd_should_retry), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
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

static int same(const char *a, const char *b)
{
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

static char path[64];

static void files(void)
{
    BIO *b = BIO_new_file(path, "w");
    char buf[32];
    FILE *fp = NULL;

    check(b != NULL && BIO_method_type(b) == BIO_TYPE_FILE && same(BIO_method_name(b), "FILE pointer"),
          "BIO_new_file for writing");
    check(BIO_write(b, "first line\n", 11) == 11 && BIO_puts(b, "second\n") == 7
          && BIO_tell(b) == 18 && BIO_flush(b) == 1, "BIO_write, BIO_puts, BIO_tell, BIO_flush");
    check(BIO_get_fp(b, &fp) == 1 && fp != NULL && BIO_get_close(b) == 1,
          "BIO_get_fp; BIO_new_file closes the file");
    BIO_free(b);

    b = BIO_new_file(path, "r");
    check(BIO_gets(b, buf, sizeof(buf)) == 11 && same(buf, "first line\n")
          && BIO_read(b, buf, 3) == 3 && memcmp(buf, "sec", 3) == 0 && BIO_tell(b) == 14,
          "reading it back");
    check(BIO_read(b, buf, 32) == 4 && BIO_read(b, buf, 32) == 0 && BIO_eof(b) == 1
          && !BIO_should_retry(b), "at the end: 0 and EOF, without retrying");
    check(BIO_seek(b, 6) == 0 && BIO_read(b, buf, 4) == 4 && memcmp(buf, "line", 4) == 0
          && BIO_reset(b) == 0 && BIO_tell(b) == 0, "BIO_seek and BIO_reset");
    check(BIO_write(b, "x", 1) == 0, "writing a file opened for reading");
    check(BIO_pending(b) == 0 && BIO_wpending(b) == 0 && BIO_ctrl(b, 9999, 0, NULL) == 0,
          "other controls");
    BIO_free(b);

    fp = fopen(path, "a");
    b = BIO_new_fp(fp, BIO_NOCLOSE);
    check(b != NULL && BIO_get_close(b) == 0 && BIO_puts(b, "appended\n") == 9,
          "BIO_new_fp with BIO_NOCLOSE");
    BIO_free(b);
    check(fputs("by hand\n", fp) >= 0 && fclose(fp) == 0, "the FILE stays open");

    b = BIO_new(BIO_s_file());
    check(b != NULL && BIO_get_init(b) == 0, "BIO_new(BIO_s_file()) isn't initialized");
    check(BIO_read_filename(b, path) == 1 && BIO_gets(b, buf, sizeof(buf)) == 11,
          "BIO_read_filename");
    check(BIO_write_filename(b, path) == 1 && BIO_puts(b, "replaced\n") == 9, "BIO_write_filename");
    check(BIO_append_filename(b, path) == 1 && BIO_puts(b, "more\n") == 5, "BIO_append_filename");
    check(BIO_rw_filename(b, path) == 1 && BIO_gets(b, buf, sizeof(buf)) == 9
          && same(buf, "replaced\n"), "BIO_rw_filename");
    ERR_clear_error();
    check(BIO_ctrl(b, BIO_C_SET_FILENAME, BIO_CLOSE, path) == 0
          && ERR_GET_REASON(ERR_get_error()) == BIO_R_BAD_FOPEN_MODE, "a filename without a mode");
    BIO_free(b);
}

static void missing(void)
{
    const char *file = NULL, *data = NULL;
    int flags = 0;
    unsigned long e;

    ERR_clear_error();
    check(BIO_new_file("/nonexistent/rustssl", "r") == NULL, "BIO_new_file: a missing file");
    e = ERR_get_error_all(&file, NULL, NULL, &data, &flags);
    check(e == (ERR_SYSTEM_FLAG | ENOENT) && same(data, "calling fopen(/nonexistent/rustssl, r)")
          && flags == (ERR_TXT_MALLOCED | ERR_TXT_STRING),
          "the system error, with the call in its data");
    check(ERR_get_error() == ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NO_SUCH_FILE) && ERR_get_error() == 0,
          "then BIO_R_NO_SUCH_FILE");
    check(BIO_new_file("/", "w") == NULL && ERR_GET_LIB(ERR_get_error()) == ERR_LIB_SYS
          && ERR_get_error() == ERR_PACK(ERR_LIB_BIO, 0, ERR_R_SYS_LIB),
          "other failures: ERR_R_SYS_LIB");
    ERR_clear_error();
}

static void descriptors(void)
{
    int fds[2];
    BIO *r, *w;
    char buf[16];
    int fd = -2;

    if (pipe(fds) != 0) {
        check(0, "pipe");
        return;
    }
    r = BIO_new_fd(fds[0], BIO_CLOSE);
    w = BIO_new_fd(fds[1], BIO_NOCLOSE);
    check(r != NULL && BIO_method_type(r) == BIO_TYPE_FD && same(BIO_method_name(r), "file descriptor")
          && BIO_get_fd(r, &fd) == fds[0] && fd == fds[0], "BIO_new_fd and BIO_get_fd");
    check(BIO_write(w, "pipe data", 9) == 9 && BIO_puts(w, "\nmore") == 5, "writing a pipe");
    check(BIO_gets(r, buf, sizeof(buf)) == 10 && same(buf, "pipe data\n"), "BIO_gets reads a line");
    BIO_free(w);
    close(fds[1]);
    check(BIO_read(r, buf, sizeof(buf)) == 4 && BIO_eof(r) == 0, "BIO_read");
    check(BIO_read(r, buf, sizeof(buf)) == 0 && BIO_eof(r) == 1 && !BIO_should_retry(r),
          "the writer closed: 0, EOF");
    check(BIO_pending(r) == 0 && BIO_flush(r) == 1 && BIO_get_close(r) == 1, "fd controls");
    BIO_free(r);
    check(fcntl(fds[0], F_GETFD) == -1, "BIO_CLOSE closed the descriptor");

    r = BIO_new(BIO_s_fd());
    check(r != NULL && BIO_get_fd(r, NULL) == -1, "BIO_get_fd before one is set");
    BIO_free(r);

    check(BIO_fd_non_fatal_error(EAGAIN) == 1 && BIO_fd_non_fatal_error(EINTR) == 1
          && BIO_fd_non_fatal_error(EINPROGRESS) == 1 && BIO_fd_non_fatal_error(EBADF) == 0
          && BIO_fd_non_fatal_error(0) == 0, "BIO_fd_non_fatal_error");
    errno = EAGAIN;
    check(BIO_fd_should_retry(-1) == 1 && BIO_fd_should_retry(0) == 1 && BIO_fd_should_retry(5) == 0,
          "BIO_fd_should_retry");
    errno = EBADF;
    check(BIO_fd_should_retry(-1) == 0, "BIO_fd_should_retry: a fatal error");
}

int main(void)
{
    snprintf(path, sizeof(path), "/tmp/rustssl-bio-%ld.txt", (long)getpid());
    files();
    missing();
    descriptors();
    unlink(path);
    printf("1..%d\n", number);
    return failures != 0;
}
