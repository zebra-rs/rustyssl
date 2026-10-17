/*
 * Conformance test for UI_OpenSSL(3)'s console, the default UI method: prompts with and
 * without echo, verification (matching and not), booleans, information and error strings,
 * results too short or too long, over-long lines, end of input, and EVP_read_pw_string, each
 * in a child process on a pseudo-terminal (its controlling terminal, so /dev/tty, with the
 * echo turned off while reading) and with no terminal (standard input and standard error).
 * The parent types the input and records what the terminal shows.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ui.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* In the child: the scenario's prompts, each result written to `out`. */
static void scenario(int which, FILE *out)
{
    UI *ui = UI_new();
    char a[64] = "", b[64] = "", c[4] = "";
    int r = -9;
    unsigned long e;

    switch (which) {
    case 0:
        UI_add_input_string(ui, "Password: ", 0, a, 4, 20);
        UI_add_verify_string(ui, "Password: ", 0, b, 4, 20, a);
        break;
    case 1:
        UI_add_input_string(ui, "Echoed: ", UI_INPUT_FLAG_ECHO, a, 0, 20);
        UI_add_info_string(ui, "Some information\n");
        UI_add_error_string(ui, "An error\n");
        break;
    case 2:
        UI_add_input_boolean(ui, "Continue? ", "(y/n) ", "yY", "nN", 0, c);
        break;
    case 3:
        UI_add_input_string(ui, "Short: ", 0, a, 4, 8);
        break;
    case 4:
        UI_add_input_string(ui, "Pass: ", 0, a, 1, 20);
        UI_add_verify_string(ui, "Pass: ", 0, b, 1, 20, a);
        break;
    case 5:
        UI_add_input_string(ui, "Long: ", UI_INPUT_FLAG_ECHO, a, 0, 63);
        UI_add_input_string(ui, "Next: ", UI_INPUT_FLAG_ECHO, b, 0, 63);
        break;
    case 6:
        UI_add_input_string(ui, "Until EOF: ", 0, a, 0, 20);
        break;
    case 7:
        UI_free(ui);
        ui = NULL;
        r = EVP_read_pw_string(a, sizeof(a), "PEM pass phrase: ", 1);
        break;
    }
    if (ui != NULL)
        r = UI_process(ui);
    fprintf(out, "result %d, a [%s], b [%s], c [%s]\n", r, a, b, c);
    while ((e = ERR_get_error()) != 0)
        fprintf(out, "error %d/%d\n", ERR_GET_LIB(e), ERR_GET_REASON(e));
    UI_free(ui);
}

/* What the terminal showed, with \r shown. */
static void show(const char *label, const char *s, size_t n)
{
    size_t i;

    printf("  %s: [", label);
    for (i = 0; i < n; i++) {
        if (s[i] == '\r')
            printf("\\r");
        else if (s[i] == '\n')
            printf("\\n");
        else
            putchar(s[i]);
    }
    printf("]\n");
}

static void pause_ms(long ms)
{
    struct timespec t;

    t.tv_sec = ms / 1000;
    t.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&t, NULL);
}

/* Reads what's there within about `ms` milliseconds. */
static size_t drain(int fd, char *buf, size_t cap, size_t have, long ms)
{
    long waited;

    for (waited = 0; waited < ms; waited += 10) {
        ssize_t n = read(fd, buf + have, cap - have - 1);

        if (n > 0) {
            have += (size_t)n;
            waited = 0;
            continue;
        }
        pause_ms(10);
    }
    buf[have] = '\0';
    return have;
}

static void run_pty(const char *label, int which, const char *const *lines)
{
    int master = posix_openpt(O_RDWR | O_NOCTTY), res[2];
    char screen[16384], out[4096];
    size_t have = 0;
    pid_t pid;
    int status;

    grantpt(master);
    unlockpt(master);
    if (pipe(res) != 0)
        return;
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        int slave;
        FILE *o;

        close(res[0]);
        setsid();
        slave = open(ptsname(master), O_RDWR);
        ioctl(slave, TIOCSCTTY, 0);
        close(master);
        o = fdopen(res[1], "w");
        scenario(which, o);
        fclose(o);
        _exit(0);
    }
    close(res[1]);
    fcntl(master, F_SETFL, O_NONBLOCK);
    for (; *lines != NULL; lines++) {
        struct termios t;
        int i;

        have = drain(master, screen, sizeof(screen), have, 300);
        /* Wait for the echo to go off if the prompt hides the input. */
        for (i = 0; i < 100 && **lines == '-'; i++) {
            if (tcgetattr(master, &t) == 0 && (t.c_lflag & ECHO) == 0)
                break;
            pause_ms(10);
        }
        write(master, *lines + 1, strlen(*lines + 1));
    }
    have = drain(master, screen, sizeof(screen), have, 300);
    waitpid(pid, &status, 0);
    have = drain(master, screen, sizeof(screen), have, 50);
    {
        ssize_t n = read(res[0], out, sizeof(out) - 1);

        out[n > 0 ? n : 0] = '\0';
    }
    close(res[0]);
    close(master);
    printf("# on a terminal: %s\n", label);
    show("terminal", screen, have);
    printf("%s", out);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, label);
}

static void run_pipe(const char *label, int which, const char *input)
{
    int in[2], err[2], res[2];
    char errs[16384], out[4096];
    pid_t pid;
    int status;
    size_t have = 0;
    ssize_t n;

    if (pipe(in) != 0 || pipe(err) != 0 || pipe(res) != 0)
        return;
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        FILE *o;

        setsid();
        dup2(in[0], 0);
        dup2(err[1], 2);
        close(in[1]);
        close(err[0]);
        close(res[0]);
        o = fdopen(res[1], "w");
        scenario(which, o);
        fclose(o);
        _exit(0);
    }
    close(in[0]);
    close(err[1]);
    close(res[1]);
    write(in[1], input, strlen(input));
    close(in[1]);
    while ((n = read(err[0], errs + have, sizeof(errs) - have - 1)) > 0)
        have += (size_t)n;
    errs[have] = '\0';
    waitpid(pid, &status, 0);
    n = read(res[0], out, sizeof(out) - 1);
    out[n > 0 ? n : 0] = '\0';
    close(err[0]);
    close(res[0]);
    printf("# without a terminal: %s\n", label);
    show("stderr", errs, have);
    printf("%s", out);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, label);
}

int main(void)
{
    static const char *const verify[] = { "-secret\n", "-secret\n", NULL };
    static const char *const mismatch[] = { "-one\n", "-two\n", NULL };
    static const char *const echoed[] = { "+hello there\n", NULL };
    static const char *const yes[] = { "+y\n", NULL };
    static const char *const other[] = { "+maybe\n", "+n\n", NULL };
    static const char *const shorts[] = { "-ab\n", NULL };
    static const char *const pem[] = { "-pass phrase\n", "-pass phrase\n", NULL };
    static char longline[1100 + 16];
    static const char *const longer[] = { "+first\n", "+after\n", NULL };

    longline[0] = '+';
    memset(longline + 1, 'x', 1100);
    strcpy(longline + 1101, "\n");

    run_pty("verified", 0, verify);
    run_pty("not verified", 4, mismatch);
    run_pty("echoed, with information", 1, echoed);
    run_pty("a boolean", 2, yes);
    run_pty("a boolean, asked again", 2, other);
    run_pty("too short", 3, shorts);
    run_pty("two prompts", 5, longer);
    run_pty("EVP_read_pw_string", 7, pem);

    run_pipe("verified", 0, "secret\nsecret\n");
    run_pipe("not verified", 4, "one\ntwo\n");
    run_pipe("echoed, with information", 1, "hello there\n");
    run_pipe("a boolean", 2, "Y\n");
    run_pipe("too short", 3, "ab\n");
    run_pipe("too long", 3, "abcdefghij\n");
    run_pipe("a long line", 5, longline + 1);
    run_pipe("end of input", 6, "no newline");
    run_pipe("nothing", 6, "");
    run_pipe("EVP_read_pw_string", 7, "pass phrase\npass phrase\n");

    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
