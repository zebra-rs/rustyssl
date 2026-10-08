/*
 * Differential probe (TEST_PLAN.md, layer L5). Reads one command per line on stdin, runs it
 * against whichever libcrypto the dynamic loader picked, and prints a deterministic line per
 * command. `cargo xtask test-differential` runs the same input against the reference and
 * rustssl and compares the output.
 *
 * Commands for BUF_MEM (one buffer at a time):
 *   new <flags>        BUF_MEM_new_ex(flags), replacing any current buffer
 *   grow <len>         BUF_MEM_grow
 *   grow_clean <len>   BUF_MEM_grow_clean
 *   fill <byte>        set every byte below `length` to <byte>
 *   dump               print `length` bytes of data in hex
 *   free               BUF_MEM_free
 *   reverse <hex>      BUF_reverse, copying and in place
 *
 * Commands for the error queue:
 *   errstr <code> <len>        ERR_error_string_n into a buffer of <len> bytes
 *   raise <lib> <reason>       ERR_raise
 *   data <word>                ERR_add_error_data with one string
 *   txt <sep> <len> <every>    ERR_add_error_txt with <len> bytes of text and the separator
 *                              (- for none) after every <every> bytes
 *   mark, pop, poptomark, clearmark, count, clear
 *                              ERR_set_mark, ERR_pop, ERR_pop_to_mark, ERR_clear_last_mark,
 *                              ERR_count_to_mark, ERR_clear_error
 *   get, peek, last            ERR_get_error_all, ERR_peek_error_all, ERR_peek_last_error_all
 *   save, savemark, restore    OSSL_ERR_STATE_save, _save_to_mark, _restore with one saved state
 *   state                      the thread's ERR_STATE, slot by slot (data as length and hash)
 *
 *   # ...              comment, echoed
 */
/* ERR_get_state is deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/err.h>

static BUF_MEM *buffer = NULL;

static void print_state(const char *command, size_t result)
{
    printf("%s %zu length=%zu max=%zu\n", command, result, buffer->length, buffer->max);
}

static int parse_hex(const char *hex, unsigned char *out, size_t *len)
{
    size_t n = strlen(hex);

    if (n % 2 != 0 || n / 2 > 256)
        return 0;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned int byte;

        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            return 0;
        out[i] = (unsigned char)byte;
    }
    *len = n / 2;
    return 1;
}

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* FNV-1a, to compare long data without printing it. */
static unsigned long hash(const char *text)
{
    unsigned long h = 2166136261UL;

    for (; *text != '\0'; text++)
        h = ((h ^ (unsigned char)*text) * 16777619UL) & 0xffffffffUL;
    return h;
}

static const char *or_dash(const char *text)
{
    return text == NULL || text[0] == '\0' ? "-" : text;
}

static void print_error(const char *command, unsigned long code, const char *file, int line,
                        const char *func, const char *data, int flags)
{
    printf("%s %lx", command, code);
    if (code != 0)
        printf(" %s:%d:%s data=%zu:%lx flags=%d", or_dash(file), line, or_dash(func), strlen(data),
               hash(data), flags);
    printf("\n");
}

static void print_err_state(void)
{
    ERR_STATE *es = ERR_get_state();

    if (es == NULL) {
        printf("state none\n");
        return;
    }
    printf("state top=%d bottom=%d\n", es->top, es->bottom);
    for (int i = 0; i < ERR_NUM_ERRORS; i++) {
        const char *data = es->err_data[i];
        int text = data != NULL && (es->err_data_flags[i] & ERR_TXT_STRING) != 0;

        printf("  %d: %lx marks=%d flags=%d %s:%d:%s data=%d:%zu", i, es->err_buffer[i],
               es->err_marks[i], es->err_flags[i], or_dash(es->err_file[i]), es->err_line[i],
               or_dash(es->err_func[i]), es->err_data_flags[i], es->err_data_size[i]);
        if (text)
            printf(":%zu:%lx", strlen(data), hash(data));
        printf("\n");
    }
}

/* Builds the text for `txt`: letters, with the separator after every `every` of them. */
static char *make_text(const char *separator, size_t len, size_t every)
{
    size_t sep = strlen(separator), used = 0;
    char *text = malloc(len + (every == 0 ? 0 : len / every * sep) + 1);

    if (text == NULL)
        return NULL;
    for (size_t i = 0; i < len; i++) {
        text[used++] = (char)('a' + i % 26);
        if (every != 0 && (i + 1) % every == 0) {
            memcpy(text + used, separator, sep);
            used += sep;
        }
    }
    text[used] = '\0';
    return text;
}

/* Runs an error-queue command; returns 0 if `command` isn't one. */
static int err_command(const char *command, const char *line)
{
    static ERR_STATE *saved = NULL;
    const char *file = NULL, *func = NULL, *data = NULL;
    int number = 0, flags = 0;
    unsigned long code;

    if (strcmp(command, "errstr") == 0) {
        unsigned long e = 0;
        size_t len = 0;
        char buf[600];

        if (sscanf(line, "%*s %lx %zu", &e, &len) != 2 || len > sizeof(buf)) {
            printf("error bad errstr\n");
            return 1;
        }
        memset(buf, '#', sizeof(buf));
        ERR_error_string_n(e, buf, len);
        buf[sizeof(buf) - 1] = '\0';
        printf("errstr %lx %zu %s\n", e, len, len == 0 ? "-" : buf);
    } else if (strcmp(command, "raise") == 0) {
        int lib = 0, reason = 0;

        if (sscanf(line, "%*s %d %d", &lib, &reason) != 2) {
            printf("error bad raise\n");
            return 1;
        }
        ERR_raise(lib, reason);
        printf("raise %lx\n", ERR_peek_last_error());
    } else if (strcmp(command, "data") == 0) {
        char word[100] = "";

        if (sscanf(line, "%*s %99s", word) != 1)
            word[0] = '\0';
        ERR_add_error_data(1, word);
        printf("data\n");
    } else if (strcmp(command, "txt") == 0) {
        char separator[16] = "";
        size_t len = 0, every = 0;
        char *text;

        if (sscanf(line, "%*s %15s %zu %zu", separator, &len, &every) != 3 || len > 20000) {
            printf("error bad txt\n");
            return 1;
        }
        if (strcmp(separator, "-") == 0)
            separator[0] = '\0';
        text = make_text(separator, len, every);
        ERR_add_error_txt(separator, text);
        free(text);
        printf("txt\n");
    } else if (strcmp(command, "mark") == 0) {
        printf("mark %d\n", ERR_set_mark());
    } else if (strcmp(command, "pop") == 0) {
        printf("pop %d\n", ERR_pop());
    } else if (strcmp(command, "poptomark") == 0) {
        printf("poptomark %d\n", ERR_pop_to_mark());
    } else if (strcmp(command, "clearmark") == 0) {
        printf("clearmark %d\n", ERR_clear_last_mark());
    } else if (strcmp(command, "count") == 0) {
        printf("count %d\n", ERR_count_to_mark());
    } else if (strcmp(command, "clear") == 0) {
        ERR_clear_error();
        printf("clear\n");
    } else if (strcmp(command, "get") == 0) {
        code = ERR_get_error_all(&file, &number, &func, &data, &flags);
        print_error("get", code, file, number, func, data, flags);
    } else if (strcmp(command, "peek") == 0) {
        code = ERR_peek_error_all(&file, &number, &func, &data, &flags);
        print_error("peek", code, file, number, func, data, flags);
    } else if (strcmp(command, "last") == 0) {
        code = ERR_peek_last_error_all(&file, &number, &func, &data, &flags);
        print_error("last", code, file, number, func, data, flags);
    } else if (strcmp(command, "save") == 0 || strcmp(command, "savemark") == 0
               || strcmp(command, "restore") == 0) {
        if (saved == NULL)
            saved = OSSL_ERR_STATE_new();
        if (strcmp(command, "save") == 0)
            OSSL_ERR_STATE_save(saved);
        else if (strcmp(command, "savemark") == 0)
            OSSL_ERR_STATE_save_to_mark(saved);
        else
            OSSL_ERR_STATE_restore(saved);
        printf("%s\n", command);
    } else if (strcmp(command, "state") == 0) {
        print_err_state();
    } else {
        return 0;
    }
    return 1;
}

int main(void)
{
    char line[1024], command[32], argument[1000];

    while (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') {
            printf("%s\n", line);
            continue;
        }
        argument[0] = '\0';
        if (sscanf(line, "%31s %999s", command, argument) < 1)
            continue;
        if (err_command(command, line)) {
            fflush(stdout);
            continue;
        } else if (strcmp(command, "new") == 0) {
            BUF_MEM_free(buffer);
            buffer = BUF_MEM_new_ex(strtoul(argument, NULL, 0));
            printf("new %s\n", buffer == NULL ? "failed" : "ok");
        } else if (strcmp(command, "reverse") == 0) {
            unsigned char in[256], out[256];
            size_t len;

            if (!parse_hex(argument, in, &len)) {
                printf("error bad hex\n");
                continue;
            }
            BUF_reverse(out, in, len);
            print_hex("reversed", out, len);
            BUF_reverse(in, NULL, len);
            print_hex("in-place", in, len);
        } else if (buffer == NULL) {
            printf("error no buffer\n");
        } else if (strcmp(command, "grow") == 0) {
            print_state("grow", BUF_MEM_grow(buffer, strtoul(argument, NULL, 0)));
        } else if (strcmp(command, "grow_clean") == 0) {
            print_state("grow_clean", BUF_MEM_grow_clean(buffer, strtoul(argument, NULL, 0)));
        } else if (strcmp(command, "fill") == 0) {
            if (buffer->length > 0)
                memset(buffer->data, (int)strtoul(argument, NULL, 0), buffer->length);
            printf("fill %zu\n", buffer->length);
        } else if (strcmp(command, "dump") == 0) {
            print_hex("data", (const unsigned char *)buffer->data, buffer->length);
        } else if (strcmp(command, "free") == 0) {
            BUF_MEM_free(buffer);
            buffer = NULL;
            printf("free\n");
        } else {
            printf("error unknown command %s\n", command);
        }
        fflush(stdout);
    }
    BUF_MEM_free(buffer);
    return 0;
}
