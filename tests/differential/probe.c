/*
 * Differential probe (TEST_PLAN.md, layer L5). Reads one command per line on stdin, runs it
 * against whichever libcrypto the dynamic loader picked, and prints a deterministic line per
 * command. `cargo xtask test-differential` runs the same input against the reference and
 * rustyssl and compares the output.
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
 * Commands for a stack of pointers into a pool of 64 ints (pool[i] = i * 7 % 10, so values
 * repeat; elements print as pool indexes, so the order of equal values shows):
 *   sknew <cmp>                OPENSSL_sk_new: 0 no comparator, 1 by value, 2 reversed
 *   skcmp <cmp>                OPENSSL_sk_set_cmp_func
 *   skpush <i>, skunshift <i>, skinsert <i> <loc>, skset <loc> <i>, skdelptr <i>
 *   skdelete <loc>, skshift, skpop, skzero, sksort, skdup, skreserve <n>
 *   skfind <value>, skfindex <value>, skfindall <value>   (with the comparisons made)
 *   skdump                     the elements and the sorted flag
 *
 * Commands for a hash table of items keyed by number (pool indexes again):
 *   lhnew <hash>               lh_ITEM_new: 0 the key itself, 1 a multiplicative hash
 *   lhinsert <i>, lhdelete <i>, lhget <i>, lhdown <n>, lhdump (the doall order)
 *
 * Commands for a BIO (`_` in a word stands for a newline):
 *   bionew <kind>              0 memory, 1 secure memory, 2 read-only over a fixed text,
 *                              3 memory behind a null filter, 4 behind a buffer, 5 behind a
 *                              line buffer, 6 a read buffer over the fixed text, 7 memory
 *                              behind a prefix filter ("> ", indented 2), 8 one end of a BIO
 *                              pair (buffers of 16 and 32 bytes)
 *   biopeer                    switch to the pair's other end
 *   biowrite <word>, bioputs <word>, bioread <n>, biogets <n>, bioline <n>
 *   bionread <n>, bionwrite <word>   BIO_nread and BIO_nwrite (what was read, or copied in)
 *   bioctrl <name> <n>         reset, eof, pending, wpending, seek, tell, eofret, setclose,
 *                              getclose, flush, info, shutdown, guarantee, request, lines,
 *                              bufsize
 *   biomem                     BIO_get_mem_ptr: the buffer's length and a hash of its data
 *   biostate                   retry flags, bytes read and written
 *
 * Commands for OpenSSL's printf (`_` in a format stands for a space). Each argument is typed:
 * i:<int>, j:<64-bit int>, d:<double>, or s:<word> (s:- is a null string); at most three:
 *   printf <n> <format> <arg>...   BIO_snprintf into a buffer of <n> bytes (at most 100),
 *                                  printing the return and the first <n> + 1 bytes
 *   bioprintf <format> <arg>...    BIO_printf to a memory BIO, printing the return and what
 *                                  it wrote
 *
 * Other helpers:
 *   hexdecode <text> <sep>     OPENSSL_hexstr2buf_ex with the separator's code
 *   strtoul <text> <base>      OPENSSL_strtoul, with and without an end pointer
 *
 *   # ...              comment, echoed
 */
#define _POSIX_C_SOURCE 200809L
/* ERR_get_state is deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/stack.h>

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

/* The pool stacks and hash tables point into. */
static int pool[64];
static int comparisons;

static int pool_index(const void *p)
{
    return p == NULL ? -1 : (int)((const int *)p - pool);
}

static int by_value(const void *a, const void *b)
{
    const int *x = *(const int *const *)a, *y = *(const int *const *)b;

    comparisons++;
    return *x < *y ? -1 : *x > *y;
}

static int by_value_reversed(const void *a, const void *b)
{
    return -by_value(a, b);
}

static OPENSSL_sk_compfunc comparator(int which)
{
    return which == 1 ? by_value : which == 2 ? by_value_reversed : NULL;
}

static void print_stack(const char *label, const OPENSSL_STACK *st)
{
    printf("%s num=%d sorted=%d:", label, OPENSSL_sk_num(st), OPENSSL_sk_is_sorted(st));
    for (int i = 0; i < OPENSSL_sk_num(st); i++)
        printf(" %d", pool_index(OPENSSL_sk_value(st, i)));
    printf("\n");
}

/* Runs a stack command; returns 0 if `command` isn't one. */
static int stack_command(const char *command, const char *line)
{
    static OPENSSL_STACK *st = NULL;
    int a = 0, b = 0, n;

    n = sscanf(line, "%*s %d %d", &a, &b);
    if (a < 0 || a >= 64)
        a = 0;
    if (strcmp(command, "sknew") == 0) {
        OPENSSL_sk_free(st);
        st = OPENSSL_sk_new(comparator(a));
        printf("sknew\n");
        return 1;
    }
    if (strncmp(command, "sk", 2) != 0)
        return 0;
    if (st == NULL) {
        printf("error no stack\n");
    } else if (strcmp(command, "skcmp") == 0) {
        OPENSSL_sk_compfunc old = OPENSSL_sk_set_cmp_func(st, comparator(a));
        printf("skcmp old=%d sorted=%d\n", old == by_value ? 1 : old == by_value_reversed ? 2 : 0,
               OPENSSL_sk_is_sorted(st));
    } else if (strcmp(command, "skpush") == 0) {
        printf("skpush %d\n", OPENSSL_sk_push(st, &pool[a]));
    } else if (strcmp(command, "skunshift") == 0) {
        printf("skunshift %d\n", OPENSSL_sk_unshift(st, &pool[a]));
    } else if (strcmp(command, "skinsert") == 0) {
        printf("skinsert %d\n", OPENSSL_sk_insert(st, &pool[a], b));
    } else if (strcmp(command, "skset") == 0) {
        sscanf(line, "%*s %d %d", &a, &b);
        if (b < 0 || b >= 64)
            b = 0;
        printf("skset %d\n", pool_index(OPENSSL_sk_set(st, a, &pool[b])));
        ERR_clear_error();
    } else if (strcmp(command, "skdelptr") == 0) {
        printf("skdelptr %d\n", pool_index(OPENSSL_sk_delete_ptr(st, &pool[a])));
    } else if (strcmp(command, "skdelete") == 0) {
        sscanf(line, "%*s %d", &a);
        printf("skdelete %d\n", pool_index(OPENSSL_sk_delete(st, a)));
    } else if (strcmp(command, "skshift") == 0) {
        printf("skshift %d\n", pool_index(OPENSSL_sk_shift(st)));
    } else if (strcmp(command, "skpop") == 0) {
        printf("skpop %d\n", pool_index(OPENSSL_sk_pop(st)));
    } else if (strcmp(command, "skzero") == 0) {
        OPENSSL_sk_zero(st);
        printf("skzero\n");
    } else if (strcmp(command, "sksort") == 0) {
        comparisons = 0;
        OPENSSL_sk_sort(st);
        print_stack("sksort", st);
    } else if (strcmp(command, "skdup") == 0) {
        OPENSSL_STACK *copy = OPENSSL_sk_dup(st);

        print_stack("skdup", copy);
        OPENSSL_sk_free(st);
        st = copy;
    } else if (strcmp(command, "skreserve") == 0) {
        sscanf(line, "%*s %d", &a);
        printf("skreserve %d\n", OPENSSL_sk_reserve(st, a));
        ERR_clear_error();
    } else if (strcmp(command, "skfind") == 0 || strcmp(command, "skfindex") == 0
               || strcmp(command, "skfindall") == 0) {
        int key, *k = &key, count = 5, at;

        sscanf(line, "%*s %d", &key);
        comparisons = 0;
        if (strcmp(command, "skfind") == 0)
            at = OPENSSL_sk_find(st, k);
        else if (strcmp(command, "skfindex") == 0)
            at = OPENSSL_sk_find_ex(st, k);
        else
            at = OPENSSL_sk_find_all(st, k, &count);
        printf("%s %d count=%d comparisons=%d\n", command, at, count, comparisons);
    } else if (strcmp(command, "skdump") == 0) {
        print_stack("skdump", st);
    } else {
        printf("error unknown command %s\n", command);
    }
    (void)n;
    return 1;
}

/* Hash table items: pool entries, keyed by their index. */
typedef struct {
    int key;
} ITEM;

DEFINE_LHASH_OF_EX(ITEM);

static ITEM items[64];

static unsigned long hash_key(const ITEM *item)
{
    return (unsigned long)item->key;
}

static unsigned long hash_mixed(const ITEM *item)
{
    return ((unsigned long)item->key * 2654435761UL) & 0xffffffffUL;
}

static int same_key(const ITEM *a, const ITEM *b)
{
    return a->key != b->key;
}

static void print_item(ITEM *item)
{
    printf(" %d", (int)(item - items));
}

/* Runs a hash table command; returns 0 if `command` isn't one. */
static int lhash_command(const char *command, const char *line)
{
    static LHASH_OF(ITEM) *lh = NULL;
    static ITEM copies[64];
    int a = 0;

    sscanf(line, "%*s %d", &a);
    if (strcmp(command, "lhnew") == 0) {
        lh_ITEM_free(lh);
        for (int i = 0; i < 64; i++)
            items[i].key = copies[i].key = i;
        lh = lh_ITEM_new(a == 1 ? hash_mixed : hash_key, same_key);
        printf("lhnew\n");
        return 1;
    }
    if (strncmp(command, "lh", 2) != 0)
        return 0;
    if (a < 0 || a >= 64)
        a = 0;
    if (lh == NULL) {
        printf("error no table\n");
    } else if (strcmp(command, "lhinsert") == 0) {
        ITEM *old = lh_ITEM_insert(lh, &items[a]);

        printf("lhinsert %d items=%lu\n", old == NULL ? -1 : (int)(old - items),
               lh_ITEM_num_items(lh));
    } else if (strcmp(command, "lhdelete") == 0) {
        ITEM *old = lh_ITEM_delete(lh, &copies[a]);

        printf("lhdelete %d items=%lu\n", old == NULL ? -1 : (int)(old - items),
               lh_ITEM_num_items(lh));
    } else if (strcmp(command, "lhget") == 0) {
        ITEM *found = lh_ITEM_retrieve(lh, &copies[a]);

        printf("lhget %d\n", found == NULL ? -1 : (int)(found - items));
    } else if (strcmp(command, "lhdown") == 0) {
        sscanf(line, "%*s %d", &a);
        lh_ITEM_set_down_load(lh, (unsigned long)a);
        printf("lhdown %lu\n", lh_ITEM_get_down_load(lh));
    } else if (strcmp(command, "lhdump") == 0) {
        printf("lhdump");
        lh_ITEM_doall(lh, print_item);
        printf("\n");
    } else {
        printf("error unknown command %s\n", command);
    }
    return 1;
}

static void print_bytes(const char *label, int ret, const char *data, int len)
{
    printf("%s %d \"", label, ret);
    for (int i = 0; i < len; i++)
        printf(data[i] == '\n' ? "\\n" : "%c", data[i]);
    printf("\"\n");
}

/* Runs a memory BIO command; returns 0 if `command` isn't one. */
static int bio_command(const char *command, const char *line)
{
    static const char fixed[] = "line one\nline two\nthird line, no newline";
    static BIO *bio = NULL, *peer = NULL;
    char word[200] = "", name[32] = "";
    char buf[300];
    int n = 0;

    if (strncmp(command, "bio", 3) != 0)
        return 0;
    sscanf(line, "%*s %199s", word);
    for (char *p = word; *p != '\0'; p++)
        if (*p == '_')
            *p = '\n';
    if (strcmp(word, "-") == 0)
        word[0] = '\0';
    n = atoi(word);
    if (n < 0 || n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    if (strcmp(command, "bionew") == 0) {
        BIO_free_all(bio);
        BIO_free(peer);
        peer = NULL;
        switch (n) {
        case 1:
            bio = BIO_new(BIO_s_secmem());
            break;
        case 2:
            bio = BIO_new_mem_buf(fixed, -1);
            break;
        case 3:
            bio = BIO_push(BIO_new(BIO_f_null()), BIO_new(BIO_s_mem()));
            break;
        case 4:
            bio = BIO_push(BIO_new(BIO_f_buffer()), BIO_new(BIO_s_mem()));
            break;
        case 5:
            bio = BIO_push(BIO_new(BIO_f_linebuffer()), BIO_new(BIO_s_mem()));
            break;
        case 6:
            bio = BIO_push(BIO_new(BIO_f_readbuffer()), BIO_new_mem_buf(fixed, -1));
            break;
        case 7:
            bio = BIO_push(BIO_new(BIO_f_prefix()), BIO_new(BIO_s_mem()));
            (void)BIO_set_prefix(bio, "> ");
            (void)BIO_set_indent(bio, 2);
            break;
        case 8:
            if (!BIO_new_bio_pair(&bio, 16, &peer, 32))
                bio = peer = NULL;
            break;
        default:
            bio = BIO_new(BIO_s_mem());
        }
        printf("bionew %d\n", bio != NULL);
    } else if (bio == NULL) {
        printf("error no bio\n");
    } else if (strcmp(command, "biopeer") == 0) {
        if (peer != NULL) {
            BIO *other = bio;

            bio = peer;
            peer = other;
        }
        printf("biopeer %d\n", peer != NULL);
    } else if (strcmp(command, "bionread") == 0) {
        char *p = NULL;
        int ret = BIO_nread(bio, &p, n);

        print_bytes("bionread", ret, p, ret > 0 && p != NULL ? ret : 0);
    } else if (strcmp(command, "bionwrite") == 0) {
        char *p = NULL;
        int room = BIO_nwrite0(bio, &p), len = (int)strlen(word), ret;

        if (room > 0 && p != NULL)
            memcpy(p, word, (size_t)(len < room ? len : room));
        ret = BIO_nwrite(bio, &p, len);
        printf("bionwrite %d %d\n", room, ret);
    } else if (strcmp(command, "biowrite") == 0) {
        printf("biowrite %d\n", BIO_write(bio, word, (int)strlen(word)));
    } else if (strcmp(command, "bioputs") == 0) {
        printf("bioputs %d\n", BIO_puts(bio, word));
    } else if (strcmp(command, "bioread") == 0) {
        int ret;

        /* A positive EOF return reads "bytes" that were never written: show the fill. */
        memset(buf, '#', sizeof(buf));
        ret = BIO_read(bio, buf, n);

        print_bytes("bioread", ret, buf, ret > 0 ? ret : 0);
    } else if (strcmp(command, "biogets") == 0 || strcmp(command, "bioline") == 0) {
        int ret;

        memset(buf, '#', sizeof(buf));
        ret = strcmp(command, "biogets") == 0 ? BIO_gets(bio, buf, n) : BIO_get_line(bio, buf, n);
        print_bytes(command, ret, buf, ret > 0 ? ret : 0);
    } else if (strcmp(command, "bioctrl") == 0) {
        long arg = 0, ret = -99;
        char *data = NULL;

        sscanf(line, "%*s %31s %ld", name, &arg);
        if (strcmp(name, "reset") == 0)
            ret = BIO_reset(bio);
        else if (strcmp(name, "eof") == 0)
            ret = BIO_eof(bio);
        else if (strcmp(name, "pending") == 0)
            ret = BIO_pending(bio);
        else if (strcmp(name, "wpending") == 0)
            ret = BIO_wpending(bio);
        else if (strcmp(name, "seek") == 0)
            ret = BIO_seek(bio, arg);
        else if (strcmp(name, "tell") == 0)
            ret = BIO_tell(bio);
        else if (strcmp(name, "eofret") == 0)
            ret = BIO_set_mem_eof_return(bio, arg);
        else if (strcmp(name, "setclose") == 0)
            ret = BIO_set_close(bio, arg);
        else if (strcmp(name, "getclose") == 0)
            ret = BIO_get_close(bio);
        else if (strcmp(name, "flush") == 0)
            ret = BIO_flush(bio);
        else if (strcmp(name, "shutdown") == 0)
            ret = BIO_shutdown_wr(bio);
        else if (strcmp(name, "guarantee") == 0)
            ret = (long)BIO_ctrl_get_write_guarantee(bio);
        else if (strcmp(name, "request") == 0)
            ret = (long)BIO_ctrl_get_read_request(bio);
        else if (strcmp(name, "lines") == 0)
            ret = BIO_get_buffer_num_lines(bio);
        else if (strcmp(name, "bufsize") == 0)
            ret = BIO_set_buffer_size(bio, arg);
        else if (strcmp(name, "info") == 0) {
            ret = BIO_get_mem_data(bio, &data);
            if (ret > 0 && data != NULL) {
                print_bytes("bioctrl info", (int)ret, data, (int)ret);
                ERR_clear_error();
                return 1;
            }
        }
        printf("bioctrl %s %ld\n", name, ret);
    } else if (strcmp(command, "biomem") == 0) {
        BUF_MEM *bm = NULL;
        BIO *mem = BIO_find_type(bio, BIO_TYPE_MEM);

        if (mem != NULL && BIO_get_mem_ptr(mem, &bm) > 0 && bm != NULL) {
            char *copy = OPENSSL_strndup(bm->data == NULL ? "" : bm->data, bm->length);

            printf("biomem %zu %lx\n", bm->length, copy == NULL ? 0UL : hash(copy));
            OPENSSL_free(copy);
        } else {
            printf("biomem none\n");
        }
    } else if (strcmp(command, "biostate") == 0) {
        printf("biostate retry=%d read=%d write=%d in=%llu out=%llu\n", BIO_should_retry(bio) != 0,
               BIO_should_read(bio) != 0, BIO_should_write(bio) != 0,
               (unsigned long long)BIO_number_read(bio), (unsigned long long)BIO_number_written(bio));
    } else {
        printf("error unknown command %s\n", command);
    }
    ERR_clear_error();
    return 1;
}

/* Runs a string helper command; returns 0 if `command` isn't one. */
static int string_command(const char *command, const char *line)
{
    char text[200] = "";
    int other = 0;

    sscanf(line, "%*s %199s %d", text, &other);
    if (strcmp(text, "-") == 0)
        text[0] = '\0';
    if (strcmp(command, "hexdecode") == 0) {
        unsigned char buf[100];
        size_t len = 0;
        int ok = OPENSSL_hexstr2buf_ex(buf, sizeof(buf), &len, text, (char)other);

        printf("hexdecode %d", ok);
        if (ok) {
            printf(" len=%zu ", len);
            for (size_t i = 0; i < len; i++)
                printf("%02x", buf[i]);
        } else {
            printf(" reason=%d", ERR_GET_REASON(ERR_get_error()));
        }
        printf("\n");
        ERR_clear_error();
    } else if (strcmp(command, "strtoul") == 0) {
        unsigned long value = 0;
        char *end = NULL;
        int with, without, saved;

        with = OPENSSL_strtoul(text, &end, other, &value);
        saved = errno;
        printf("strtoul %d %lu end=%d errno=%d", with, value, (int)(end - text), saved);
        without = OPENSSL_strtoul(text, NULL, other, &value);
        printf(" without=%d\n", without);
    } else {
        return 0;
    }
    return 1;
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

/* A typed argument of a printf command. */
typedef struct {
    int i;
    long long j;
    double d;
    const char *s;
} ARG;

/*
 * Calls CALL(arguments...) with the arguments typed as `sig` says (one letter each), so each
 * argument is passed as its own C type, as a real call would.
 */
#define V_i(a) (a).i
#define V_j(a) (a).j
#define V_d(a) (a).d
#define V_s(a) (a).s
#define C1(x) \
    if (strcmp(sig, #x) == 0) \
        return CALL(V_##x(a[0]));
#define C2(x, y) \
    if (strcmp(sig, #x #y) == 0) \
        return CALL(V_##x(a[0]), V_##y(a[1]));
#define C3(x, y, z) \
    if (strcmp(sig, #x #y #z) == 0) \
        return CALL(V_##x(a[0]), V_##y(a[1]), V_##z(a[2]));
#define L3(x, y) C3(x, y, i) C3(x, y, j) C3(x, y, d) C3(x, y, s)
#define L2(x) C2(x, i) C2(x, j) C2(x, d) C2(x, s) L3(x, i) L3(x, j) L3(x, d) L3(x, s)
#define EVERY_SIGNATURE C1(i) C1(j) C1(d) C1(s) L2(i) L2(j) L2(d) L2(s)

static int call_snprintf(char *buf, size_t n, const char *f, const char *sig, const ARG *a)
{
#define CALL(...) BIO_snprintf(buf, n, f, __VA_ARGS__)
    if (sig[0] == '\0')
        return CALL(0);
    EVERY_SIGNATURE
#undef CALL
    return -99;
}

static int call_printf(BIO *bio, const char *f, const char *sig, const ARG *a)
{
#define CALL(...) BIO_printf(bio, f, __VA_ARGS__)
    if (sig[0] == '\0')
        return CALL(0);
    EVERY_SIGNATURE
#undef CALL
    return -99;
}

static void print_escaped(const char *label, int ret, const char *data, size_t len)
{
    printf("%s %d \"", label, ret);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];

        if (c >= ' ' && c <= '~' && c != '\\' && c != '"')
            putchar(c);
        else
            printf("\\x%02x", c);
    }
    printf("\"\n");
}

static int printf_command(const char *command, const char *line)
{
    static BIO *mem = NULL;
    static char words[1024];
    char format[300], sig[4] = "", buf[128];
    ARG a[3];
    char *word, *save = NULL;
    size_t n = 0;
    int count = 0, ret;

    if (strcmp(command, "printf") != 0 && strcmp(command, "bioprintf") != 0)
        return 0;
    snprintf(words, sizeof(words), "%s", line);
    strtok_r(words, " ", &save);
    if (strcmp(command, "printf") == 0) {
        word = strtok_r(NULL, " ", &save);
        n = word == NULL ? 0 : strtoul(word, NULL, 10);
        if (n > 100)
            n = 100;
    }
    word = strtok_r(NULL, " ", &save);
    snprintf(format, sizeof(format), "%s", word == NULL ? "" : word);
    for (char *p = format; *p != '\0'; p++)
        if (*p == '_')
            *p = ' ';
    while ((word = strtok_r(NULL, " ", &save)) != NULL && count < 3) {
        memset(&a[count], 0, sizeof(a[count]));
        if (word[0] == '\0' || word[1] != ':') {
            printf("error bad argument %s\n", word);
            return 1;
        }
        switch (word[0]) {
        case 'i':
            a[count].i = (int)strtol(word + 2, NULL, 10);
            break;
        case 'j':
            a[count].j = strtoll(word + 2, NULL, 10);
            break;
        case 'd':
            a[count].d = strtod(word + 2, NULL);
            break;
        case 's':
            a[count].s = strcmp(word + 2, "-") == 0 ? NULL : word + 2;
            break;
        default:
            printf("error bad argument %s\n", word);
            return 1;
        }
        sig[count++] = word[0];
        sig[count] = '\0';
    }
    if (strcmp(command, "printf") == 0) {
        memset(buf, '#', sizeof(buf));
        ret = call_snprintf(buf, n, format, sig, a);
        print_escaped("printf", ret, buf, n + 1);
    } else {
        char *data = NULL;
        long len;

        if (mem == NULL)
            mem = BIO_new(BIO_s_mem());
        ret = call_printf(mem, format, sig, a);
        len = BIO_get_mem_data(mem, &data);
        print_escaped("bioprintf", ret, data, len > 0 ? (size_t)len : 0);
        (void)BIO_reset(mem);
    }
    ERR_clear_error();
    return 1;
}

int main(void)
{
    for (int i = 0; i < 64; i++)
        pool[i] = i * 7 % 10;
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
        if (err_command(command, line) || stack_command(command, line)
            || lhash_command(command, line) || string_command(command, line)
            || bio_command(command, line) || printf_command(command, line)) {
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
