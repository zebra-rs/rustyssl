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
 *                              pair (buffers of 16 and 32 bytes), 9 a datagram memory BIO,
 *                              10 one end of a datagram pair (default buffers)
 *   biopeer                    switch to the pair's other end
 *   biowrite <word>, bioputs <word>, bioread <n>, biogets <n>, bioline <n>
 *   bionread <n>, bionwrite <word>   BIO_nread and BIO_nwrite (what was read, or copied in)
 *   bioctrl <name> <n>         reset, eof, pending, wpending, seek, tell, eofret, setclose,
 *                              getclose, flush, info, shutdown, guarantee, request, lines,
 *                              bufsize, wbufsize, notrunc, mtu
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
 * Commands for addresses (`_` in a spec stands for nothing, so `_` alone is the empty spec):
 *   hostserv <spec> <prio>     BIO_parse_hostserv with priority 0 (host) or 1 (service):
 *                              the result, host, and service, or the error's reason
 *   addr <family> <hex> <port> BIO_ADDR_rawmake (4 for AF_INET, 6 for AF_INET6, u for
 *                              AF_UNIX with the hex as the path), then the family, raw port,
 *                              raw address, and numeric host and service strings
 *
 * Other helpers:
 *   hexdecode <text> <sep>     OPENSSL_hexstr2buf_ex with the separator's code
 *   strtoul <text> <base>      OPENSSL_strtoul, with and without an end pointer
 *   tracecat <name> <num>      OSSL_trace_get_category_num and OSSL_trace_get_category_name
 *
 * Commands for objects (`-` for empty hex):
 *   objtxt <hex> <no_name>     OBJ_txt2obj of the text in hex: its NID, OBJ_obj2txt with names
 *                              and without, and a2d_ASN1_OBJECT of the text; or the error
 *   objder <hex>               an object with those content octets: OBJ_obj2nid, OBJ_obj2txt
 *                              with names and without, and i2a_ASN1_OBJECT
 *   objname <name>             OBJ_sn2nid, OBJ_ln2nid, and OBJ_txt2nid
 *
 * Commands for ASN.1 headers:
 *   asnhdr <hex> <delta>       ASN1_get_object on the octets with omax their count plus delta
 *                              (never more than the octets, past the header): the result, the
 *                              outputs (preset to -7), the octets used, and the errors
 *   asnput <cons> <len> <tag> <class>   ASN1_put_object and ASN1_object_size
 *   d2iobj <hex>               d2i_ASN1_OBJECT: the NID and text, the octets used, the errors,
 *                              and i2d_ASN1_OBJECT of the result
 *
 * Commands for INTEGER and ENUMERATED:
 *   asnint <type> <hex>        a string of that type and octets: the int64, uint64, long, and
 *                              ENUMERATED getters, i2a_ASN1_INTEGER, and the errors
 *   asnset <value>             ASN1_INTEGER_set_int64 and the octets stored
 *   a2iint <size> <hex>        a2i_ASN1_INTEGER on the text (in hex) with a buffer of <size>
 *   a2istr <size> <hex>        the same with a2i_ASN1_STRING, then i2a_ASN1_STRING of the result
 *                              (at most 300)
 *   asnbit <hex> <n> <value> <flags-hex>   a BIT STRING of those octets: ASN1_BIT_STRING_set_bit
 *                              of bit <n>, the octets after, get_bit around <n>, and
 *                              ASN1_BIT_STRING_check against the flags
 *
 * Commands for character strings:
 *   asntext <type> <flags> <hex>   a string of that type: ASN1_STRING_print_ex with <flags> (to a
 *                              BIO and counted), ASN1_STRING_to_UTF8, and the errors
 *   asnmb <inform> <mask> <min> <max> <hex>   ASN1_mbstring_ncopy: the type, the octets, the
 *                              errors
 *
 * Commands for times:
 *   asntime <type> <flags> <hex>   a string of that type, flags, and octets: the checks,
 *                              ASN1_TIME_to_tm, both printouts, ASN1_TIME_normalize, and the
 *                              difference from a fixed time
 *   asntimet <time> <days> <secs>  ASN1_TIME_adj, ASN1_UTCTIME_adj, ASN1_GENERALIZEDTIME_adj,
 *                              and OPENSSL_gmtime_adj of OPENSSL_gmtime
 *
 * Commands for the template engine:
 *   asnany <type>:<hex> ...    up to 8 ASN1_TYPEs (type -2 is a negative INTEGER, 1 a BOOLEAN
 *                              from the first octet, 6 an OBJECT from its content octets, `-`
 *                              for none): i2d_ASN1_TYPE of each, then i2d_ASN1_SEQUENCE_ANY and
 *                              i2d_ASN1_SET_ANY of them all
 *   asnd2i <item> <hex>        ASN1_item_d2i of the octets with item <item> (0 ANY, 1 SEQUENCE_ANY,
 *                              2 SET_ANY, 3 OCTET_STRING, 4 INTEGER, 5 BIT_STRING, 6 BMPSTRING,
 *                              7 TIME, 8 DIRECTORYSTRING, 9 INT64, 10 UINT32, 11 the probe's
 *                              PROBEREC, 12 ASN1_SEQUENCE, 13 UTF8STRING): how much was read
 *                              and the re-encoding and ASN1_item_print listing, or the errors with
 *                              their data
 *   asnbio <hex>               ASN1_item_d2i_bio (as ANY) from a memory BIO over the octets until
 *                              a read fails: each element's re-encoding, then the errors
 *   asnparse <indent> <dump> <hex>   ASN1_parse_dump of the octets (dump -2: ASN1_parse) to a
 *                              memory BIO: the return, the listing (escaped), and the errors
 *   asns2i <text>              s2i_ASN1_INTEGER of the text (`-` for none, `_` for a space), then
 *                              i2s_ASN1_INTEGER and the octets of what it made, and the errors
 *   b64enc <chunk> <hex>       EVP_EncodeUpdate of the octets in chunks, then EVP_EncodeFinal, and
 *                              EVP_EncodeBlock of them all: each step's return and output
 *   b64dec <chunk> <hex>       EVP_DecodeUpdate of the text (in hex) in chunks, then
 *                              EVP_DecodeFinal, and EVP_DecodeBlock of it all
 *   b64bio <enc> <nonl> <chunk> <hex>   through BIO_f_base64 (BIO_FLAGS_BASE64_NO_NL if <nonl>):
 *                              writes the octets in chunks and flushes (enc 1), or reads the
 *                              text in chunks (enc 0); the results and the output
 *   pemread <flags> <hex>      PEM_read_bio_ex of the text (in hex) with <flags> until it fails:
 *                              each block's name, header, and data, then the errors
 *   paramset <fn> <type> <size> <null> <value>   OSSL_PARAM_set_<fn> (int32, uint32, int64,
 *                              uint64, double, int, uint, long, ulong, size_t, time_t) of the
 *                              value into a parameter of the type and size (data NULL if
 *                              <null>): the return, return_size, the data, and the errors;
 *                              cases where OpenSSL touches memory out of bounds print "skip"
 *   paramget <type> <hex>      every typed getter on a parameter of the type over the octets
 *                              (`-` for none): each return and value, and the errors
 *   paramstr <op> <size> <max> <hex>   op 0: OSSL_PARAM_get_utf8_string of <size> of the octets
 *                              into a buffer of <max>; 1: get_octet_string likewise; 2 and 3:
 *                              set_utf8_string (the octets up to a NUL) and set_octet_string
 *                              into a parameter of <size> octets (<max> 0: data NULL)
 *   parammerge <keys> <keys>   OSSL_PARAM_merge of two arrays of the comma-separated keys (`-`
 *                              for none): the merged keys and which array each came from
 *   tracestr <text> <full> <hex>   OSSL_trace_string to a memory BIO (`-` for no data), printing
 *                              the return and what it wrote; never full and masked past
 *                              OSSL_TRACE_STRING_MAX, where OpenSSL overflows its buffer
 *
 * Commands for library contexts, in four slots (a context is named by its slot, g for the
 * global default, `-` for NULL):
 *   ctxnew <slot>              OSSL_LIB_CTX_new into an empty slot
 *   ctxfree <slot>             OSSL_LIB_CTX_free; the slot stays filled if it was the default
 *   ctxfreeglobal              OSSL_LIB_CTX_free of the global default, while it's the default
 *   ctxdefault <name>          OSSL_LIB_CTX_set0_default: the previous default's name
 *   ctxmax <name> <n>          OSSL_set_max_threads, then OSSL_get_max_threads of every context
 *   ctxdiag <name> <n>         OSSL_LIB_CTX_set_conf_diagnostics, then every context's flag
 *   ctxexidx <class>           CRYPTO_get_ex_new_index in the class: the index
 *
 * Commands for default properties, in one library context of the probe's (`-` for an empty
 * query; a query is in hex):
 *   propnew                    a new context, so names are numbered afresh
 *   propset <hex>              EVP_set_default_properties (propset with no argument: NULL):
 *                              the return, the errors with their data, whether FIPS is
 *                              required, and EVP_get1_default_properties
 *   propfips <enable>          EVP_default_properties_enable_fips, then as propset
 *
 * Commands for providers, in one library context of the probe's, with eight slots for the
 * providers loaded (names: default, base, null, and ones no module exists for):
 *   pnew                       a new context
 *   pload <slot> <name>        OSSL_PROVIDER_load into an empty slot: loaded or NULL, and the
 *                              errors (codes; the data of CRYPTO's)
 *   ptry <slot> <name> <keep>  OSSL_PROVIDER_try_load, keeping the fallback if <keep>
 *   punload <slot>             OSSL_PROVIDER_unload, emptying the slot
 *   pavail <name>              OSSL_PROVIDER_available
 *   pall                       OSSL_PROVIDER_do_all: the names, in order; then which slots hold
 *                              the same provider as another, and the error libraries taken
 *   pparams <slot>             the provider's name, version, and status parameters
 * Each frees the thread's error state afterwards (OPENSSL_thread_stop), so no error slot keeps
 * a buffer sized by a module lookup's message, which differs between the libraries.
 *
 *   # ...              comment, echoed
 */
#define _POSIX_C_SOURCE 200809L
/* ERR_get_state is deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/stack.h>
#include <openssl/thread.h>
#include <openssl/trace.h>
#include <openssl/x509v3.h>

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
        case 9:
            bio = BIO_new(BIO_s_dgram_mem());
            break;
        case 10:
            if (!BIO_new_bio_dgram_pair(&bio, 0, &peer, 0))
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
        else if (strcmp(name, "wbufsize") == 0)
            ret = BIO_set_write_buf_size(bio, arg);
        else if (strcmp(name, "notrunc") == 0)
            ret = BIO_dgram_set_no_trunc(bio, (int)arg);
        else if (strcmp(name, "mtu") == 0)
            ret = BIO_dgram_set_mtu(bio, arg) + 1000 * BIO_dgram_get_mtu(bio);
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
    } else if (strcmp(command, "tracecat") == 0) {
        const char *name = OSSL_trace_get_category_name(other);

        printf("tracecat %d %s\n", OSSL_trace_get_category_num(text), name == NULL ? "(null)" : name);
    } else if (strcmp(command, "tracestr") == 0) {
        unsigned char data[256];
        char hex[600] = "-";
        size_t len = 0;
        BIO *mem = BIO_new(BIO_s_mem());
        char *out;
        long n;
        int text_mode = 0, full = 0, ret;

        sscanf(line, "%*s %d %d %599s", &text_mode, &full, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("tracestr bad hex\n");
            BIO_free(mem);
            return 1;
        }
        if (full && !text_mode && len > OSSL_TRACE_STRING_MAX)
            full = 0;
        ret = OSSL_trace_string(mem, text_mode, full, data, len);
        n = BIO_get_mem_data(mem, &out);
        print_escaped("tracestr", ret, out, (size_t)n);
        BIO_free(mem);
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

/* Prints OBJ_obj2txt of `o` with names and without, as `label`. */
static void print_obj_texts(const ASN1_OBJECT *o)
{
    char buf[700];
    int n;

    n = OBJ_obj2txt(buf, sizeof(buf), o, 0);
    printf(" txt=%d:%s", n, buf);
    n = OBJ_obj2txt(buf, sizeof(buf), o, 1);
    printf(" num=%d:%s", n, buf);
}

static void print_obj_error(void)
{
    unsigned long code = ERR_peek_last_error();

    printf(" err=%d/%d\n", ERR_GET_LIB(code), ERR_GET_REASON(code));
    ERR_clear_error();
}

/* Runs an object command; returns 0 if `command` isn't one. */
static int obj_command(const char *command, const char *line)
{
    char hex[600] = "-", text[300];
    unsigned char data[300];
    size_t len = 0;
    int other = 0;

    sscanf(line, "%*s %599s %d", hex, &other);
    if (strcmp(command, "objname") == 0) {
        printf("objname %d %d %d", OBJ_sn2nid(hex), OBJ_ln2nid(hex), OBJ_txt2nid(hex));
        print_obj_error();
        return 1;
    }
    if (strcmp(command, "objtxt") != 0 && strcmp(command, "objder") != 0)
        return 0;
    if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
        printf("%s bad hex\n", command);
        return 1;
    }
    if (strcmp(command, "objtxt") == 0) {
        ASN1_OBJECT *o;
        unsigned char out[300];
        int n;

        memcpy(text, data, len);
        text[len] = '\0';
        o = OBJ_txt2obj(text, other);
        printf("objtxt nid=%d", OBJ_obj2nid(o));
        if (o != NULL)
            print_obj_texts(o);
        ASN1_OBJECT_free(o);
        print_obj_error();
        n = a2d_ASN1_OBJECT(out, sizeof(out), text, -1);
        printf("a2d %d ", n);
        for (int i = 0; i < n; i++)
            printf("%02x", out[i]);
        printf(" measured=%d", a2d_ASN1_OBJECT(NULL, 0, text, -1));
        print_obj_error();
    } else {
        ASN1_OBJECT *o = ASN1_OBJECT_create(0, data, (int)len, NULL, NULL);
        BIO *mem = BIO_new(BIO_s_mem());
        char *out;
        long n;
        int ret;

        printf("objder nid=%d", OBJ_obj2nid(o));
        print_obj_texts(o);
        ret = i2a_ASN1_OBJECT(mem, o);
        n = BIO_get_mem_data(mem, &out);
        printf(" i2a=%d:", ret);
        for (long i = 0; i < n; i++)
            putchar(out[i] == '\n' ? '|' : out[i]);
        BIO_free(mem);
        ASN1_OBJECT_free(o);
        print_obj_error();
    }
    return 1;
}

static void print_asn_errors(void)
{
    unsigned long code;

    printf(" err=");
    while ((code = ERR_get_error()) != 0)
        printf("%d/%d,", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

/* Runs an ASN.1 header command; returns 0 if `command` isn't one. */
static int asn_command(const char *command, const char *line)
{
    char hex[600] = "-";
    unsigned char data[300];
    size_t len = 0;

    if (strcmp(command, "asnput") == 0) {
        unsigned char buf[32], *p = buf;
        int cons = 0, length = 0, tag = 0, xclass = 0;

        sscanf(line, "%*s %d %d %d %d", &cons, &length, &tag, &xclass);
        ASN1_put_object(&p, cons, length, tag, xclass);
        printf("asnput size=%d", ASN1_object_size(cons, length, tag));
        print_hex("", buf, (size_t)(p - buf));
        return 1;
    }
    if (strcmp(command, "asnhdr") != 0 && strcmp(command, "d2iobj") != 0)
        return 0;
    int delta = 0;

    sscanf(line, "%*s %599s %d", hex, &delta);
    if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
        printf("%s bad hex\n", command);
        return 1;
    }
    if (strcmp(command, "asnhdr") == 0) {
        const unsigned char *p = data;
        long length = -7, omax = (long)len + delta;
        int tag = -7, xclass = -7, ret;

        /* More than the octets is fine only when the header ends within them. */
        if (delta > 0) {
            long probe_len = -7;
            int probe_tag, probe_class;
            const unsigned char *q = data;

            if (len == 0 || ASN1_get_object(&q, &probe_len, &probe_tag, &probe_class, (long)len) & 0x80)
                omax = (long)len;
            ERR_clear_error();
        }
        ret = ASN1_get_object(&p, &length, &tag, &xclass, omax);
        printf("asnhdr ret=%#x tag=%d class=%d length=%ld used=%d", ret, tag, xclass, length, (int)(p - data));
        print_asn_errors();
    } else {
        const unsigned char *p = data;
        ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, (long)len);
        unsigned char out[300], *q = out;
        char text[700] = "";
        int n = 0;

        if (o != NULL) {
            OBJ_obj2txt(text, sizeof(text), o, 1);
            n = i2d_ASN1_OBJECT(o, &q);
        }
        printf("d2iobj %s nid=%d text=%s used=%d", o == NULL ? "NULL" : "ok", OBJ_obj2nid(o), text, (int)(p - data));
        print_hex(" i2d", out, n > 0 ? (size_t)n : 0);
        if (o != NULL && o != OBJ_nid2obj(OBJ_obj2nid(o)))
            ASN1_OBJECT_free(o);
        printf("d2iobj");
        print_asn_errors();
    }
    return 1;
}

/* Runs an INTEGER command; returns 0 if `command` isn't one. */
static int int_command(const char *command, const char *line)
{
    char hex[700] = "-";
    unsigned char data[300];
    size_t len = 0;
    int number = 0;

    if (strcmp(command, "asnset") == 0) {
        long long value = 0;
        ASN1_INTEGER *a = ASN1_INTEGER_new();

        sscanf(line, "%*s %lld", &value);
        printf("asnset %d type=%d", ASN1_INTEGER_set_int64(a, (int64_t)value), a->type);
        print_hex("", a->data, (size_t)a->length);
        ASN1_INTEGER_free(a);
        return 1;
    }
    if (strcmp(command, "asnint") != 0 && strcmp(command, "a2iint") != 0 && strcmp(command, "a2istr") != 0)
        return 0;
    sscanf(line, "%*s %d %699s", &number, hex);
    if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
        printf("%s bad hex\n", command);
        return 1;
    }
    if (strcmp(command, "asnint") == 0) {
        ASN1_STRING *s = ASN1_STRING_type_new(number);
        BIO *mem = BIO_new(BIO_s_mem());
        int64_t v = -7;
        uint64_t u = 7;
        char *out;
        long n;
        int r1, r2;

        ASN1_STRING_set(s, data, (int)len);
        r1 = ASN1_INTEGER_get_int64(&v, s);
        r2 = ASN1_INTEGER_get_uint64(&u, s);
        printf("asnint %d:%lld %d:%llu %ld %ld i2a=%d:", r1, (long long)v, r2, (unsigned long long)u,
               ASN1_INTEGER_get(s), ASN1_ENUMERATED_get(s), i2a_ASN1_INTEGER(mem, s));
        n = BIO_get_mem_data(mem, &out);
        fwrite(out, 1, (size_t)n, stdout);
        print_asn_errors();
        BIO_free(mem);
        ASN1_STRING_free(s);
    } else {
        BIO *in = BIO_new(BIO_s_mem());
        ASN1_INTEGER *a = ASN1_INTEGER_new();
        char buf[300];
        int r;

        if (number < 0 || number > 300)
            number = 300;
        BIO_write(in, data, (int)len);
        memset(buf, 'x', sizeof(buf));
        r = strcmp(command, "a2istr") == 0 ? a2i_ASN1_STRING(in, a, buf, number) : a2i_ASN1_INTEGER(in, a, buf, number);
        printf("%s %d type=%d", command, r, a->type);
        print_hex("", a->data, (size_t)a->length);
        print_escaped(" buf", 0, buf, number > 0 ? (size_t)number : 0);
        if (r == 1 && strcmp(command, "a2istr") == 0) {
            BIO *mem = BIO_new(BIO_s_mem());
            char *out;
            long n;

            r = i2a_ASN1_STRING(mem, a, V_ASN1_OCTET_STRING);
            n = BIO_get_mem_data(mem, &out);
            print_escaped(" i2a", r, out, (size_t)n);
            BIO_free(mem);
        }
        printf("%s", command);
        print_asn_errors();
        ASN1_INTEGER_free(a);
        BIO_free(in);
    }
    return 1;
}

/* Runs a BIT STRING command; returns 0 if `command` isn't one. */
static int bit_command(const char *command, const char *line)
{
    char hex[600] = "-", flags_hex[600] = "-";
    unsigned char data[300], flags[300];
    size_t len = 0, flags_len = 0;
    int n = 0, value = 0, r;
    ASN1_BIT_STRING *s;

    if (strcmp(command, "asnbit") != 0)
        return 0;
    sscanf(line, "%*s %599s %d %d %599s", hex, &n, &value, flags_hex);
    if ((strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len))
        || (strcmp(flags_hex, "-") != 0 && !parse_hex(flags_hex, flags, &flags_len))) {
        printf("asnbit bad hex\n");
        return 1;
    }
    s = ASN1_BIT_STRING_new();
    if (len > 0)
        ASN1_BIT_STRING_set(s, data, (int)len);
    s->flags = ASN1_STRING_FLAG_BITS_LEFT | 5;
    r = ASN1_BIT_STRING_set_bit(s, n, value);
    printf("asnbit %d flags=%#lx get=%d,%d,%d check=%d", r, s->flags, ASN1_BIT_STRING_get_bit(s, n - 1),
           ASN1_BIT_STRING_get_bit(s, n), ASN1_BIT_STRING_get_bit(s, n + 1),
           ASN1_BIT_STRING_check(s, flags, (int)flags_len));
    print_hex("", s->data, (size_t)s->length);
    ASN1_BIT_STRING_free(s);
    return 1;
}

/* Runs a character-string command; returns 0 if `command` isn't one. */
static int text_command(const char *command, const char *line)
{
    char hex[700] = "-";
    unsigned char data[300];
    size_t len = 0;

    if (strcmp(command, "asntext") == 0) {
        int type = 0;
        unsigned long flags = 0;
        ASN1_STRING *s;
        BIO *mem = BIO_new(BIO_s_mem());
        unsigned char *utf8 = NULL;
        char *out;
        long n;
        int r, counted;

        sscanf(line, "%*s %d %lx %699s", &type, &flags, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asntext bad hex\n");
            BIO_free(mem);
            return 1;
        }
        s = ASN1_STRING_type_new(type);
        ASN1_STRING_set(s, data, (int)len);
        r = ASN1_STRING_print_ex(mem, s, flags);
        counted = ASN1_STRING_print_ex(NULL, s, flags);
        n = BIO_get_mem_data(mem, &out);
        print_escaped("asntext", r, out, n > 0 ? (size_t)n : 0);
        printf("asntext counted=%d", counted);
        r = ASN1_STRING_to_UTF8(&utf8, s);
        print_escaped(" utf8", r, (const char *)utf8, r > 0 ? (size_t)r : 0);
        printf("asntext");
        print_asn_errors();
        OPENSSL_free(utf8);
        ASN1_STRING_free(s);
        BIO_free(mem);
        return 1;
    }
    if (strcmp(command, "asnmb") == 0) {
        int inform = 0, r;
        unsigned long mask = 0;
        long min = 0, max = 0;
        ASN1_STRING *out = NULL;

        sscanf(line, "%*s %x %lx %ld %ld %699s", &inform, &mask, &min, &max, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asnmb bad hex\n");
            return 1;
        }
        r = ASN1_mbstring_ncopy(&out, data, (int)len, inform, mask, min, max);
        printf("asnmb %d", r);
        if (out != NULL) {
            printf(" type=%d", out->type);
            print_hex("", out->data, (size_t)out->length);
        } else {
            printf("\n");
        }
        printf("asnmb");
        print_asn_errors();
        ASN1_STRING_free(out);
        return 1;
    }
    return 0;
}

/* Encodes `der` as a new buffer, printing its length and octets after `label`. */
static void print_i2d(const char *label, int len, unsigned char *der)
{
    printf(" %s=%d", label, len);
    if (len > 0) {
        printf(":");
        for (int i = 0; i < len; i++)
            printf("%02x", der[i]);
    }
    OPENSSL_free(der);
}

/* An application type for asnd2i: most kinds of field, a CHOICE, ANY DEFINED BY, and itself. */
typedef struct {
    int type;
    union {
        ASN1_INTEGER *num;
        ASN1_UTF8STRING *str;
    } d;
} PROBEPICK;

ASN1_CHOICE(PROBEPICK) = {
    ASN1_SIMPLE(PROBEPICK, d.num, ASN1_INTEGER),
    ASN1_EXP(PROBEPICK, d.str, ASN1_UTF8STRING, 3)
} ASN1_CHOICE_END(PROBEPICK)

typedef struct PROBEREC_st PROBEREC;
struct PROBEREC_st {
    ASN1_OBJECT *type;
    void *value;
    ASN1_OCTET_STRING *opt;
    ASN1_IA5STRING *imp;
    ASN1_BOOLEAN flag;
    STACK_OF(ASN1_TYPE) *set;
    PROBEPICK *pick;
    int64_t i64;
    PROBEREC *inner;
};
DECLARE_ASN1_ITEM(PROBEREC)

ASN1_ADB_TEMPLATE(PROBEREC_default) = ASN1_SIMPLE(PROBEREC, value, ASN1_ANY);

ASN1_ADB(PROBEREC) = {
    ADB_ENTRY(NID_sha256, ASN1_SIMPLE(PROBEREC, value, ASN1_INTEGER)),
    ADB_ENTRY(NID_sha1, ASN1_OPT(PROBEREC, value, ASN1_UTF8STRING))
} ASN1_ADB_END(PROBEREC, 0, type, 0, &PROBEREC_default_tt, NULL);

ASN1_SEQUENCE(PROBEREC) = {
    ASN1_SIMPLE(PROBEREC, type, ASN1_OBJECT),
    ASN1_ADB_OBJECT(PROBEREC),
    ASN1_EXP_OPT(PROBEREC, opt, ASN1_OCTET_STRING, 0),
    ASN1_IMP_OPT(PROBEREC, imp, ASN1_IA5STRING, 1),
    ASN1_OPT(PROBEREC, flag, ASN1_FBOOLEAN),
    ASN1_SET_OF_OPT(PROBEREC, set, ASN1_ANY),
    ASN1_OPT(PROBEREC, pick, PROBEPICK),
    ASN1_IMP_EX(PROBEREC, i64, INT64, 4, ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED),
    ASN1_EXP_OPT(PROBEREC, inner, PROBEREC, 2)
} ASN1_SEQUENCE_END(PROBEREC)

static const ASN1_ITEM *probe_item(int n)
{
    switch (n) {
    case 0: return ASN1_ITEM_rptr(ASN1_ANY);
    case 1: return ASN1_ITEM_rptr(ASN1_SEQUENCE_ANY);
    case 2: return ASN1_ITEM_rptr(ASN1_SET_ANY);
    case 3: return ASN1_ITEM_rptr(ASN1_OCTET_STRING);
    case 4: return ASN1_ITEM_rptr(ASN1_INTEGER);
    case 5: return ASN1_ITEM_rptr(ASN1_BIT_STRING);
    case 6: return ASN1_ITEM_rptr(ASN1_BMPSTRING);
    case 7: return ASN1_ITEM_rptr(ASN1_TIME);
    case 8: return ASN1_ITEM_rptr(DIRECTORYSTRING);
    case 9: return ASN1_ITEM_rptr(INT64);
    case 10: return ASN1_ITEM_rptr(UINT32);
    case 11: return ASN1_ITEM_rptr(PROBEREC);
    case 12: return ASN1_ITEM_rptr(ASN1_SEQUENCE);
    default: return ASN1_ITEM_rptr(ASN1_UTF8STRING);
    }
}

/* Runs a template engine command; returns 0 if `command` isn't one. */
static int template_command(const char *command, const char *line)
{
    if (strcmp(command, "pemread") == 0) {
        char hex[700] = "-";
        unsigned char data[300];
        size_t len = 0;
        unsigned int flags = 0;
        BIO *in;
        char *name, *header;
        unsigned char *body;
        long blen;
        int r;
        unsigned long code;

        sscanf(line, "%*s %u %699s", &flags, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("pemread bad hex\n");
            return 1;
        }
        flags &= ~(unsigned int)PEM_FLAG_SECURE;
        in = BIO_new_mem_buf(data, (int)len);
        while ((r = PEM_read_bio_ex(in, &name, &header, &body, &blen, flags)) == 1) {
            print_escaped("pemread name", 1, name, strlen(name));
            print_escaped("pemread header", 1, header, strlen(header));
            print_escaped("pemread data", (int)blen, (char *)body, (size_t)blen);
            OPENSSL_free(name);
            OPENSSL_free(header);
            OPENSSL_free(body);
        }
        printf("pemread %d left %d", r, (int)BIO_pending(in));
        while ((code = ERR_get_error()) != 0)
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        printf("\n");
        BIO_free(in);
        return 1;
    }
    if (strcmp(command, "b64bio") == 0) {
        char hex[700] = "-";
        unsigned char data[300], out[1200];
        size_t len = 0;
        int enc = 0, nonl = 0, chunk = 1, r, total = 0;
        BIO *mem, *b64 = BIO_new(BIO_f_base64());
        char *text;
        long n;

        sscanf(line, "%*s %d %d %d %699s", &enc, &nonl, &chunk, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("b64bio bad hex\n");
            BIO_free(b64);
            return 1;
        }
        if (chunk < 1)
            chunk = 1;
        if (nonl)
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        printf("b64bio");
        if (enc) {
            size_t i;

            mem = BIO_new(BIO_s_mem());
            BIO_push(b64, mem);
            for (i = 0; i < len; i += (size_t)chunk)
                printf(" %d", BIO_write(b64, data + i, len - i < (size_t)chunk ? (int)(len - i) : chunk));
            printf(" wpending %ld flush %d", (long)BIO_wpending(b64), BIO_flush(b64));
            n = BIO_get_mem_data(mem, &text);
            print_escaped(" out", 0, text, (size_t)n);
        } else {
            mem = BIO_new_mem_buf(data, (int)len);
            BIO_push(b64, mem);
            while ((r = BIO_read(b64, out + total, chunk)) > 0 && total < 900)
                total += r;
            printf(" last %d eof %d", r, (int)BIO_eof(b64));
            print_hex("", out, (size_t)total);
        }
        BIO_free_all(b64);
        ERR_clear_error();
        return 1;
    }
    if (strcmp(command, "b64enc") == 0 || strcmp(command, "b64dec") == 0) {
        char hex[700] = "-";
        unsigned char data[300], out[1200];
        size_t len = 0, i;
        int chunk = 1, outl, r;
        int enc = strcmp(command, "b64enc") == 0;
        EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();

        sscanf(line, "%*s %d %699s", &chunk, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("%s bad hex\n", command);
            EVP_ENCODE_CTX_free(ctx);
            return 1;
        }
        if (chunk < 1)
            chunk = 1;
        printf("%s", command);
        if (enc)
            EVP_EncodeInit(ctx);
        else
            EVP_DecodeInit(ctx);
        for (i = 0; i < len || i == 0; i += (size_t)chunk) {
            int n = len - i < (size_t)chunk ? (int)(len - i) : chunk;

            memset(out, 0xee, sizeof(out));
            r = enc ? EVP_EncodeUpdate(ctx, out, &outl, data + i, n) : EVP_DecodeUpdate(ctx, out, &outl, data + i, n);
            printf(" [%d %d num=%d", r, outl, EVP_ENCODE_CTX_num(ctx));
            print_hex("", out, (size_t)(outl > 0 ? outl + 1 : 0));
            printf("]");
            if (len == 0 || (!enc && r < 0))
                break;
        }
        memset(out, 0xee, sizeof(out));
        if (enc) {
            EVP_EncodeFinal(ctx, out, &outl);
            r = 1;
        } else {
            r = EVP_DecodeFinal(ctx, out, &outl);
        }
        printf(" final %d %d", r, outl);
        print_hex("", out, (size_t)(outl > 0 ? outl + 1 : 0));
        memset(out, 0xee, sizeof(out));
        r = enc ? EVP_EncodeBlock(out, data, (int)len) : EVP_DecodeBlock(out, data, (int)len);
        printf(" block %d", r);
        print_hex("", out, (size_t)(r > 0 ? r + 1 : 0));
        printf("\n");
        EVP_ENCODE_CTX_free(ctx);
        return 1;
    }
    if (strcmp(command, "asns2i") == 0) {
        char text[300] = "";
        ASN1_INTEGER *a;
        char *s;
        unsigned long code;
        int i;

        sscanf(line, "%*s %299s", text);
        if (strcmp(text, "-") == 0)
            text[0] = '\0';
        for (i = 0; text[i] != '\0'; i++)
            if (text[i] == '_')
                text[i] = ' ';
        a = s2i_ASN1_INTEGER(NULL, text);
        if (a != NULL) {
            s = i2s_ASN1_INTEGER(NULL, a);
            printf("asns2i %s type=%d", s != NULL ? s : "NULL", a->type);
            print_hex("", a->data, (size_t)a->length);
            OPENSSL_free(s);
            ASN1_INTEGER_free(a);
        } else {
            printf("asns2i NULL\n");
        }
        printf("asns2i errors:");
        while ((code = ERR_get_error()) != 0)
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        printf("\n");
        return 1;
    }
    if (strcmp(command, "asnparse") == 0) {
        char hex[700] = "-";
        unsigned char data[300];
        size_t len = 0;
        int indent = 0, dump = 0, r;
        BIO *mem = BIO_new(BIO_s_mem());
        char *out;
        long outlen;
        unsigned long code;

        sscanf(line, "%*s %d %d %699s", &indent, &dump, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asnparse bad hex\n");
            BIO_free(mem);
            return 1;
        }
        r = dump < -1 ? ASN1_parse(mem, data, (long)len, indent) : ASN1_parse_dump(mem, data, (long)len, indent, dump);
        outlen = BIO_get_mem_data(mem, &out);
        print_escaped("asnparse", r, out, (size_t)outlen);
        printf("asnparse errors:");
        while ((code = ERR_get_error()) != 0)
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        printf("\n");
        BIO_free(mem);
        return 1;
    }
    if (strcmp(command, "asnbio") == 0) {
        char hex[700] = "-";
        unsigned char data[300], *der;
        size_t len = 0;
        int i, dlen;
        BIO *b;
        ASN1_VALUE *v;
        unsigned long code;
        const char *edata;
        int eflags;

        sscanf(line, "%*s %699s", hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asnbio bad hex\n");
            return 1;
        }
        b = BIO_new_mem_buf(data, (int)len);
        printf("asnbio");
        while ((v = ASN1_item_d2i_bio(ASN1_ITEM_rptr(ASN1_ANY), b, NULL)) != NULL) {
            der = NULL;
            dlen = ASN1_item_i2d(v, &der, ASN1_ITEM_rptr(ASN1_ANY));
            printf(" %d:", dlen);
            for (i = 0; i < dlen; i++)
                printf("%02x", der[i]);
            OPENSSL_free(der);
            ASN1_item_free(v, ASN1_ITEM_rptr(ASN1_ANY));
        }
        printf(" left=%d", (int)BIO_pending(b));
        while ((code = ERR_get_error_all(NULL, NULL, NULL, &edata, &eflags)) != 0) {
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
            if ((eflags & ERR_TXT_STRING) != 0 && edata[0] != '\0')
                printf("[%s]", edata);
        }
        printf("\n");
        BIO_free(b);
        return 1;
    }
    if (strcmp(command, "asnd2i") == 0) {
        char hex[700] = "-";
        unsigned char data[300], *der = NULL;
        const unsigned char *q = data;
        size_t len = 0;
        int n = 0, i;
        const ASN1_ITEM *it;
        ASN1_VALUE *v;
        unsigned long code;
        const char *edata;
        int eflags;

        sscanf(line, "%*s %d %699s", &n, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asnd2i bad hex\n");
            return 1;
        }
        it = probe_item(n);
        v = ASN1_item_d2i(NULL, &q, (long)len, it);
        if (v != NULL) {
            int dlen = ASN1_item_i2d(v, &der, it);

            BIO *mem = BIO_new(BIO_s_mem());
            char *text;
            long tlen;
            int r;

            printf("asnd2i ok used=%ld der=%d:", (long)(q - data), dlen);
            for (i = 0; i < dlen; i++)
                printf("%02x", der[i]);
            OPENSSL_free(der);
            r = ASN1_item_print(mem, v, 2, it, NULL);
            tlen = BIO_get_mem_data(mem, &text);
            print_escaped(" print", r, text, (size_t)tlen);
            BIO_free(mem);
            ASN1_item_free(v, it);
        } else {
            printf("asnd2i fail used=%ld", (long)(q - data));
        }
        while ((code = ERR_get_error_all(NULL, NULL, NULL, &edata, &eflags)) != 0) {
            printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
            if ((eflags & ERR_TXT_STRING) != 0 && edata[0] != '\0')
                printf("[%s]", edata);
        }
        printf("\n");
        return 1;
    }
    if (strcmp(command, "asnany") == 0) {
        STACK_OF(ASN1_TYPE) *sk = sk_ASN1_TYPE_new_null();
        const char *p = line + strlen(command);
        char item[600];
        int n, offset;
        unsigned char *der;

        printf("asnany");
        while (sk_ASN1_TYPE_num(sk) < 8 && sscanf(p, " %599s%n", item, &offset) == 1) {
            unsigned char data[300];
            size_t len = 0;
            int type = 0;
            char *colon = strchr(item, ':');
            ASN1_TYPE *t = ASN1_TYPE_new();

            p += offset;
            if (colon == NULL || sscanf(item, "%d", &type) != 1
                || (strcmp(colon + 1, "-") != 0 && !parse_hex(colon + 1, data, &len))) {
                printf(" bad");
                ASN1_TYPE_free(t);
                continue;
            }
            if (type == V_ASN1_BOOLEAN) {
                ASN1_TYPE_set(t, type, len > 0 && data[0] != 0 ? (void *)1 : NULL);
            } else if (type == V_ASN1_NULL) {
                ASN1_TYPE_set(t, type, NULL);
            } else if (type == V_ASN1_OBJECT) {
                unsigned char object[310];
                const unsigned char *q = object;
                ASN1_OBJECT *o;

                object[0] = V_ASN1_OBJECT;
                object[1] = (unsigned char)len;
                memcpy(object + 2, data, len);
                o = len < 128 ? d2i_ASN1_OBJECT(NULL, &q, (long)len + 2) : NULL;
                if (o == NULL) {
                    printf(" noobj");
                    ASN1_TYPE_free(t);
                    ERR_clear_error();
                    continue;
                }
                ASN1_TYPE_set(t, type, o);
            } else {
                ASN1_STRING *str = ASN1_STRING_type_new(type == -2 ? V_ASN1_NEG_INTEGER : type);

                ASN1_STRING_set(str, data, (int)len);
                ASN1_TYPE_set(t, type == -2 ? V_ASN1_INTEGER : type, str);
            }
            der = NULL;
            n = i2d_ASN1_TYPE(t, &der);
            print_i2d("e", n, der);
            sk_ASN1_TYPE_push(sk, t);
        }
        der = NULL;
        n = i2d_ASN1_SEQUENCE_ANY(sk, &der);
        print_i2d("seq", n, der);
        der = NULL;
        n = i2d_ASN1_SET_ANY(sk, &der);
        print_i2d("set", n, der);
        printf(" measured=%d,%d\n", i2d_ASN1_SEQUENCE_ANY(sk, NULL), i2d_ASN1_SET_ANY(sk, NULL));
        sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
        ERR_clear_error();
        return 1;
    }
    return 0;
}

/* Runs a time command; returns 0 if `command` isn't one. */
static int time_command(const char *command, const char *line)
{
    if (strcmp(command, "asntime") == 0) {
        char hex[700] = "-";
        unsigned char data[300];
        size_t len = 0;
        int type = 0, day = 7, sec = 7, r;
        long flags = 0;
        ASN1_STRING *s, *n, *fixed = ASN1_STRING_new();
        BIO *mem = BIO_new(BIO_s_mem());
        struct tm tm;
        char *out;
        long outlen;

        sscanf(line, "%*s %d %lx %699s", &type, &flags, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("asntime bad hex\n");
            BIO_free(mem);
            ASN1_STRING_free(fixed);
            return 1;
        }
        s = ASN1_STRING_type_new(type);
        ASN1_STRING_set(s, data, (int)len);
        s->flags = flags;
        memset(&tm, 0, sizeof(tm));
        r = ASN1_TIME_to_tm(s, &tm);
        printf("asntime check=%d,%d,%d tm=%d %d-%d-%d %d:%d:%d %d %d", ASN1_TIME_check(s), ASN1_UTCTIME_check(s),
               ASN1_GENERALIZEDTIME_check(s), r, tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
               tm.tm_wday, tm.tm_yday);
        r = ASN1_TIME_print(mem, s);
        BIO_puts(mem, "|");
        r = r * 10 + ASN1_TIME_print_ex(mem, s, ASN1_DTFLGS_ISO8601);
        outlen = BIO_get_mem_data(mem, &out);
        print_escaped(" print", r, out, (size_t)outlen);
        ASN1_TIME_set_string(fixed, "20240229123456Z");
        r = ASN1_TIME_diff(&day, &sec, fixed, s);
        printf("asntime diff=%d %d %d cmp=%d", r, day, sec, ASN1_TIME_compare(s, fixed));
        n = ASN1_STRING_dup(s);
        r = ASN1_TIME_normalize(n);
        printf(" normalize=%d type=%d", r, n->type);
        print_hex("", n->data, n->length > 0 ? (size_t)n->length : 0);
        ASN1_STRING_free(n);
        ASN1_STRING_free(s);
        ASN1_STRING_free(fixed);
        BIO_free(mem);
        ERR_clear_error();
        return 1;
    }
    if (strcmp(command, "asntimet") == 0) {
        long long when = 0;
        int days = 0;
        long secs = 0;
        time_t t;
        ASN1_STRING *a, *u, *g;
        struct tm tm;

        sscanf(line, "%*s %lld %d %ld", &when, &days, &secs);
        t = (time_t)when;
        a = ASN1_TIME_adj(NULL, t, days, secs);
        u = ASN1_UTCTIME_adj(NULL, t, days, secs);
        g = ASN1_GENERALIZEDTIME_adj(NULL, t, days, secs);
        printf("asntimet %s %s %s", a ? (a->length > 0 ? (char *)a->data : "-1") : "NULL",
               u ? (char *)u->data : "NULL", g ? (g->length > 0 ? (char *)g->data : "-1") : "NULL");
        memset(&tm, 0, sizeof(tm));
        if (OPENSSL_gmtime(&t, &tm) != NULL) {
            int r = OPENSSL_gmtime_adj(&tm, days, secs);

            printf(" gmtime_adj=%d %d-%d-%d %d:%d:%d", r, tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min,
                   tm.tm_sec);
        }
        printf("\n");
        ASN1_STRING_free(a);
        ASN1_STRING_free(u);
        ASN1_STRING_free(g);
        ERR_clear_error();
        return 1;
    }
    return 0;
}

/* Runs an error-queue command; returns 0 if `command` isn't one. */
static void print_octets(const unsigned char *data, size_t len)
{
    printf(" ");
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static void print_param_errors(void)
{
    unsigned long code;

    printf(" errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void print_return_size(size_t n)
{
    if (n == OSSL_PARAM_UNMODIFIED)
        printf(" return unmodified");
    else
        printf(" return %zu", n);
}

static int params_command(const char *command, const char *line)
{
    if (strcmp(command, "paramset") == 0) {
        char fn[16] = "", value[64] = "0";
        unsigned int type = 0;
        size_t size = 0;
        int null = 0, r = 0;
        unsigned char data[40];
        OSSL_PARAM p = { "p", 0, NULL, 0, 12345 };
        long long sv;
        unsigned long long uv;
        double dv;

        sscanf(line, "%*s %15s %u %zu %d %63s", fn, &type, &size, &null, value);
        sv = strtoll(value, NULL, 0);
        uv = strtoull(value, NULL, 0);
        dv = strtod(value, NULL);
        if (size > 32)
            size = 32;
        memset(data, 0xaa, sizeof(data));
        p.data_type = type;
        p.data_size = size;
        p.data = null ? NULL : data;
        printf("paramset %s %u %zu %d %s:", fn, type, size, null, value);
        /* OpenSSL reads before a value narrowed to nothing, and writes a real through NULL. */
        if ((type == OSSL_PARAM_INTEGER && size == 0 && !null)
            || (type == OSSL_PARAM_REAL && size == 8 && null
                && (strcmp(fn, "uint64") == 0 || strcmp(fn, "ulong") == 0 || strcmp(fn, "size_t") == 0))
            || (strcmp(fn, "double") == 0 && (dv == 9223372036854775808.0 || dv == -9223372036854775808.0
                                              || dv == 18446744073709551616.0))) {
            printf(" skip\n");
            return 1;
        }
        if (strcmp(fn, "int32") == 0)
            r = OSSL_PARAM_set_int32(&p, (int32_t)sv);
        else if (strcmp(fn, "uint32") == 0)
            r = OSSL_PARAM_set_uint32(&p, (uint32_t)uv);
        else if (strcmp(fn, "int64") == 0)
            r = OSSL_PARAM_set_int64(&p, (int64_t)sv);
        else if (strcmp(fn, "uint64") == 0)
            r = OSSL_PARAM_set_uint64(&p, (uint64_t)uv);
        else if (strcmp(fn, "double") == 0)
            r = OSSL_PARAM_set_double(&p, dv);
        else if (strcmp(fn, "int") == 0)
            r = OSSL_PARAM_set_int(&p, (int)sv);
        else if (strcmp(fn, "uint") == 0)
            r = OSSL_PARAM_set_uint(&p, (unsigned int)uv);
        else if (strcmp(fn, "long") == 0)
            r = OSSL_PARAM_set_long(&p, (long)sv);
        else if (strcmp(fn, "ulong") == 0)
            r = OSSL_PARAM_set_ulong(&p, (unsigned long)uv);
        else if (strcmp(fn, "size_t") == 0)
            r = OSSL_PARAM_set_size_t(&p, (size_t)uv);
        else if (strcmp(fn, "time_t") == 0)
            r = OSSL_PARAM_set_time_t(&p, (time_t)sv);
        printf(" %d", r);
        print_return_size(p.return_size);
        if (!null)
            print_octets(data, size);
        print_param_errors();
        return 1;
    }
    if (strcmp(command, "paramget") == 0) {
        char hex[700] = "-";
        unsigned char data[300];
        size_t len = 0;
        unsigned int type = 0;
        OSSL_PARAM p = { "p", 0, NULL, 0, 0 };
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        double d;
        int r;

        sscanf(line, "%*s %u %699s", &type, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("paramget bad hex\n");
            return 1;
        }
        printf("paramget %u %s:", type, hex);
        if (type == OSSL_PARAM_INTEGER && len == 0) {
            printf(" skip\n");
            return 1;
        }
        p.data_type = type;
        p.data = data;
        p.data_size = len;
        r = OSSL_PARAM_get_int32(&p, &i32);
        printf(" int32 %d %d", r, r ? i32 : 0);
        r = OSSL_PARAM_get_uint32(&p, &u32);
        printf(" uint32 %d %u", r, r ? u32 : 0);
        r = OSSL_PARAM_get_int64(&p, &i64);
        printf(" int64 %d %lld", r, r ? (long long)i64 : 0);
        r = OSSL_PARAM_get_uint64(&p, &u64);
        printf(" uint64 %d %llu", r, r ? (unsigned long long)u64 : 0);
        r = OSSL_PARAM_get_double(&p, &d);
        printf(" double %d %.17g", r, r ? d : 0);
        print_param_errors();
        return 1;
    }
    if (strcmp(command, "paramstr") == 0) {
        char hex[700] = "-";
        unsigned char data[300], out[300];
        size_t len = 0, size = 0, max = 0, used = 99;
        int op = 0, r;
        OSSL_PARAM p = { "p", 0, NULL, 0, 12345 };
        void *buf = out;

        sscanf(line, "%*s %d %zu %zu %699s", &op, &size, &max, hex);
        if (strcmp(hex, "-") != 0 && !parse_hex(hex, data, &len)) {
            printf("paramstr bad hex\n");
            return 1;
        }
        if (max > sizeof(out))
            max = sizeof(out);
        if (size > sizeof(out))
            size = sizeof(out);
        memset(out, 0xaa, sizeof(out));
        printf("paramstr %d %zu %zu %s:", op, size, max, hex);
        if (op == 0 || op == 1) {
            if (size > len)
                size = len;
            p.data_type = op == 0 ? OSSL_PARAM_UTF8_STRING : OSSL_PARAM_OCTET_STRING;
            p.data = data;
            p.data_size = size;
            if (op == 0)
                r = OSSL_PARAM_get_utf8_string(&p, (char **)&buf, max);
            else
                r = OSSL_PARAM_get_octet_string(&p, &buf, max, &used);
            printf(" %d used %zu", r, used);
            print_octets(out, max + 1 < sizeof(out) ? max + 1 : max);
        } else {
            data[len < sizeof(data) ? len : sizeof(data) - 1] = '\0';
            p.data_type = op == 2 ? OSSL_PARAM_UTF8_STRING : OSSL_PARAM_OCTET_STRING;
            p.data = max == 0 ? NULL : out;
            p.data_size = size;
            if (op == 2)
                r = OSSL_PARAM_set_utf8_string(&p, (const char *)data);
            else
                r = OSSL_PARAM_set_octet_string(&p, data, len);
            printf(" %d", r);
            print_return_size(p.return_size);
            print_octets(out, size + 1 < sizeof(out) ? size + 1 : size);
        }
        print_param_errors();
        return 1;
    }
    if (strcmp(command, "parammerge") == 0) {
        char lists[2][300] = { "-", "-" };
        OSSL_PARAM arrays[2][40];
        int values[2][40];
        OSSL_PARAM *m, *q;
        int a;

        sscanf(line, "%*s %299s %299s", lists[0], lists[1]);
        printf("parammerge %s %s:", lists[0], lists[1]);
        for (a = 0; a < 2; a++) {
            int n = 0;
            char *key = strcmp(lists[a], "-") == 0 ? NULL : strtok(lists[a], ",");

            for (; key != NULL && n < 39; key = strtok(NULL, ",")) {
                values[a][n] = a * 100 + n;
                arrays[a][n] = OSSL_PARAM_construct_int(key, &values[a][n]);
                n++;
            }
            arrays[a][n] = OSSL_PARAM_construct_end();
        }
        m = OSSL_PARAM_merge(arrays[0], arrays[1]);
        if (m == NULL)
            printf(" NULL");
        for (q = m; q != NULL && q->key != NULL; q++)
            printf(" %s=%d", q->key, *(int *)q->data);
        OSSL_PARAM_free(m);
        print_param_errors();
        return 1;
    }
    return 0;
}

static OSSL_LIB_CTX *ctx_slots[4];

static OSSL_LIB_CTX *ctx_named(const char *name, int *ok)
{
    *ok = 1;
    if (strcmp(name, "-") == 0)
        return NULL;
    if (strcmp(name, "g") == 0)
        return OSSL_LIB_CTX_get0_global_default();
    if (name[0] >= '0' && name[0] <= '3' && name[1] == '\0' && ctx_slots[name[0] - '0'] != NULL)
        return ctx_slots[name[0] - '0'];
    *ok = 0;
    return NULL;
}

static void print_ctx_name(OSSL_LIB_CTX *ctx)
{
    int i;

    if (ctx == NULL) {
        printf(" NULL");
        return;
    }
    if (ctx == OSSL_LIB_CTX_get0_global_default()) {
        printf(" g");
        return;
    }
    for (i = 0; i < 4; i++)
        if (ctx == ctx_slots[i]) {
            printf(" %d", i);
            return;
        }
    printf(" other");
}

static int ctx_command(const char *command, const char *line)
{
    char name[16] = "-";
    long long n = 0;
    int slot = -1, ok, i;
    OSSL_LIB_CTX *ctx;

    if (strncmp(command, "ctx", 3) != 0)
        return 0;
    sscanf(line, "%*s %15s %lld", name, &n);
    if (name[0] >= '0' && name[0] <= '3' && name[1] == '\0')
        slot = name[0] - '0';
    printf("%s %s:", command, name);
    if (strcmp(command, "ctxnew") == 0) {
        if (slot < 0 || ctx_slots[slot] != NULL)
            printf(" busy");
        else
            printf(" %s", (ctx_slots[slot] = OSSL_LIB_CTX_new()) != NULL ? "made" : "NULL");
    } else if (strcmp(command, "ctxfree") == 0) {
        if (slot < 0 || ctx_slots[slot] == NULL) {
            printf(" empty");
        } else {
            int is_default = OSSL_LIB_CTX_set0_default(NULL) == ctx_slots[slot];

            OSSL_LIB_CTX_free(ctx_slots[slot]);
            if (is_default) {
                printf(" default, kept");
            } else {
                ctx_slots[slot] = NULL;
                printf(" freed");
            }
        }
    } else if (strcmp(command, "ctxfreeglobal") == 0) {
        if (OSSL_LIB_CTX_set0_default(NULL) == OSSL_LIB_CTX_get0_global_default()) {
            OSSL_LIB_CTX_free(OSSL_LIB_CTX_get0_global_default());
            printf(" kept %llu", (unsigned long long)OSSL_get_max_threads(NULL));
        } else {
            printf(" skip");
        }
    } else if (strcmp(command, "ctxdefault") == 0) {
        ctx = ctx_named(name, &ok);
        if (ok)
            print_ctx_name(OSSL_LIB_CTX_set0_default(ctx));
        else
            printf(" empty");
        printf(" now");
        print_ctx_name(OSSL_LIB_CTX_set0_default(NULL));
    } else if (strcmp(command, "ctxmax") == 0 || strcmp(command, "ctxdiag") == 0) {
        int max = strcmp(command, "ctxmax") == 0;

        ctx = ctx_named(name, &ok);
        if (!ok) {
            printf(" empty\n");
            return 1;
        }
        if (max)
            printf(" %d", OSSL_set_max_threads(ctx, (uint64_t)n));
        else
            OSSL_LIB_CTX_set_conf_diagnostics(ctx, (int)n);
        for (i = -1; i < 4; i++) {
            OSSL_LIB_CTX *c = i < 0 ? OSSL_LIB_CTX_get0_global_default() : ctx_slots[i];

            if (c == NULL)
                continue;
            if (max)
                printf(" %llu", (unsigned long long)OSSL_get_max_threads(c));
            else
                printf(" %d", OSSL_LIB_CTX_get_conf_diagnostics(c));
        }
        if (max)
            printf(" default %llu", (unsigned long long)OSSL_get_max_threads(NULL));
        else
            printf(" default %d", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    } else if (strcmp(command, "ctxexidx") == 0) {
        printf(" %d", CRYPTO_get_ex_new_index(atoi(name), 0, NULL, NULL, NULL, NULL));
    } else {
        printf(" unknown");
    }
    printf("\n");
    ERR_clear_error();
    return 1;
}

static OSSL_LIB_CTX *prop_ctx;

/* Prints text quoted on the same line, bytes outside printable ASCII escaped. */
static void print_quoted(const char *text)
{
    printf(" \"");
    for (; *text != '\0'; text++) {
        unsigned char c = (unsigned char)*text;

        if (c >= ' ' && c <= '~' && c != '\\' && c != '"')
            putchar(c);
        else
            printf("\\x%02x", c);
    }
    printf("\"");
}

static void print_prop_state(int r)
{
    unsigned long code;
    const char *data;
    int flags;
    char *text;

    printf(" %d errors:", r);
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            print_quoted(data);
    }
    text = EVP_get1_default_properties(prop_ctx);
    printf(" fips %d now", EVP_default_properties_is_fips_enabled(prop_ctx));
    if (text == NULL)
        printf(" NULL");
    else
        print_quoted(text);
    printf("\n");
    OPENSSL_free(text);
}

static int prop_command(const char *command, const char *line)
{
    if (strcmp(command, "propnew") == 0) {
        OSSL_LIB_CTX_free(prop_ctx);
        prop_ctx = OSSL_LIB_CTX_new();
        printf("propnew\n");
        return 1;
    }
    if (prop_ctx == NULL)
        prop_ctx = OSSL_LIB_CTX_new();
    if (strcmp(command, "propset") == 0) {
        char hex[700] = "";
        unsigned char q[300];
        size_t len = 0;

        sscanf(line, "%*s %699s", hex);
        if (hex[0] != '\0' && strcmp(hex, "-") != 0 && !parse_hex(hex, q, &len)) {
            printf("propset bad hex\n");
            return 1;
        }
        q[len] = '\0';
        printf("propset %s:", hex[0] == '\0' ? "NULL" : hex);
        print_prop_state(EVP_set_default_properties(prop_ctx, hex[0] == '\0' ? NULL : (const char *)q));
        return 1;
    }
    if (strcmp(command, "propfips") == 0) {
        int enable = 0;

        sscanf(line, "%*s %d", &enable);
        printf("propfips %d:", enable);
        print_prop_state(EVP_default_properties_enable_fips(prop_ctx, enable));
        return 1;
    }
    return 0;
}

static OSSL_LIB_CTX *prov_ctx;
static OSSL_PROVIDER *prov_slots[8];
static int prov_library_base = -1;

static void print_prov_errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if (ERR_GET_LIB(code) == ERR_LIB_CRYPTO && (flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            print_quoted(data);
    }
    printf("\n");
}

static int print_prov_name(OSSL_PROVIDER *prov, void *arg)
{
    (void)arg;
    printf(" %s", OSSL_PROVIDER_get0_name(prov));
    return 1;
}

static int prov_command(const char *command, const char *line)
{
    char name[64] = "";
    int slot = -1, keep = 0;

    if (command[0] != 'p' || (strcmp(command, "pnew") != 0 && strcmp(command, "pload") != 0
                              && strcmp(command, "ptry") != 0 && strcmp(command, "punload") != 0
                              && strcmp(command, "pavail") != 0 && strcmp(command, "pall") != 0
                              && strcmp(command, "pparams") != 0))
        return 0;
    if (prov_library_base < 0)
        prov_library_base = ERR_get_next_error_library();
    if (strcmp(command, "pnew") == 0 || prov_ctx == NULL) {
        int i;

        for (i = 0; i < 8; i++) {
            OSSL_PROVIDER_unload(prov_slots[i]);
            prov_slots[i] = NULL;
        }
        OSSL_LIB_CTX_free(prov_ctx);
        prov_ctx = OSSL_LIB_CTX_new();
        if (strcmp(command, "pnew") == 0) {
            printf("pnew\n");
            return 1;
        }
    }
    printf("%s", line);
    if (strcmp(command, "pload") == 0 || strcmp(command, "ptry") == 0) {
        sscanf(line, "%*s %d %63s %d", &slot, name, &keep);
        if (slot < 0 || slot > 7 || prov_slots[slot] != NULL) {
            printf(": busy\n");
            return 1;
        }
        prov_slots[slot] = strcmp(command, "pload") == 0 ? OSSL_PROVIDER_load(prov_ctx, name)
                                                         : OSSL_PROVIDER_try_load(prov_ctx, name, keep);
        printf(": %s", prov_slots[slot] == NULL ? "NULL" : "loaded");
    } else if (strcmp(command, "punload") == 0) {
        sscanf(line, "%*s %d", &slot);
        if (slot < 0 || slot > 7 || prov_slots[slot] == NULL) {
            printf(": empty\n");
            return 1;
        }
        printf(": %d", OSSL_PROVIDER_unload(prov_slots[slot]));
        prov_slots[slot] = NULL;
    } else if (strcmp(command, "pavail") == 0) {
        sscanf(line, "%*s %63s", name);
        printf(": %d", OSSL_PROVIDER_available(prov_ctx, name));
    } else if (strcmp(command, "pall") == 0) {
        int i, j, r;

        printf(":");
        r = OSSL_PROVIDER_do_all(prov_ctx, print_prov_name, NULL);
        printf(" (%d) same:", r);
        for (i = 0; i < 8; i++)
            for (j = i + 1; j < 8; j++)
                if (prov_slots[i] != NULL && prov_slots[i] == prov_slots[j])
                    printf(" %d=%d", i, j);
        printf(" libraries %d", ERR_get_next_error_library() - prov_library_base);
    } else {
        const char *pname = NULL, *version = NULL;
        int status = -1;
        OSSL_PARAM params[4];

        sscanf(line, "%*s %d", &slot);
        if (slot < 0 || slot > 7 || prov_slots[slot] == NULL) {
            printf(": empty\n");
            return 1;
        }
        params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, (char **)&pname, 0);
        params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, (char **)&version, 0);
        params[2] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_STATUS, &status);
        params[3] = OSSL_PARAM_construct_end();
        printf(": %s %d", OSSL_PROVIDER_get0_name(prov_slots[slot]), OSSL_PROVIDER_get_params(prov_slots[slot], params));
        printf(" \"%s\" \"%s\" %d self-test %d", pname, version, status, OSSL_PROVIDER_self_test(prov_slots[slot]));
    }
    print_prov_errors();
    /*
     * A failed module lookup's data holds the module directory and the system loader's message,
     * which differ between the libraries; drop the error state so no slot keeps a buffer sized
     * by it (the err commands print the sizes).
     */
    OPENSSL_thread_stop();
    return 1;
}

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

static void print_c_string(const char *label, char *text)
{
    printf(" %s=%s", label, text == NULL ? "(null)" : text);
    OPENSSL_free(text);
}

static int addr_command(const char *command, const char *line)
{
    char spec[256] = "", family[8] = "", hex[256] = "";
    int prio = 0, port = 0;

    if (strcmp(command, "hostserv") == 0) {
        char *host = (char *)"-", *service = (char *)"-";
        int ret;

        sscanf(line, "%*s %255s %d", spec, &prio);
        for (char *p = spec; *p != '\0'; p++)
            if (*p == '_')
                memmove(p, p + 1, strlen(p)), p--;
        ret = BIO_parse_hostserv(spec, &host, &service, prio);
        printf("hostserv %d", ret);
        if (ret) {
            if (strcmp(host != NULL ? host : "", "-") != 0 || host == NULL)
                print_c_string("host", host);
            else
                printf(" host=untouched");
            if (strcmp(service != NULL ? service : "", "-") != 0 || service == NULL)
                print_c_string("service", service);
            else
                printf(" service=untouched");
        } else {
            printf(" reason=%d", ERR_GET_REASON(ERR_peek_last_error()));
        }
        printf("\n");
        ERR_clear_error();
        return 1;
    }
    if (strcmp(command, "addr") == 0) {
        unsigned char raw[128];
        size_t len = 0, rawlen = 0;
        BIO_ADDR *a = BIO_ADDR_new();
        int fam, ret;

        sscanf(line, "%*s %7s %255s %d", family, hex, &port);
        if (!parse_hex(hex, raw, &len) || len > sizeof(raw) - 1) {
            printf("error bad hex\n");
            BIO_ADDR_free(a);
            return 1;
        }
        raw[len] = '\0';
        fam = family[0] == '4' ? AF_INET : family[0] == '6' ? AF_INET6 : AF_UNIX;
        ret = BIO_ADDR_rawmake(a, fam, raw, len, htons((unsigned short)port));
        printf("addr %d family=%d port=%u", ret, BIO_ADDR_family(a), ntohs(BIO_ADDR_rawport(a)));
        if (BIO_ADDR_rawaddress(a, NULL, &rawlen) && rawlen <= sizeof(raw)) {
            BIO_ADDR_rawaddress(a, raw, &rawlen);
            printf(" raw=");
            for (size_t i = 0; i < rawlen; i++)
                printf("%02x", raw[i]);
        }
        if (fam == AF_UNIX) {
            print_c_string("path", BIO_ADDR_path_string(a));
        } else if (ret) {
            print_c_string("host", BIO_ADDR_hostname_string(a, 1));
            print_c_string("service", BIO_ADDR_service_string(a, 1));
        }
        printf("\n");
        BIO_ADDR_free(a);
        ERR_clear_error();
        return 1;
    }
    return 0;
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
            || bio_command(command, line) || printf_command(command, line)
            || addr_command(command, line) || obj_command(command, line)
            || asn_command(command, line) || int_command(command, line)
            || bit_command(command, line) || text_command(command, line)
            || time_command(command, line) || template_command(command, line)
            || params_command(command, line) || ctx_command(command, line)
            || prop_command(command, line) || prov_command(command, line)) {
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
