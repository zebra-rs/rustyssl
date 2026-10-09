/*
 * Conformance test for PEM framing (PEM_read_bio_ex(3), PEM_read_bio, PEM_read, PEM_write_bio,
 * PEM_write, PEM_proc_type, PEM_dek_info), in TAP format: blocks written with and without
 * headers and read back; text before the BEGIN line, a BOM, trailing whitespace, CR LF, NULs,
 * lines longer than the reader's buffer, encrypted-style headers and their line-length rules,
 * mismatched or missing END lines, bad base64, and each reading flag. Every result is printed,
 * so the outputs are compared byte for byte.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>

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
    unsigned long code;
    const char *data;
    int flags;

    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            printf("[%s]", data);
    }
    printf("\n");
}

static void escaped(const char *what, const unsigned char *p, long n)
{
    long i;

    printf("%s\"", what);
    for (i = 0; i < n; i++) {
        if (p[i] == '\n')
            printf("\\n");
        else if (p[i] < 0x20 || p[i] > 0x7e)
            printf("\\x%02x", p[i]);
        else
            putchar(p[i]);
    }
    printf("\"");
}

/* Reads every block from `text` with PEM_read_bio_ex and `flags`, printing each. */
static int read_all(const char *what, const char *text, long textlen, unsigned int flags)
{
    BIO *in = BIO_new_mem_buf(text, (int)textlen);
    char *name, *header;
    unsigned char *data;
    long len;
    int r, count = 0;

    printf("# %s (flags %u):\n", what, flags);
    while ((r = PEM_read_bio_ex(in, &name, &header, &data, &len, flags)) == 1) {
        printf("#   ");
        escaped("name ", (unsigned char *)name, (long)strlen(name));
        escaped(" header ", (unsigned char *)header, (long)strlen(header));
        printf(" data %ld ", len);
        escaped("", data, len);
        printf("\n");
        if ((flags & PEM_FLAG_SECURE) != 0) {
            OPENSSL_secure_free(name);
            OPENSSL_secure_free(header);
            OPENSSL_secure_clear_free(data, (size_t)len);
        } else {
            OPENSSL_free(name);
            OPENSSL_free(header);
            OPENSSL_free(data);
        }
        count++;
    }
    printf("#   then %d, pointers %s, left %d", r, name == NULL && header == NULL && data == NULL && len == 0 ? "cleared" : "set",
           (int)BIO_pending(in));
    errors();
    BIO_free(in);
    return count;
}

static int read_text(const char *what, const char *text, unsigned int flags)
{
    return read_all(what, text, (long)strlen(text), flags);
}

static void writing(void)
{
    unsigned char data[10000];
    BIO *mem = BIO_new(BIO_s_mem());
    char *text;
    long n;
    int r, i;
    static const long sizes[] = { 0, 1, 3, 48, 49, 100, 10000 };

    for (i = 0; i < 10000; i++)
        data[i] = (unsigned char)(i * 11 + 5);
    for (i = 0; i < (int)(sizeof(sizes) / sizeof(sizes[0])); i++) {
        r = PEM_write_bio(mem, "TEST DATA", i % 2 ? "Proc-Type: 4,ENCRYPTED\nDEK-Info: X,00" : "", data, sizes[i]);
        n = BIO_get_mem_data(mem, &text);
        printf("# write %ld: %d, %ld chars", sizes[i], r, n);
        if (n < 400)
            escaped(" ", (unsigned char *)text, n);
        printf("\n");
        (void)BIO_reset(mem);
    }
    r = PEM_write_bio(mem, "ROUND", NULL, data, 10000);
    n = BIO_get_mem_data(mem, &text);
    check(r > 0 && read_all("round trip", text, n, PEM_FLAG_EAY_COMPATIBLE) == 1, "PEM_write_bio and PEM_read_bio_ex");
    r = PEM_write_bio(mem, "SECOND", NULL, data, 5);
    n = BIO_get_mem_data(mem, &text);
    check(read_all("two blocks", text, n, PEM_FLAG_EAY_COMPATIBLE) == 2, "blocks one after another");
    BIO_free(mem);
}

static void reading(void)
{
    static const char *const flagnames[] = { "default", "EAY", "ONLY_B64" };
    static const unsigned int flagvalues[] = { 0, PEM_FLAG_EAY_COMPATIBLE, PEM_FLAG_ONLY_B64 };
    static const struct {
        const char *name, *text;
    } cases[] = {
        { "plain", "-----BEGIN X-----\naGVsbG8=\n-----END X-----\n" },
        { "junk before", "some text\n-----BEGIN-----\n-----BEGIN X-----\naGVsbG8=\n-----END X-----\n" },
        { "bom", "\xEF\xBB\xBF-----BEGIN X-----\naGVsbG8=\n-----END X-----\n" },
        { "trailing spaces", "-----BEGIN X-----  \t\naGVsbG8=   \n-----END X-----  \n" },
        { "crlf", "-----BEGIN X-----\r\naGVs\r\nbG8=\r\n-----END X-----\r\n" },
        { "header", "-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-CBC,0011\n\naGVsbG8=\n-----END X-----\n" },
        { "header no blank", "-----BEGIN X-----\nKey: value\naGVsbG8=\n-----END X-----\n" },
        { "two blanks", "-----BEGIN X-----\nKey: v\n\n\naGVsbG8=\n-----END X-----\n" },
        { "short line mid encrypted", "-----BEGIN X-----\nK: v\n\naGVs\nbG8=\n-----END X-----\n" },
        { "long line encrypted",
          "-----BEGIN X-----\nK: v\n\naGVsbG8gaGVsbG8gaGVsbG8gaGVsbG8gaGVsbG8gaGVsbG8gaGVsbG8gaGVsbG8gaGVs\n-----END X-----\n" },
        { "end mismatch", "-----BEGIN X-----\naGVsbG8=\n-----END Y-----\n" },
        { "no end", "-----BEGIN X-----\naGVsbG8=\n" },
        { "no begin", "aGVsbG8=\n" },
        { "no data", "-----BEGIN X-----\n-----END X-----\n" },
        { "bad base64", "-----BEGIN X-----\naGV*bG8=\n-----END X-----\n" },
        { "junk after data", "-----BEGIN X-----\naGVsbG8= junk\n-----END X-----\n" },
        { "control chars", "-----BEGIN X-----\naGVs\x01bG8=\n-----END X-----\n" },
        { "high octets", "-----BEGIN X-----\naGVsbG8=\xa0\xff\n-----END X-----\n" },
        { "empty name", "-----BEGIN -----\naGVsbG8=\n-----END -----\n" },
        { "space name", "-----BEGIN A B-----\naGVsbG8=\n-----END A B-----\n" },
    };
    size_t i, f;
    char longtext[2000], *p = longtext;
    static const char nul[] = "-----BEGIN X-----\naGVs\0bG8=\n-----END X-----\n";

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for (f = 0; f < 3; f++) {
            char what[80];

            snprintf(what, sizeof(what), "%s, %s", cases[i].name, flagnames[f]);
            read_text(what, cases[i].text, flagvalues[f]);
        }
    }
    read_all("embedded NUL", nul, (long)sizeof(nul) - 1, PEM_FLAG_EAY_COMPATIBLE);
    read_all("embedded NUL default", nul, (long)sizeof(nul) - 1, 0);

    p += sprintf(p, "-----BEGIN LONG-----\n");
    for (i = 0; i < 300; i++)
        *p++ = (char)('A' + i % 26);
    p += sprintf(p, "\n-----END LONG-----\n");
    read_text("line over 254", longtext, PEM_FLAG_EAY_COMPATIBLE);
    p = longtext;
    p += sprintf(p, "-----BEGIN LONG-----\nK: v\n\n");
    for (i = 0; i < 300; i++)
        *p++ = (char)('A' + i % 26);
    p += sprintf(p, "\n-----END LONG-----\n");
    read_text("line over 254 encrypted", longtext, PEM_FLAG_EAY_COMPATIBLE);

    check(read_text("both flags", "-----BEGIN X-----\naGVsbG8=\n-----END X-----\n",
                    PEM_FLAG_EAY_COMPATIBLE | PEM_FLAG_ONLY_B64) == 0,
          "EAY_COMPATIBLE and ONLY_B64 together are refused");
    check(read_text("secure", "-----BEGIN X-----\naGVsbG8=\n-----END X-----\n",
                    PEM_FLAG_SECURE | PEM_FLAG_EAY_COMPATIBLE) == 1,
          "PEM_FLAG_SECURE");
}

static void files(void)
{
    FILE *f = tmpfile();
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len = 0;
    BIO *mem = BIO_new_mem_buf("-----BEGIN B-----\nYWJj\n-----END B-----\n", -1);

    check(PEM_write(f, "FILED", "H: v\n", (const unsigned char *)"abc", 3) == 5, "PEM_write");
    rewind(f);
    check(PEM_read(f, &name, &header, &data, &len) == 1 && strcmp(name, "FILED") == 0 && strcmp(header, "H: v\n") == 0
              && len == 3 && memcmp(data, "abc", 3) == 0,
          "PEM_read");
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    check(PEM_read_bio(mem, &name, &header, &data, &len) == 1 && strcmp(name, "B") == 0 && len == 3, "PEM_read_bio");
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    BIO_free(mem);
    fclose(f);
    ERR_clear_error();
}

static void headers(void)
{
    char buf[PEM_BUFSIZE];
    unsigned char iv[16];
    int i;

    for (i = 0; i < 16; i++)
        iv[i] = (unsigned char)(i * 17);
    buf[0] = '\0';
    PEM_proc_type(buf, PEM_TYPE_ENCRYPTED);
    PEM_dek_info(buf, "AES-128-CBC", 16, (char *)iv);
    escaped("# headers ", (unsigned char *)buf, (long)strlen(buf));
    printf("\n");
    check(strcmp(buf, "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n") == 0,
          "PEM_proc_type and PEM_dek_info");
    buf[0] = '\0';
    PEM_proc_type(buf, PEM_TYPE_MIC_CLEAR);
    PEM_proc_type(buf, PEM_TYPE_MIC_ONLY);
    PEM_proc_type(buf, 99);
    escaped("# types ", (unsigned char *)buf, (long)strlen(buf));
    printf("\n");
    memset(buf, 'x', sizeof(buf));
    buf[PEM_BUFSIZE - 30] = '\0';
    PEM_dek_info(buf, "AES-128-CBC", 16, (char *)iv);
    escaped("# truncated ", (unsigned char *)buf + PEM_BUFSIZE - 30, (long)strlen(buf + PEM_BUFSIZE - 30));
    printf(" %d\n", (int)strlen(buf));
    memset(buf, 'x', sizeof(buf));
    buf[PEM_BUFSIZE - 10] = '\0';
    PEM_proc_type(buf, PEM_TYPE_ENCRYPTED);
    escaped("# proc truncated ", (unsigned char *)buf + PEM_BUFSIZE - 10, (long)strlen(buf + PEM_BUFSIZE - 10));
    printf(" %d\n", (int)strlen(buf));
}

int main(void)
{
    writing();
    reading();
    files();
    headers();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
