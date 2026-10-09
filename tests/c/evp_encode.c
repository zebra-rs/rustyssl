/*
 * Conformance test for base64 (EVP_EncodeInit(3) and family): EVP_EncodeBlock/EVP_DecodeBlock,
 * streaming with EVP_EncodeUpdate/Final and EVP_DecodeUpdate/Final over chunks of every size,
 * line handling (whitespace, CR LF, '-'), padding and its errors, the octets reported on error,
 * the NULs written after encoded lines, and the context functions, in TAP format. Results are
 * printed, so the outputs are compared byte for byte.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Prints `n` octets as text, with \n and other controls escaped, then what follows them. */
static void show(const char *what, int ret, const unsigned char *p, int n)
{
    int i;

    printf("# %s: %d \"", what, ret);
    for (i = 0; i < n; i++) {
        if (p[i] == '\n')
            printf("\\n");
        else if (p[i] < 0x20 || p[i] > 0x7e)
            printf("\\x%02x", p[i]);
        else
            putchar(p[i]);
    }
    printf("\" then %02x\n", n >= 0 ? p[n] : 0);
}

static void blocks(void)
{
    unsigned char out[256], in[8] = "abcdefg";
    int n, len;

    for (len = 0; len <= 7; len++) {
        memset(out, 'Z', sizeof(out));
        n = EVP_EncodeBlock(out, in, len);
        show("EncodeBlock", n, out, n > 0 ? n : 0);
    }
    check(EVP_EncodeBlock(out, in, 5) == 8 && memcmp(out, "YWJjZGU=", 9) == 0, "EVP_EncodeBlock pads and ends with a NUL");

    static const char *const inputs[] = {
        "YWJjZGU=", "YWJjZA==", "YWJj", "  YWJj\r\n", "YWJj\n\n\n", "YW Jj", "YWJ", "YWJjZ", "YWJj*", "", "=",
        "-YWJj", "YWJj-", "\tYWJj", "YWJjYWJj ", "YW=j", "Y===",
    };
    size_t i;

    for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        memset(out, 'Z', sizeof(out));
        n = EVP_DecodeBlock(out, (const unsigned char *)inputs[i], (int)strlen(inputs[i]));
        printf("# DecodeBlock \"%s\"", inputs[i]);
        show("", n, out, n > 0 ? n : 0);
    }
    check(EVP_DecodeBlock(out, (const unsigned char *)"YWJjZGU=", 8) == 6 && memcmp(out, "abcde\0", 6) == 0,
          "EVP_DecodeBlock keeps the padding as zero octets");
}

static void encode_stream(void)
{
    unsigned char in[200], out[512];
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(), *copy = EVP_ENCODE_CTX_new();
    int chunk, outl, total, i, r;

    for (i = 0; i < 200; i++)
        in[i] = (unsigned char)(i * 13 + 7);
    for (chunk = 1; chunk <= 64; chunk *= 2) {
        unsigned char all[1024];

        total = 0;
        EVP_EncodeInit(ctx);
        for (i = 0; i < 150; i += chunk) {
            int n = 150 - i < chunk ? 150 - i : chunk;

            memset(out, 'Z', sizeof(out));
            r = EVP_EncodeUpdate(ctx, out, &outl, in + i, n);
            if (r != 1 || (outl > 0 && out[outl] != 0))
                printf("# chunk %d at %d: %d, %d, then %02x\n", chunk, i, r, outl, out[outl]);
            memcpy(all + total, out, (size_t)outl);
            total += outl;
        }
        printf("# chunk %d: held %d\n", chunk, EVP_ENCODE_CTX_num(ctx));
        memset(out, 'Z', sizeof(out));
        EVP_EncodeFinal(ctx, out, &outl);
        memcpy(all + total, out, (size_t)outl + 1);
        total += outl;
        show("encoded", total, all, total);
    }
    EVP_EncodeInit(ctx);
    check(EVP_EncodeUpdate(ctx, out, &outl, in, 0) == 0 && outl == 0, "no input is 0");
    check(EVP_EncodeUpdate(ctx, out, &outl, in, 10) == 1 && outl == 0 && EVP_ENCODE_CTX_num(ctx) == 10, "10 octets are held");
    check(EVP_ENCODE_CTX_copy(copy, ctx) == 1 && EVP_ENCODE_CTX_num(copy) == 10, "EVP_ENCODE_CTX_copy");
    EVP_EncodeFinal(copy, out, &outl);
    show("final of the copy", outl, out, outl);
    check(outl == 17 && EVP_ENCODE_CTX_num(copy) == 0, "a short last line");
    EVP_EncodeFinal(copy, out, &outl);
    check(outl == 0, "nothing more");
    EVP_ENCODE_CTX_free(ctx);
    EVP_ENCODE_CTX_free(copy);
    EVP_ENCODE_CTX_free(NULL);
}

/* Decodes `text` in chunks of `chunk`, printing each step and the final. */
static void decode(const char *what, const char *text, int chunk)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    unsigned char out[512];
    int len = (int)strlen(text), i, outl, r;

    printf("# %s (chunks of %d):", what, chunk);
    EVP_DecodeInit(ctx);
    for (i = 0; i < len; i += chunk) {
        int n = len - i < chunk ? len - i : chunk;

        r = EVP_DecodeUpdate(ctx, out, &outl, (const unsigned char *)text + i, n);
        printf(" [%d %d]", r, outl);
        if (r < 0)
            break;
    }
    printf(" held %d", EVP_ENCODE_CTX_num(ctx));
    r = EVP_DecodeFinal(ctx, out, &outl);
    printf(" final %d %d\n", r, outl);
    EVP_ENCODE_CTX_free(ctx);
}

static void decode_stream(void)
{
    static const struct {
        const char *name, *text;
    } cases[] = {
        { "padded", "YWJjZGU=\n" },
        { "two lines", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2\nd3h5eg==\n" },
        { "crlf", "YWJj\r\nZGVm\r\n" },
        { "dash end", "YWJjZGVm-ignored" },
        { "dash mid group", "YWJjZG-" },
        { "after padding", "YWI=YWJj" },
        { "three pads", "YW===" },
        { "bad char", "YWJj!ZGVm" },
        { "high bit", "YWJj\xc3\xa9" },
        { "unfinished", "YWJjZG" },
        { "seven held", "YWJjZG9" },
        { "spaces", "Y W J j" },
        { "empty", "" },
    };
    size_t i;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    unsigned char out[64];
    int outl, r;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        decode(cases[i].name, cases[i].text, 1);
        decode(cases[i].name, cases[i].text, 5);
        decode(cases[i].name, cases[i].text, 1000);
    }
    EVP_DecodeInit(ctx);
    r = EVP_DecodeUpdate(ctx, out, &outl, (const unsigned char *)"YWJjZG", 6);
    check(r == 1 && outl == 0 && EVP_ENCODE_CTX_num(ctx) == 6, "characters are held until they make whole groups");
    r = EVP_DecodeUpdate(ctx, out, &outl, (const unsigned char *)"", 0);
    check(r == 0 && outl == 0 && EVP_ENCODE_CTX_num(ctx) == 6, "an empty update is the end, holding on");
    r = EVP_DecodeUpdate(ctx, out, &outl, (const unsigned char *)"Vm", -1);
    printf("# negative length: %d %d held %d\n", r, outl, EVP_ENCODE_CTX_num(ctx));
    r = EVP_DecodeFinal(ctx, out, &outl);
    printf("# final: %d %d\n", r, outl);
    check(r == -1, "characters held that don't make whole groups don't decode");
    EVP_DecodeInit(ctx);
    r = EVP_DecodeUpdate(ctx, out, &outl,
                         (const unsigned char *)"YWJjYWJjYWJjYWJjYWJjYWJjYWJjYWJjYWJjYWJjYWJjYWJjYWJjYWJjYWJjYWJj*", 65);
    check(r == -1 && outl == 48 && memcmp(out, "abcabc", 6) == 0, "what was decoded before an error is reported");
    EVP_ENCODE_CTX_free(ctx);
}

int main(void)
{
    blocks();
    encode_stream();
    decode_stream();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
