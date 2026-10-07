/*
 * Differential probe (TEST_PLAN.md, layer L5). Reads one command per line on stdin, runs it
 * against whichever libcrypto the dynamic loader picked, and prints a deterministic line per
 * command. `cargo xtask test-differential` runs the same input against the reference and
 * rustssl and compares the output.
 *
 * Commands (one buffer at a time):
 *   new <flags>        BUF_MEM_new_ex(flags), replacing any current buffer
 *   grow <len>         BUF_MEM_grow
 *   grow_clean <len>   BUF_MEM_grow_clean
 *   fill <byte>        set every byte below `length` to <byte>
 *   dump               print `length` bytes of data in hex
 *   free               BUF_MEM_free
 *   reverse <hex>      BUF_reverse, copying and in place
 *   # ...              comment, echoed
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/buffer.h>

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
        if (strcmp(command, "new") == 0) {
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
