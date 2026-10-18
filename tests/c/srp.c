/*
 * Conformance test for SRP (SRP_Calc_x(3), SRP_create_verifier(3), SRP_VBASE_new(3),
 * SRP_user_pwd_new(3)): the computations of both sides over a known group agreeing on the
 * premaster secret, the checks of public values, the known groups, verifiers as numbers and as
 * SRP base64 text, users, and a verifier base read from a file (groups defined in it, users of
 * those and of known groups, revoked and unknown ones, made-up users from a seed key), with the
 * errors of bad files and NULL arguments.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/srp.h>

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
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static void hex(const char *label, const BIGNUM *b)
{
    char *h = b == NULL ? NULL : BN_bn2hex(b);

    printf("  %s: %s\n", label, h == NULL ? "(null)" : h);
    OPENSSL_free(h);
}

static BIGNUM *bn(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

/* The 1024-bit group of RFC 5054 in SRP's base64. */
static const char N1024[] = "Ewl2hcjiutMd3Fu2lgFnUXWSc67TVyy2vwYCKoS9MLsrdJVT9RgWTCuEqWJrfB6uE3LsE9GkOlaZabS7M29sj5TnzUqO"
                            "LJMjiwEzArfiLr9WbMRANlF68N5AVLcPWvNx6Zjl3m5Scp0BzJBz9TkgfhzKJZ.WtP3Mv/67I/0wmRZ";

static void calc(void)
{
    SRP_gN *gN = SRP_get_default_gN("1024");
    BIGNUM *s = bn("BEB25379D1A8581EB5A727673A2441EE");
    BIGNUM *a = bn("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393");
    BIGNUM *b = bn("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20");
    BIGNUM *x, *v = NULL, *A, *B, *u, *u2, *Kc, *Ks, *zero = BN_new(), *s2 = BN_dup(s);
    BN_CTX *ctx = BN_CTX_new();

    printf("# the computations\n");
    check(gN != NULL && strcmp(gN->id, "1024") == 0, "the 1024-bit group");
    x = SRP_Calc_x(s, "alice", "password123");
    hex("x", x);
    v = BN_new();
    BN_mod_exp(v, gN->g, x, gN->N, ctx);
    hex("v", v);
    A = SRP_Calc_A(a, gN->N, gN->g);
    hex("A", A);
    B = SRP_Calc_B(b, gN->N, gN->g, v);
    hex("B", B);
    check(SRP_Verify_A_mod_N(A, gN->N) == 1 && SRP_Verify_B_mod_N(B, gN->N) == 1, "A and B are valid");
    u = SRP_Calc_u(A, B, gN->N);
    hex("u", u);
    u2 = SRP_Calc_u_ex(A, B, gN->N, NULL, NULL);
    check(BN_cmp(u, u2) == 0, "SRP_Calc_u_ex");
    Kc = SRP_Calc_client_key(gN->N, B, gN->g, x, a, u);
    Ks = SRP_Calc_server_key(A, v, u, b, gN->N);
    hex("premaster", Kc);
    check(Kc != NULL && Ks != NULL && BN_cmp(Kc, Ks) == 0, "both sides agree");
    BN_free(Kc);
    Kc = SRP_Calc_client_key_ex(gN->N, B, gN->g, x, a, u, NULL, NULL);
    check(BN_cmp(Kc, Ks) == 0, "SRP_Calc_client_key_ex");
    BN_free(B);
    B = SRP_Calc_B_ex(b, gN->N, gN->g, v, NULL, NULL);
    hex("B again", B);
    BN_free(x);
    x = SRP_Calc_x_ex(s, "alice", "password123", NULL, NULL);
    hex("x again", x);

    printf("# the checks\n");
    check(SRP_Verify_B_mod_N(gN->N, gN->N) == 0, "B = N is invalid");
    check(SRP_Verify_A_mod_N(zero, gN->N) == 0, "A = 0 is invalid");
    check(SRP_Verify_B_mod_N(NULL, gN->N) == 0, "B NULL");
    {
        BIGNUM *n2 = BN_dup(gN->N), *same = SRP_Calc_u(gN->N, B, gN->N);

        check(SRP_Calc_u(n2, B, gN->N) == NULL, "u of A = N");
        /* A that is N itself (the same pointer) isn't checked, as OpenSSL's k = SHA1(N | g). */
        check(same != NULL, "u of N itself");
        BN_free(n2);
        BN_free(same);
    }
    check(SRP_Calc_x(zero, "alice", "p") == NULL, "x of a zero salt");
    check(SRP_Calc_x(s, NULL, "p") == NULL && SRP_Calc_A(NULL, gN->N, gN->g) == NULL
              && SRP_Calc_B(b, NULL, gN->g, v) == NULL && SRP_Calc_server_key(A, v, u, b, NULL) == NULL
              && SRP_Calc_client_key(gN->N, B, gN->g, NULL, a, u) == NULL,
          "NULL arguments");
    errors();

    printf("# the known groups\n");
    printf("  default %s, 2048 %s, bogus %s\n", SRP_get_default_gN(NULL)->id, SRP_get_default_gN("2048")->id,
           SRP_get_default_gN("bogus") == NULL ? "none" : "found");
    {
        static const char *ids[] = { "8192", "6144", "4096", "3072", "2048", "1536", "1024" };
        size_t i;

        for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            SRP_gN *g = SRP_get_default_gN(ids[i]);
            char *k = SRP_check_known_gN_param(g->g, g->N);

            printf("  %s: %d bits, g %s, known as %s\n", g->id, BN_num_bits(g->N), BN_bn2dec(g->g) ? "set" : "?",
                   k == NULL ? "none" : k);
        }
    }
    check(SRP_check_known_gN_param(gN->N, gN->g) == NULL, "swapped");
    check(SRP_check_known_gN_param(NULL, gN->N) == NULL, "NULL g");

    printf("# verifiers\n");
    {
        BIGNUM *sv = s2, *vv = NULL, *rs = NULL, *rv = NULL;

        check(SRP_create_verifier_BN("alice", "password123", &sv, &vv, gN->N, gN->g) == 1, "SRP_create_verifier_BN");
        check(sv == s2 && BN_cmp(vv, v) == 0, "the same verifier");
        BN_free(vv);
        vv = NULL;
        check(SRP_create_verifier_BN_ex("alice", "pw", &rs, &rv, gN->N, gN->g, NULL, NULL) == 1 && rs != NULL
                  && BN_num_bits(rs) <= 160,
              "a random salt");
        BN_clear_free(rs);
        BN_clear_free(rv);
        check(SRP_create_verifier_BN(NULL, "pw", &sv, &vv, gN->N, gN->g) == 0, "no user");
        check(SRP_create_verifier_BN("u", "pw", &sv, &vv, NULL, gN->g) == 0, "no group");
    }
    {
        char *salt = "Ivg1cfqFdfUp0pyv2rD4wD", *ver = NULL, *salt2 = NULL, *ver2 = NULL, *ver3 = NULL;
        char *id = SRP_create_verifier("alice", "password123", &salt, &ver, NULL, "1024");

        printf("  id %s, salt %s\n  verifier %s\n", id, salt, ver);
        id = SRP_create_verifier_ex("alice", "password123", &salt, &ver2, N1024, "02", NULL, NULL);
        printf("  explicit group: id %s\n", id);
        check(ver2 != NULL && strcmp(ver, ver2) == 0, "the same verifier from the group's text");
        id = SRP_create_verifier("alice", "password123", &salt2, &ver3, NULL, NULL);
        printf("  default group: id %s, random salt of %zu characters\n", id, salt2 == NULL ? 0 : strlen(salt2));
        check(SRP_create_verifier("alice", "pw", &salt, &ver3, NULL, "9999") == NULL, "an unknown group");
        check(SRP_create_verifier("alice", "pw", NULL, &ver3, NULL, "1024") == NULL, "no salt slot");
        {
            char *bad = "!!!!";

            check(SRP_create_verifier("alice", "pw", &bad, &ver3, NULL, "1024") == NULL, "a salt that isn't base64");
        }
        OPENSSL_free(ver);
        OPENSSL_free(ver2);
        OPENSSL_free(ver3);
        OPENSSL_free(salt2);
    }
    errors();

    BN_free(s);
    BN_free(s2);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(v);
    BN_free(A);
    BN_free(B);
    BN_free(u);
    BN_free(u2);
    BN_free(Kc);
    BN_free(Ks);
    BN_free(zero);
    BN_CTX_free(ctx);
}

static void users(void)
{
    SRP_user_pwd *u = SRP_user_pwd_new(), *got;
    SRP_VBASE *vb = SRP_VBASE_new(NULL);
    SRP_gN *gN = SRP_get_default_gN("1536");

    printf("# users\n");
    check(u != NULL && u->id == NULL && u->s == NULL, "an empty user");
    SRP_user_pwd_set_gN(u, gN->g, gN->N);
    check(SRP_user_pwd_set1_ids(u, "eve", "Eve E.") == 1 && strcmp(u->id, "eve") == 0 && strcmp(u->info, "Eve E.") == 0,
          "SRP_user_pwd_set1_ids");
    check(SRP_user_pwd_set1_ids(u, "eve", NULL) == 1 && u->info == NULL, "no info");
    check(SRP_user_pwd_set0_sv(u, BN_new(), NULL) == 0, "no verifier");
    check(SRP_user_pwd_set0_sv(u, BN_new(), BN_new()) == 1, "SRP_user_pwd_set0_sv");
    check(SRP_VBASE_add0_user(vb, u) == 1, "SRP_VBASE_add0_user");
    got = SRP_VBASE_get_by_user(vb, "eve");
    check(got == u, "SRP_VBASE_get_by_user");
    got = SRP_VBASE_get1_by_user(vb, "eve");
    check(got != NULL && got != u && strcmp(got->id, "eve") == 0 && got->N == gN->N, "SRP_VBASE_get1_by_user copies");
    SRP_user_pwd_free(got);
    check(SRP_VBASE_get1_by_user(vb, "nobody") == NULL && SRP_VBASE_get_by_user(vb, "nobody") == NULL, "no such user");
    check(SRP_VBASE_get1_by_user(NULL, "eve") == NULL, "no base");
    SRP_VBASE_free(vb);
    SRP_VBASE_free(NULL);
    SRP_user_pwd_free(NULL);
}

static void vbase(void)
{
    char path[64], bad[64];
    char *salt = "Ivg1cfqFdfUp0pyv2rD4wD", *ver = NULL;
    FILE *f;
    SRP_VBASE *vb;
    SRP_user_pwd *u;
    SRP_gN *gN = SRP_get_default_gN("1024");

    printf("# a verifier file\n");
    snprintf(path, sizeof(path), "/tmp/rustyssl-srp-%ld.txt", (long)getpid());
    snprintf(bad, sizeof(bad), "/tmp/rustyssl-srp-bad-%ld.txt", (long)getpid());
    (void)SRP_create_verifier("alice", "password123", &salt, &ver, NULL, "1024");
    f = fopen(path, "w");
    fprintf(f, "# groups and users\n");
    fprintf(f, "I\t%s\t02\tmine\t\tmy group\n", N1024);
    fprintf(f, "V\t%s\t%s\talice\tmine\tAlice A.\n", ver, salt);
    fprintf(f, "V\t%s\t%s\tbob\t1024\t\n", ver, salt);
    fprintf(f, "V\t%s\t%s\tcarol\tnosuch\t\n", ver, salt);
    fprintf(f, "R\t%s\t%s\tdave\t1024\t\n", ver, salt);
    fclose(f);

    vb = SRP_VBASE_new("seed");
    check(SRP_VBASE_init(vb, path) == SRP_NO_ERROR, "SRP_VBASE_init");
    printf("  users %d, cache %d, default group %s\n", sk_SRP_user_pwd_num(vb->users_pwd),
           sk_SRP_gN_cache_num(vb->gN_cache),
           vb->default_N == NULL ? "none" : (BN_cmp(vb->default_N, gN->N) == 0 ? "1024's prime" : "another"));
    u = SRP_VBASE_get1_by_user(vb, "alice");
    check(u != NULL && strcmp(u->info, "Alice A.") == 0 && BN_cmp(u->N, gN->N) == 0 && u->N != gN->N,
          "alice, in the file's group");
    hex("alice's salt", u->s);
    check(SRP_check_known_gN_param(u->g, u->N) != NULL, "the file's group is a known one");
    SRP_user_pwd_free(u);
    u = SRP_VBASE_get1_by_user(vb, "bob");
    check(u != NULL && u->N == gN->N && u->info != NULL && u->info[0] == '\0', "bob, in the known group");
    SRP_user_pwd_free(u);
    u = SRP_VBASE_get1_by_user(vb, "zed");
    check(u != NULL && strcmp(u->id, "zed") == 0 && u->N == vb->default_N, "a made-up user");
    hex("zed's salt", u->s);
    SRP_user_pwd_free(u);
    check(SRP_VBASE_get_by_user(vb, "carol") == NULL && SRP_VBASE_get_by_user(vb, "dave") == NULL,
          "unknown groups and revoked users are left out");
    SRP_VBASE_free(vb);

    vb = SRP_VBASE_new(NULL);
    check(SRP_VBASE_init(vb, NULL) == SRP_ERR_OPEN_FILE, "no file name");
    errors();
    check(SRP_VBASE_init(vb, "/nonexistent/srp.txt") == SRP_ERR_OPEN_FILE, "no such file");
    ERR_clear_error();
    f = fopen(bad, "w");
    fprintf(f, "V\tonly\tthree\n");
    fclose(f);
    check(SRP_VBASE_init(vb, bad) == SRP_ERR_VBASE_INCOMPLETE_FILE, "too few fields");
    errors();
    f = fopen(bad, "w");
    fprintf(f, "V\t!!!!\t%s\tfrank\t1024\t\n", salt);
    fclose(f);
    check(SRP_VBASE_init(vb, bad) == SRP_ERR_VBASE_BN_LIB, "a verifier that isn't base64");
    errors();
    check(SRP_VBASE_get_by_user(vb, "frank") == NULL, "frank wasn't added");
    SRP_VBASE_free(vb);
    vb = SRP_VBASE_new("seed");
    f = fopen(bad, "w");
    fclose(f);
    check(SRP_VBASE_init(vb, bad) == SRP_NO_ERROR, "an empty file");
    printf("  default group %s\n",
           vb->default_N == NULL ? "none" : (BN_cmp(vb->default_N, SRP_get_default_gN(NULL)->N) == 0 ? "8192" : "?"));
    SRP_VBASE_free(vb);
    remove(path);
    remove(bad);
    OPENSSL_free(ver);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    calc();
    users();
    vbase();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
