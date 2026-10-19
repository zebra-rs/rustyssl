/* A module with no OSSL_provider_init (tests/c/provider_ext.c): loading it fails. */

int not_a_provider(void);

int not_a_provider(void)
{
    return 0;
}
