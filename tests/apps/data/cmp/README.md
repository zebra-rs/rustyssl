# `openssl cmp` corpus data

`cmp.cnf` is the configuration file of `tests/apps/cmp.txt`'s configuration-file cases
(`-config`, `-section`, the values `read_config` takes, the verification and provider options
given there) and of the cases that need an option only a configuration file can set:
`ref_cert` (on the command line, upstream's `-ref_cert` sets `-rsp_cert`'s variable).

Its paths are relative to test-apps' work directory (`target/xtask/test-apps`), from which the
reference's source tree is `../../ref/openssl-<version>/src`; the credentials are upstream's,
in `test/recipes/80-test_cmp_http_data/Mock/`. Update the version in `M` when the vendored
release changes.
