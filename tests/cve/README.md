# The CVE regression suite

`cargo xtask test-cve` (TEST_PLAN.md, layer L9; AGENTS.md rule 11).

- `cves.txt`: every OpenSSL CVE and how it's covered (the kinds are explained at its top).
  The driver fails when the reference's `CHANGES.md` names a CVE missing here, when a `test`
  entry has no passing check naming it, or when an `apps` entry's corpus has no `# CVE-...`
  comment.
- `cve_*.c`: TAP programs by area (ASN.1, X.509, PKCS#7/CMS/PKCS#12/TS, CMP exchanges, public
  keys, ciphers, BIO, TLS, DTLS associations, QUIC, thread races, lengths near INT_MAX), with
  the shared helpers in `cve.h`. Each check's description
  starts with the CVE it guards. They run on the reference and on rustyssl, in `data/`, and
  must pass with identical output: print outcomes (results, error codes, alerts, lengths),
  never random values.
- `cve_size.c` works on lengths near INT_MAX: it maps about 4 GB (touching up to 3.7 GB, for
  EVP_EncodeUpdate's 1.6 GB of input) and takes a few seconds. Where the address space isn't
  there, its checks print `# skip`.
- `data/`: inputs the programs read. Most are upstream's own regression files, copied from
  the reference's source tree (`test/recipes/80-test_cms_data/`, `80-test_cmsapi_data/`,
  `80-test_pkcs12_data/`, `test/d2i-tests/`, `test/certs/`, `test/smime-certs/`); they are
  OpenSSL's, under the Apache License 2.0. `rsa2048.pem` is a fixed key made for this suite,
  so implicit rejection's synthetic messages are the same on every run.
