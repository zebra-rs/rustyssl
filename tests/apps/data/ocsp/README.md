Fixtures for `tests/apps/ocsp.txt`, made once with the reference's `openssl`:

- `ND1.der` ... `ISDOSC_D1.der`: upstream's `test/ocsp-tests/*.ors`, base64-decoded;
- `index.txt` (with `index.txt.attr`): a CA database for the responder (`ocsp.pem` of
  `test/ocsp-tests`), with revocations of every kind `unpack_revinfo` reads, and broken ones;
  `dup-index.txt` (a serial number twice) and `bad-index.txt` (a short row) for the errors;
- `req.der`: `ocsp -issuer intermediate-cert.pem -cert server-cert.pem -serial 1 ... -serial 99
  -no_nonce -reqout req.der`; `req-nonce.der`: one certificate, with a nonce;
- `resp.der`: `ocsp -index index.txt -rsigner ocsp.pem -CA intermediate-cert.pem -reqin req.der
  -ndays 36500 -respout resp.der`; `resp-nonce.der`: for `req-nonce.der`, with `-nmin 10`.
