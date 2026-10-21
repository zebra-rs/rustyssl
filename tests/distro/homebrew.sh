#!/bin/sh
# TEST_PLAN L11, macOS: Homebrew's Python on Homebrew's openssl@3 ("system"), then on rustyssl's
# keg through DYLD_LIBRARY_PATH ("rustyssl"), without touching the Homebrew installation.
# Usage: homebrew.sh <rustyssl's lib directory> <work directory>
# (Homebrew's curl links openssl@4, so it can't take rustyssl's 3.x libraries.)
set -u
LIB=$1
W=$2
BREW=$(brew --prefix)
OPENSSL=$BREW/opt/openssl@3/bin/openssl
# The newest Homebrew Python whose ssl module links openssl@3 (newer ones link openssl@4).
PY=
for py in $(ls -d "$BREW"/opt/python@3.1[0-9]/bin/python3.1[0-9] 2> /dev/null); do
    v=$(basename "$py" | sed 's/python//')
    if otool -L "$BREW"/opt/python@$v/Frameworks/Python.framework/Versions/$v/lib/python$v/lib-dynload/_ssl*.so \
        2> /dev/null | grep -q 'openssl@3/lib/libssl'; then PY=$py; fi
done
[ -n "$PY" ] || { echo "no Homebrew Python links openssl@3"; exit 1; }
mkdir -p "$W/www" "$W/pki"
cd "$W" || exit 1
result() { if [ "$3" -eq 0 ]; then echo "RESULT $1 $2 pass"; else echo "RESULT $1 $2 fail"; fi; }

echo "== Python: $PY"
"$OPENSSL" req -x509 -newkey rsa:3072 -nodes -keyout pki/ca.key -subj /CN=L11-CA -days 30 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=keyCertSign -out pki/ca.pem 2> /dev/null
"$OPENSSL" req -new -newkey rsa:2048 -nodes -keyout pki/server.key -subj /CN=localhost \
    -out pki/server.csr 2> /dev/null
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > pki/ext.cnf
"$OPENSSL" x509 -req -in pki/server.csr -CA pki/ca.pem -CAkey pki/ca.key -CAcreateserial \
    -days 30 -extfile pki/ext.cnf -out pki/server.pem 2> /dev/null || exit 1
echo hello > www/hello.txt

# The server stays on Homebrew's OpenSSL.
"$PY" - > server.log 2>&1 <<EOF &
import http.server, ssl, functools
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("$W/pki/server.pem", "$W/pki/server.key")
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory="$W/www")
httpd = http.server.HTTPServer(("127.0.0.1", 8444), handler)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
EOF
SERVER=$!
sleep 2

client() { # $1 phase, then the environment
    p=$1
    shift
    env "$@" "$PY" -c "
import ssl, urllib.request
ctx = ssl.create_default_context(cafile='$W/pki/ca.pem')
assert urllib.request.urlopen('https://localhost:8444/hello.txt', context=ctx).read() == b'hello\n'
" > last.log 2>&1
    result python-urllib-https $p $?
    env "$@" "$PY" -c "
import ssl, urllib.request
ctx = ssl.create_default_context(cafile='$W/pki/ca.pem')
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
assert urllib.request.urlopen('https://localhost:8444/hello.txt', context=ctx).read() == b'hello\n'
" > last.log 2>&1
    result python-urllib-tls1.2 $p $?
    env "$@" "$PY" -c "
import hashlib
assert hashlib.sha256(b'abc').hexdigest().startswith('ba7816bf')
assert hashlib.new('sha3_256', b'').hexdigest().startswith('a7ffc6f8')
" > last.log 2>&1
    result python-hashlib $p $?
    env "$@" DYLD_PRINT_LIBRARIES=1 "$PY" -c "import ssl" 2> loaded.log
    if grep -q "$LIB/libssl.3.dylib" loaded.log; then where=rustyssl; else where=system; fi
    [ "$where" = "$p" ]; result python-loads-$p-libssl $p $?
}
client system NOTHING=1
client rustyssl DYLD_LIBRARY_PATH="$LIB"
kill $SERVER
echo "== done"
