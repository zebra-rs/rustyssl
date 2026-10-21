#!/bin/sh
# TEST_PLAN L11: the distro system tests, run inside one distribution's container by
# `cargo xtask test-distro`. Usage: scenarios.sh <debian|ubuntu|fedora|el|alpine> <package.tar.gz>
#
# Every scenario runs twice: on the distribution's own OpenSSL ("system"), then after
# `rustyssl-select rustyssl` put rustyssl's libraries first for every program ("rustyssl"). Each
# prints `RESULT <scenario> <phase> pass|fail`; the driver compares the two phases. Everything
# is local (servers on 127.0.0.1, a local package index), except the package manager's own
# HTTPS repositories.
set -u
DISTRO=$1
PACKAGE=$2
W=/tmp/l11
mkdir -p $W/www $W/pki
cd $W

log() { echo "== $*"; }
result() { # $1 scenario, $2 phase, $3 exit status
    if [ "$3" -eq 0 ]; then echo "RESULT $1 $2 pass"; else echo "RESULT $1 $2 fail"; fi
}
quiet() { "$@" > $W/last.log 2>&1; }

# --- Packages -----------------------------------------------------------------------------
log "installing the scenarios' packages"
case $DISTRO in
debian|ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq > /dev/null
    apt-get install -y -qq ca-certificates curl wget git openssh-server openssh-client nginx \
        apache2 python3 python3-pip postgresql postgresql-client openssl procps tar gzip \
        > /dev/null || exit 1
    ;;
fedora|el)
    dnf install -y -q curl wget git-core openssh-server openssh-clients nginx httpd mod_ssl \
        python3 python3-pip postgresql-server postgresql openssl crypto-policies-scripts \
        procps-ng findutils tar gzip shadow-utils util-linux > /dev/null || exit 1
    ;;
alpine)
    apk add -q curl wget git openssh nginx apache2 apache2-ssl python3 py3-pip postgresql \
        postgresql-client openssl procps tar shadow > /dev/null || exit 1
    ;;
esac
tar --keep-directory-symlink -xzf "$PACKAGE" -C / || exit 1
SELECT=$(ls /usr/lib*/rustyssl/bin/rustyssl-select /usr/lib/*/rustyssl/bin/rustyssl-select 2> /dev/null | head -1)
HOME_DIR=$(sed -n "s/^HOME_DIR='\(.*\)'$/\1/p" "$SELECT")
log "rustyssl is in $HOME_DIR"

# --- Keys and certificates (the system's openssl, once) -----------------------------------
log "making the test PKI"
cat > pki/ext.cnf <<'EOF'
[req]
distinguished_name = dn
[dn]
[server]
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = keyCertSign,cRLSign
EOF
mkcert() { # $1 name, $2 key bits, $3 digest: a server certificate for localhost from the CA
    openssl req -new -newkey rsa:$2 -nodes -keyout pki/$1.key -subj /CN=localhost \
        -config pki/ext.cnf -out pki/$1.csr 2> /dev/null &&
    openssl x509 -req -in pki/$1.csr -CA pki/ca.pem -CAkey pki/ca.key -CAcreateserial \
        -days 30 -$3 -extfile pki/ext.cnf -extensions server -out pki/$1.pem 2> /dev/null
}
openssl req -x509 -newkey rsa:3072 -nodes -keyout pki/ca.key -subj /CN=L11-CA -days 30 \
    -config pki/ext.cnf -extensions ca -out pki/ca.pem 2> /dev/null || exit 1
mkcert server 2048 sha256 || exit 1
mkcert rsa3072 3072 sha256 || exit 1
case $DISTRO in fedora|el)
    # Fedora's OpenSSL refuses SHA-1 signatures unless its configuration allows them.
    printf 'openssl_conf = init\n[init]\nalg_section = evp\n[evp]\nrh-allow-sha1-signatures = yes\n' \
        > pki/sha1.cnf
    OPENSSL_CONF=$W/pki/sha1.cnf mkcert sha1 3072 sha1 || { log "no SHA-1 certificate"; rm -f pki/sha1.pem; } ;;
esac
cat pki/server.pem pki/ca.pem > pki/chain.pem
echo hello > www/hello.txt

# A git repository served as files ("dumb" HTTP), and a package index with one wheel.
git init -q --bare www/repo.git
git -C www/repo.git config uploadpack.allowAnySHA1InWant true
(cd $W && rm -rf src && git init -q src && cd src && echo l11 > f &&
    git add f && git -c user.name=l11 -c user.email=l11@localhost commit -qm l11 &&
    git push -q ../www/repo.git HEAD:refs/heads/main) || exit 1
git -C www/repo.git symbolic-ref HEAD refs/heads/main
git -C www/repo.git update-server-info
mkdir -p www/simple/l11pkg
python3 - <<'EOF' || exit 1
import base64, hashlib, zipfile
name = "/tmp/l11/www/simple/l11pkg/l11pkg-1.0-py3-none-any.whl"
files = {
    "l11pkg/__init__.py": b"VALUE = 'l11'\n",
    "l11pkg-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: l11pkg\nVersion: 1.0\n",
    "l11pkg-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: l11\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
}
record = []
with zipfile.ZipFile(name, "w") as z:
    for path, data in files.items():
        z.writestr(path, data)
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{path},sha256={digest},{len(data)}")
    record.append("l11pkg-1.0.dist-info/RECORD,,")
    z.writestr("l11pkg-1.0.dist-info/RECORD", "\n".join(record) + "\n")
open("/tmp/l11/www/simple/l11pkg/index.html", "w").write(
    '<a href="l11pkg-1.0-py3-none-any.whl">l11pkg-1.0-py3-none-any.whl</a>\n')
open("/tmp/l11/www/simple/index.html", "w").write('<a href="l11pkg/">l11pkg</a>\n')
EOF
chmod -R a+rX $W

# --- Servers ----------------------------------------------------------------------------------
NGINX_CONF=$W/nginx.conf
cat > $NGINX_CONF <<EOF
daemon on;
user root;
pid $W/nginx.pid;
error_log $W/nginx.err;
events {}
http {
    access_log off;
    types { application/octet-stream whl; text/html html; }
    server {
        listen 127.0.0.1:8443 ssl;
        server_name localhost;
        ssl_certificate $W/pki/chain.pem;
        ssl_certificate_key $W/pki/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        root $W/www;
        autoindex on;
    }
}
EOF
MODS=$(dirname "$(find / -name mod_ssl.so -not -path '/proc/*' 2> /dev/null | head -1)")
HTTPD=$(command -v apache2 || command -v httpd)
cat > $W/httpd.conf <<EOF
ServerRoot $W
DefaultRuntimeDir $W
PidFile $W/httpd.pid
ErrorLog $W/httpd.err
LogLevel warn
LoadModule mpm_event_module $MODS/mod_mpm_event.so
LoadModule authz_core_module $MODS/mod_authz_core.so
LoadModule unixd_module $MODS/mod_unixd.so
LoadModule ssl_module $MODS/mod_ssl.so
User #65534
Group #65534
Listen 127.0.0.1:9443
ServerName localhost
<VirtualHost 127.0.0.1:9443>
    DocumentRoot $W/www
    SSLEngine on
    SSLCertificateFile $W/pki/chain.pem
    SSLCertificateKeyFile $W/pki/server.key
    <Directory $W/www>
        Require all granted
    </Directory>
</VirtualHost>
EOF
# Modules some builds have built in: drop the LoadModule lines for those.
for m in mpm_event unixd authz_core; do
    [ -f "$MODS/mod_$m.so" ] || sed -i "/mod_$m.so/d" $W/httpd.conf
done

# sshd (an absolute path, which it needs to re-execute itself): host keys, root logins by key.
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
mkdir -p /run/sshd /root/.ssh
chmod 700 /root/.ssh
sed -i -E 's/^root:[^:]*:/root:*:/' /etc/shadow
ssh-keygen -A > /dev/null 2>&1
for t in ed25519 ecdsa rsa; do
    ssh-keygen -q -t $t -N '' -f $W/id_$t
    cat $W/id_$t.pub >> /root/.ssh/authorized_keys
done
chmod 600 /root/.ssh/authorized_keys

# PostgreSQL: one cluster, TLS only.
INITDB=$(command -v initdb || ls /usr/lib/postgresql/*/bin/initdb /usr/libexec/postgresql*/initdb \
    2> /dev/null | head -1)
PGBIN=$(dirname "$INITDB")
PGDATA=$W/pgdata
mkdir -p $PGDATA && chown postgres $PGDATA
su postgres -s /bin/sh -c "$INITDB -D $PGDATA -A trust" > /dev/null 2>&1 || log "initdb failed"
cp pki/server.key pki/chain.pem $PGDATA/ && chown postgres $PGDATA/server.key $PGDATA/chain.pem
chmod 600 $PGDATA/server.key
cat >> $PGDATA/postgresql.conf <<EOF
listen_addresses = 'localhost'
port = 5433
unix_socket_directories = '$PGDATA'
ssl = on
ssl_cert_file = 'chain.pem'
ssl_key_file = 'server.key'
EOF
printf 'hostssl all all 127.0.0.1/32 trust\nhostssl all all ::1/128 trust\n' > $PGDATA/pg_hba.conf
chown postgres $PGDATA/postgresql.conf $PGDATA/pg_hba.conf

start_servers() {
    nginx -c $NGINX_CONF || log "nginx failed to start"
    $HTTPD -f $W/httpd.conf -k start || log "httpd failed to start"
    $SSHD -p 2222 -o PidFile=$W/sshd.pid -o PermitRootLogin=prohibit-password \
        -o PasswordAuthentication=no 2> $W/sshd.err || { log "sshd failed to start"; cat $W/sshd.err; }
    su postgres -s /bin/sh -c "$PGBIN/pg_ctl -D $PGDATA -l $PGDATA/pg.log -w start" > /dev/null ||
        { log "postgres failed to start"; tail -5 $PGDATA/pg.log; }
    sleep 1
}
stop_servers() {
    nginx -c $NGINX_CONF -s stop 2> /dev/null
    $HTTPD -f $W/httpd.conf -k stop 2> /dev/null
    [ -f $W/sshd.pid ] && kill "$(cat $W/sshd.pid)" 2> /dev/null
    su postgres -s /bin/sh -c "$PGBIN/pg_ctl -D $PGDATA -w stop" > /dev/null 2>&1
    sleep 2
}

# --- Scenarios --------------------------------------------------------------------------------
CURL="curl -sS --max-time 20 --cacert $W/pki/ca.pem"
pkg_https() {
    case $DISTRO in
    debian|ubuntu)
        # apt fetches with GnuTLS, not OpenSSL, but the scenario is in the plan all the same.
        for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
            [ -f "$f" ] && sed -i 's|http://|https://|g' "$f"
        done
        quiet apt-get update ;;
    fedora|el) quiet dnf -q makecache --refresh ;;
    alpine) quiet apk update ;;
    esac
}
scenarios() { # $1 phase
    p=$1
    start_servers
    pkg_https; result package-manager-https $p $?
    for t in ed25519 ecdsa rsa; do
        quiet ssh -i $W/id_$t -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null root@127.0.0.1 true
        result ssh-login-$t $p $?
    done
    [ "$($CURL https://localhost:8443/hello.txt 2> $W/last.log)" = hello ]; result nginx-curl $p $?
    [ "$($CURL --tlsv1.2 --tls-max 1.2 https://localhost:8443/hello.txt 2> $W/last.log)" = hello ]
    result nginx-curl-tls1.2 $p $?
    [ "$($CURL https://localhost:9443/hello.txt 2> $W/last.log)" = hello ]; result httpd-curl $p $?
    [ "$(wget -q -O- --ca-certificate=$W/pki/ca.pem https://localhost:8443/hello.txt 2> $W/last.log)" = hello ]
    result wget $p $?
    rm -rf $W/clone
    quiet git -c http.sslCAInfo=$W/pki/ca.pem clone -q https://localhost:8443/repo.git $W/clone &&
        [ "$(cat $W/clone/f)" = l11 ]
    result git-clone $p $?
    rm -rf $W/pip-$p
    quiet python3 -m pip install -q --no-cache-dir --break-system-packages --target $W/pip-$p \
        --index-url https://localhost:8443/simple/ --cert $W/pki/ca.pem l11pkg &&
        [ "$(PYTHONPATH=$W/pip-$p python3 -c 'import l11pkg; print(l11pkg.VALUE)')" = l11 ]
    result pip-install $p $?
    [ "$(PGSSLROOTCERT=$W/pki/ca.pem $PGBIN/psql -Atc 'select ssl from pg_stat_ssl where pid = pg_backend_pid()' \
        'host=localhost port=5433 user=postgres dbname=postgres sslmode=verify-full' 2> $W/last.log)" = t ]
    result postgresql-verify-full $p $?
    loaded $p
    if [ "$(readlink -f "$(command -v openssl)")" = "$HOME_DIR/bin/openssl" ]; then
        where=rustyssl
    else
        where=system
    fi
    [ "$where" = "$p" ]; result openssl-tool-is-$p $p $?
    case $DISTRO in fedora|el) crypto_policies $p ;; esac
    stop_servers
}

# Which libraries the programs loaded: rustyssl's after the switch, the system's before.
loaded() {
    maps=$(python3 -c "import ssl; print(''.join(l for l in open('/proc/self/maps') if 'libssl.so' in l))")
    case "$maps" in
    *"$HOME_DIR"*) where=rustyssl ;;
    *) where=system ;;
    esac
    [ "$where" = "$1" ]; result python-loads-$1-libssl $1 $?
    pid=$(cat $W/sshd.pid 2> /dev/null)
    case "$(cat /proc/$pid/maps 2> /dev/null)" in
    *"$HOME_DIR/libcrypto"*) where=rustyssl ;;
    *) where=system ;;
    esac
    [ "$where" = "$1" ]; result sshd-loads-$1-libcrypto $1 $?
}

# Fedora's crypto policies: what curl (on the libraries under test, reading the policy through
# openssl.cnf) accepts from permissive servers, under each policy. The two phases must agree.
crypto_policies() {
    p=$1
    probe() { # $1 name, $2 certificate, then s_server options
        name=$1 cert=$2
        shift 2
        OPENSSL_CONF=/dev/null openssl s_server -quiet -accept 127.0.0.1:7443 -www \
            -cert $W/pki/$cert.pem -key $W/pki/$cert.key -cert_chain $W/pki/ca.pem \
            -cipher 'ALL:@SECLEVEL=0' "$@" > /dev/null 2>&1 &
        spid=$!
        sleep 1
        quiet $CURL -o /dev/null https://localhost:7443/
        r=$?
        kill $spid 2> /dev/null
        wait $spid 2> /dev/null
        result "policy-$policy-$name" $p $r
    }
    for policy in DEFAULT LEGACY FUTURE; do
        quiet update-crypto-policies --set $policy
        probe rsa2048-tls1.3 server
        probe rsa3072-tls1.3 rsa3072
        probe rsa3072-tls1.2 rsa3072 -tls1_2
        probe rsa3072-tls1.1 rsa3072 -tls1_1
        [ -s $W/pki/sha1.pem ] && probe sha1-signed sha1
        probe rsa-kx-tls1.2 rsa3072 -tls1_2 -cipher 'AES256-SHA:@SECLEVEL=0'
        probe cbc-sha1-tls1.2 rsa3072 -tls1_2 -cipher 'ECDHE-RSA-AES128-SHA:@SECLEVEL=0'
    done
    quiet update-crypto-policies --set DEFAULT
}

log "system phase"
scenarios system
log "switching to rustyssl"
"$SELECT" rustyssl || exit 1
hash -r
[ "$("$SELECT" status)" = rustyssl ] || exit 1
log "openssl is now: $(openssl version)"
scenarios rustyssl
"$SELECT" system > /dev/null
hash -r
[ "$("$SELECT" status)" = system ]; result select-back-to-system rustyssl $?
echo "== done"
