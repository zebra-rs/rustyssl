# rustyssl for Fedora and RHEL 10 (and its rebuilds), side by side with the system's OpenSSL.
# Builds with the pinned Rust toolchain (rustup); Fedora's own Rust may be older.
%global layout %{?rhel:el}%{!?rhel:fedora}
%global debug_package %{nil}

Name:           rustyssl
Version:        3.6.5
Release:        0.1.0%{?dist}
Summary:        Memory-safe drop-in replacement for OpenSSL's libraries
License:        Apache-2.0
URL:            https://github.com/zebra-rs/rustyssl
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  gcc binutils
ExclusiveArch:  x86_64 aarch64

%description
rustyssl reimplements libcrypto.so.3 and libssl.so.3 in Rust with OpenSSL 3's ABI,
including Fedora's extras (MD2, the SCTP functions, the OPENSSL_3.1.0 versions of
EVP_{MD,CIPHER}_CTX_dup), and the openssl command-line tool. It is installed under
%{_libdir}/rustyssl; run "rustyssl-select rustyssl" to make every program use it,
and "rustyssl-select system" to go back. It reads the system's crypto policies.

%prep
%autosetup

%build
cargo xtask package %{layout}

%install
mkdir -p %{buildroot}
cp -a target/package/%{layout}/root/. %{buildroot}/

%preun
# Select the system's OpenSSL again before the files go away (not on upgrade).
if [ "$1" -eq 0 ] && [ "$(%{_libdir}/rustyssl/bin/rustyssl-select status)" = rustyssl ]; then
    %{_libdir}/rustyssl/bin/rustyssl-select system
fi

%files
%license LICENSE.txt
%{_libdir}/rustyssl
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.cnf.dist
%config(noreplace) %{_sysconfdir}/pki/tls/ct_log_list.cnf.dist

%changelog
* Wed Oct 21 2026 rustyssl developers <rustyssl@localhost> - 3.6.5-0.1.0
- OpenSSL 3.6.5's ABI with the Fedora profile, side by side with the system's OpenSSL.
