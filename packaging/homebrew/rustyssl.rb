# A keg-only Homebrew formula for rustyssl: OpenSSL 3's libraries and tool, in Rust.
# Programs use it through its install names (opt/rustyssl/lib/libcrypto.3.dylib, ...) or
# DYLD_LIBRARY_PATH; it never replaces openssl@3.
class Rustyssl < Formula
  desc "Memory-safe drop-in replacement for OpenSSL's libraries"
  homepage "https://github.com/zebra-rs/rustyssl"
  url "https://github.com/zebra-rs/rustyssl/archive/refs/tags/v1.0.1.tar.gz"
  license "Apache-2.0"

  keg_only "it provides the same libraries as openssl@3"

  depends_on "rustup" => :build

  def install
    system "rustup", "show" # installs the toolchain rust-toolchain.toml pins
    system "cargo", "xtask", "package", "homebrew", "--prefix", prefix,
           "--openssldir", etc/"rustyssl"
    cp_r Dir["target/package/homebrew/root#{prefix}/*"], prefix
    (etc/"rustyssl").install Dir["target/package/homebrew/root#{etc}/rustyssl/*"]
  end

  test do
    assert_match "OpenSSL 3", shell_output("#{bin}/openssl version")
    assert_equal "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                 pipe_output("#{bin}/openssl dgst -sha256 -r", "abc").split.first
  end
end
