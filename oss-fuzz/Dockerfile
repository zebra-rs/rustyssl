# OSS-Fuzz's projects/rustyssl/Dockerfile (README.md in this directory).
FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN git clone --depth 1 https://github.com/zebra-rs/rustyssl.git rustyssl
WORKDIR $SRC/rustyssl
COPY build.sh $SRC/
