# ClusterFuzzLite's build image (oss-fuzz/README.md): the checkout under test, built by the same
# build.sh OSS-Fuzz uses.
FROM gcr.io/oss-fuzz-base/base-builder-rust
COPY . $SRC/rustyssl
WORKDIR $SRC/rustyssl
COPY oss-fuzz/build.sh $SRC/
