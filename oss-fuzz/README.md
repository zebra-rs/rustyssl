# OSS-Fuzz and ClusterFuzzLite

rustyssl's fuzz targets (`fuzz/`, 108 of them, TEST_PLAN.md layer L9) run two ways:

- **In our CI, with ClusterFuzzLite** (`.clusterfuzzlite/`, `.github/workflows/cflite_*.yml`):
  every pull request builds the targets with AddressSanitizer and fuzzes the ones its change
  affects for 10 minutes in all (`code-change` mode), and a daily batch fuzzes them for an hour.
  A crash fails the job and uploads the reproducer.
- **On OSS-Fuzz**, once the project is accepted: this directory holds the three files OSS-Fuzz
  needs under `projects/rustyssl/` in [google/oss-fuzz](https://github.com/google/oss-fuzz).
  Submitting them is the maintainer's step (a pull request to google/oss-fuzz with these files,
  plus the contacts who receive crash reports); nothing here does it.

| File | Role |
|---|---|
| `build.sh` | Builds every target with `cargo fuzz build -O --debug-assertions` and copies it to `$OUT`. Shared: ClusterFuzzLite's Dockerfile copies this same file. `FUZZ_TARGETS="a b"` limits it to some targets. |
| `Dockerfile` | OSS-Fuzz's image: the Rust base builder and a clone of this repository. |
| `project.yaml` | OSS-Fuzz's metadata: Rust, libFuzzer, AddressSanitizer, x86_64. Add `auto_ccs` for more crash-report recipients before submitting. |

The fuzz crate is its own workspace because `libfuzzer-sys` compiles libFuzzer (C++), which
nothing that ships may depend on (README.md, security rule 8). The build overrides the pinned
stable toolchain with the base image's nightly, which cargo-fuzz needs.

Check a build locally (Docker, x86_64; the full set needs several GB of disk):

```sh
docker build -t rustyssl-cflite -f .clusterfuzzlite/Dockerfile .
docker run --rm -e SANITIZER=address -e FUZZ_TARGETS="buf_mem der" -v "$PWD/target/cflite-out:/out" \
  rustyssl-cflite compile
```
