# orc dev container

The whole toolchain lives in one image so it is identical on every machine
(and the SP1 guest ELF, hence the program vkey, is reproducible).

| Tool | Version |
|---|---|
| Rust (base image) | `rust:1.99.1-trixie` (Debian 13; bookworm's glibc 2.36 is too old for the SP1 riscv64 C toolchain, which needs 2.38) |
| SP1 (`cargo prove`, `succinct` toolchain) | v6.10.0 via `sp1up --version v6.10.0 --c-toolchain` |
| RISC-V C toolchain | `~/.sp1/bin/riscv64-unknown-elf-gcc` (`CC_riscv64im_succinct_zkvm_elf` is set) |
| Go (for sp1-sdk `native-gnark`) | 1.26.10, `GOTOOLCHAIN=local` |
| Foundry | v1.8.7 via foundryup 0.0.8 |
| clang, protoc (+ libprotobuf-dev well-known types) | Debian trixie packages |

All versions are build args at the top of `docker/Dockerfile`.

The `succinct` toolchain ships `rustc` only, so `cargo +succinct --version`
fails by design; check it with `rustc +succinct --version`. Guest builds go
through `sp1-build` / `cargo prove build`, which run the default `cargo` with
the succinct `rustc`.

## Build

Files the container writes into the repo must be owned by you, so the image
user gets your UID/GID. Do this once per machine:

```bash
printf 'DEV_UID=%s\nDEV_GID=%s\n' "$(id -u)" "$(id -g)" > .env   # gitignored
docker compose build
```

Or inline: `DEV_UID=$(id -u) DEV_GID=$(id -g) docker compose build`.
Do NOT use `UID=$(id -u) ...`: `UID` is read-only in bash, the assignment is
rejected and the image silently gets UID 1000. Without `.env` the IDs default
to 1000.

## Use

```bash
docker compose run --rm dev bash                  # interactive shell in /workspace
docker compose run --rm dev cargo prove --version # one-off command
```

- The repo is bind-mounted at `/workspace`.
- `CARGO_TARGET_DIR=/cargo-target` is a named volume, so container builds never
  touch (or fight with) host `target/` dirs.
- Named volumes also keep the cargo registry/git cache, the Go module cache,
  and `~/.sp1/circuits` (Groth16 artifacts, several GB, downloaded on the first
  Groth16 proof). Only that subdirectory is a volume. Mounting all of `~/.sp1`
  would hide the SP1 toolchain baked into the image.
- No memory limit is set. A Groth16 wrap needs about 14 GB of RAM.
- `shm_size: 16gb`: SP1 v6 executes the guest in a child process that shares
  memory through `/dev/shm`. With Docker's 64 MB default, execution dies with
  `Child native executor crashed ... signal: 7` (SIGBUS). The value is a cap,
  not a reservation.
- Guest cycle tracking (`cycle-tracker-report-*` markers) needs sp1-sdk's
  `profiling` feature in SP1 v6; without it the markers are ignored.
- `docker compose down -v` deletes the volumes (caches and circuits).

## Another machine

1. Clone the repo and install Docker (with Compose v2).
2. Write `.env` with that machine's IDs (command above) and run
   `docker compose build`. The build downloads everything from pinned URLs;
   nothing is needed on the host besides Docker.
3. The build calls the GitHub API a few times (sp1up). If it fails with
   rate-limit errors, wait or retry from another network.

linux/amd64 is the tested platform. ARM hosts (e.g. Apple Silicon) are
untested for the SP1 toolchain: sp1up and Go have arm64 downloads, but the SP1
prover, `native-gnark` and the RISC-V C toolchain have not been tried there.
