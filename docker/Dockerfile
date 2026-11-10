# syntax=docker/dockerfile:1
#
# orc dev image: Rust + SP1 (cargo-prove, succinct toolchain, riscv64 C toolchain)
# + Go/clang (sp1-sdk `native-gnark`) + Foundry.
#
# Every version below is pinned so the guest ELF (and therefore the SP1 program
# vkey) is reproducible across machines. See docker/README.md for usage.

ARG RUST_VERSION=1.99.1
# Debian trixie, NOT bookworm: the riscv64 C toolchain that `sp1up --c-toolchain`
# installs for SP1 v6 (succinctlabs/riscv-gnu-toolchain 2026.02.13) needs
# GLIBC_2.38; bookworm ships glibc 2.36 and riscv64-unknown-elf-gcc fails with
# "version `GLIBC_2.38' not found".
FROM rust:${RUST_VERSION}-trixie

# --- pinned versions ---------------------------------------------------------
# SP1: sp1up is fetched from the same git tag as the cargo-prove release.
ARG SP1_VERSION=v6.10.0
# Go: sp1 v6.10.0 crates/recursion/gnark-ffi/go/go.mod requires go >= 1.24.0.
ARG GO_VERSION=1.26.10
ARG GO_SHA256_AMD64=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5
ARG GO_SHA256_ARM64=3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797
# Foundry: the Rust `foundryup` installer version, then the Foundry release it installs.
ARG FOUNDRYUP_VERSION=0.0.8
ARG FOUNDRY_VERSION=v1.8.7

# --- user mapping --------------------------------------------------------------
# Match the host UID/GID so files written into the bind-mounted repo are owned
# by the host user, not root.
ARG UID=1000
ARG GID=1000
ARG USERNAME=dev

ENV DEBIAN_FRONTEND=noninteractive

# System packages. clang/libclang-dev: bindgen + cgo for sp1-recursion-gnark-ffi
# (`native-gnark`); protobuf-compiler + libprotobuf-dev: prost-build in
# sp1-prover-types needs protoc AND the well-known types (google/protobuf/empty.proto).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev git curl ca-certificates \
        clang libclang-dev protobuf-compiler libprotobuf-dev; \
    rm -rf /var/lib/apt/lists/*

# Go from the official tarball, checksum-verified.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) sha="$GO_SHA256_AMD64" ;; \
        arm64) sha="$GO_SHA256_ARM64" ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"; \
    echo "${sha}  /tmp/go.tgz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz

# Non-root user. --no-log-init avoids multi-GB sparse lastlog/faillog files when
# the host UID is large (e.g. domain accounts). Reuses an existing group with
# that GID (e.g. GID 20 on macOS hosts) and tolerates a clashing UID.
RUN set -eux; \
    if ! getent group "${GID}" >/dev/null; then groupadd --gid "${GID}" "${USERNAME}"; fi; \
    useradd --no-log-init --non-unique --uid "${UID}" --gid "${GID}" \
        --create-home --shell /bin/bash "${USERNAME}"; \
    # Mount points for named volumes must exist with the right owner, otherwise
    # Docker creates them as root and the user cannot write to them.
    mkdir -p /usr/local/cargo/registry /usr/local/cargo/git /cargo-target /workspace; \
    chown "${UID}:${GID}" /usr/local/cargo/registry /usr/local/cargo/git /cargo-target /workspace

USER ${USERNAME}
ENV HOME=/home/${USERNAME}

# SP1: cargo-prove + succinct rustc toolchain + riscv64 C toolchain (for crates
# with C code such as ring). Version and --c-toolchain MUST go in the same
# invocation: sp1up picks rv32 vs rv64 from the publish date of the requested
# release, and a bare `sp1up --c-toolchain` would also reinstall `latest`.
RUN set -eux; \
    mkdir -p "$HOME/.sp1/bin"; \
    curl -fsSL -o "$HOME/.sp1/bin/sp1up" \
        "https://raw.githubusercontent.com/succinctlabs/sp1/${SP1_VERSION}/sp1up/sp1up"; \
    chmod +x "$HOME/.sp1/bin/sp1up"; \
    "$HOME/.sp1/bin/sp1up" --version "${SP1_VERSION}" --c-toolchain; \
    # Fail the build if sp1up silently fell back to the rv32 toolchain (it does
    # when the GitHub API call for the publish date fails, e.g. rate limiting).
    test -x "$HOME/.sp1/bin/riscv64-unknown-elf-gcc"; \
    "$HOME/.sp1/bin/riscv64-unknown-elf-gcc" --version; \
    rm -f "$HOME"/.sp1/rust-toolchain-*.tar.gz; \
    mkdir -p "$HOME/.sp1/circuits"; \
    "$HOME/.sp1/bin/cargo-prove" prove --version; \
    # The succinct toolchain ships rustc only (no cargo): `cargo +succinct` is
    # expected to fail; sp1-build runs the default cargo with RUSTC=succinct.
    rustc +succinct --version

# Foundry via the (Rust) foundryup installer, both pinned.
RUN set -eux; \
    curl -fsSL -o /tmp/foundryup-init.sh \
        "https://raw.githubusercontent.com/foundry-rs/foundryup/v${FOUNDRYUP_VERSION}/foundryup-init.sh"; \
    FOUNDRYUP_VERSION="${FOUNDRYUP_VERSION}" sh /tmp/foundryup-init.sh -y; \
    rm /tmp/foundryup-init.sh; \
    "$HOME/.foundry/bin/foundryup" --install "${FOUNDRY_VERSION}"; \
    "$HOME/.foundry/bin/forge" --version

# Go module cache lives under GOPATH so it can be persisted in a named volume.
RUN mkdir -p "$HOME/go/pkg/mod"

ENV PATH=/home/${USERNAME}/.sp1/bin:/home/${USERNAME}/.foundry/bin:/usr/local/go/bin:/home/${USERNAME}/go/bin:${PATH} \
    GOPATH=/home/${USERNAME}/go \
    GOTOOLCHAIN=local \
    CC_riscv64im_succinct_zkvm_elf=/home/${USERNAME}/.sp1/bin/riscv64-unknown-elf-gcc

# SP1 v6 runs the native executor as a child binary. By default the build script of
# sp1-core-executor-runner builds it into the shared $CARGO_TARGET_DIR/sp1-native-bins for
# EVERY feature set and embeds it with include_bytes!. A `profiling` build (portable executor,
# so the binary is an empty `fn main() {}`) overwrites the native binary, and the next default
# build embeds that stub. Every execute/prove then fails with "failed sending input to child:
# Broken pipe". The fix is to prebuild the runner once and use the upstream override. The
# runner version MUST equal the sp1-sdk version in every Cargo.lock (bump SP1_VERSION together).
RUN set -eux; \
    cargo install --locked --version "${SP1_VERSION#v}" sp1-core-executor-runner-binary; \
    rm -rf /usr/local/cargo/registry/* /usr/local/cargo/git/*
ENV SP1_CORE_RUNNER_OVERRIDE_BINARY=/usr/local/cargo/bin/sp1-core-executor-runner-binary

# rustfmt + clippy for the pinned toolchain (the rust image installs the minimal
# profile, without them). Last on purpose so adding it does not invalidate the
# expensive SP1/Foundry layers above; the official image leaves RUSTUP_HOME
# world-writable, so the non-root user can add components.
ARG RUST_VERSION
RUN rustup component add --toolchain "${RUST_VERSION}" rustfmt clippy

WORKDIR /workspace
CMD ["bash"]
