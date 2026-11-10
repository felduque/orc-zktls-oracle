# orc: zk-TLS GitHub oracle (proof of concept)

> **Español:** este README está en inglés. Una traducción al español es bienvenida (abrí un PR).

orc lets a GitHub user prove on-chain that **"the account that owns my token has at least N
commits in repo X"**, bound to one Ethereum address, without revealing the token to anyone. The
prover fetches the answer from `api.github.com` over MPC-TLS ([TLSNotary](https://github.com/tlsnotary/tlsn))
together with a notary that never sees the plaintext. An [SP1](https://github.com/succinctlabs/sp1)
zkVM guest then verifies the notarized transcript and the predicate, and a Groth16 proof of that
guest is checked by a Solidity contract (`OrcClaim`) that allows one claim per GitHub account per
campaign. The point is to validate the stack end to end (TLSNotary alpha.15, SP1 v6, EVM). The use
case itself is not new (see [Prior art](#prior-art-and-credits)).

> [!WARNING]
> **Status: proof of concept.** Unaudited, testnet only (Base Sepolia). The notary is a single
> trusted party and `presentation.bin` files contain your GitHub data. Read
> [Trust model](#trust-model-and-privacy) before using it, and don't use it to protect anything
> of value. See [SECURITY.md](SECURITY.md).

## Contents

- [How it works](#how-it-works)
- [Trust model and privacy](#trust-model-and-privacy)
- [What gets checked](#what-gets-checked)
- [Repository layout](#repository-layout)
- [Quickstart (Docker dev environment)](#quickstart-docker-dev-environment)
- [Measured numbers](#measured-numbers)
- [Milestones](#milestones)
- [Known limitations and future work](#known-limitations-and-future-work)
- [Reproducibility](#reproducibility)
- [Prior art and credits](#prior-art-and-credits)
- [License](#license)

## How it works

```
                          (1) preflight, plain HTTPS outside MPC: viewer.id
          +-------------+ ------------------------------------------------> +----------------+
          |     orc     |                                                   |                |
          |  (prover)   | ==== (2) TLS 1.2 to api.github.com:443 =========> | api.github.com |
          |             |      one POST /graphql; TLS keys are              |                |
          +-------------+      secret-shared with the notary (MPC)          +----------------+
             |       ^
   MPC-TLS   |       |  (3) signed attestation (secp256k1 over SHA-256 commitments);
   protocol  v       |      the notary never sees plaintext or the token
          +-------------+
          | orc-notary  |
          +-------------+
             |
             v  (4) prover builds the presentation and self-checks it natively
   presentation.bin   Authorization value hidden, everything else revealed
   guest-input.json   eth address, chain id, campaign id, owner, name, threshold
             |
             v  (5) orc-script: SP1 guest runs orc_core::verify_claim
          +---------------------+
          | SP1 guest           | --> commits abi.encode(PublicValues), 256 bytes
          | (program/)          |
          +---------------------+
             |  (6) SP1 Groth16 wrap
             v
          +---------------------+     verifyProof      +-------------------------------+
          | OrcClaim.sol        | -------------------> | SP1VerifierGateway (Groth16)  |
          | claim(pv, proof)    |                      | Base Sepolia, SP1 v6.1.0      |
          +---------------------+                      +-------------------------------+
```

Claim flow:

1. **Preflight.** `orc` calls the GitHub GraphQL API once over plain HTTPS (outside MPC) to learn
   the token owner's node id (`viewer.id`). The notarized query needs it as a variable.
2. **MPC-TLS session.** `orc` opens a TLS 1.2 connection to `api.github.com` whose session keys
   are secret-shared with `orc-notary`. Over it, `orc` sends exactly one `POST /graphql` with a
   fixed header set, including `Authorization: bearer <token>` and
   `X-Orc-Binding: keccak256(abi.encode(ethAddress, chainId, campaignId))`. The query returns the
   viewer's `login`, `databaseId` and `id`, the repo's `databaseId`, and `totalCount` of the
   default-branch commits authored by the viewer.
3. **Attestation.** The prover commits (SHA-256) to everything it will reveal: the whole response
   and the whole request except the `Authorization` value. The notary signs an attestation over
   those commitments, the TLS session time and the server's ephemeral key.
4. **Presentation.** `orc` builds `presentation.bin` (attestation, server identity proof,
   commitment openings) plus `guest-input.json`, and runs the same verifier natively as a
   self-check.
5. **zkVM.** `orc-script` feeds both to the SP1 guest. The guest runs `orc_core::verify_claim`
   with trust anchors compiled in (`api.github.com`, Mozilla roots) and commits
   `abi.encode(PublicValues)`. Any failed check panics, so no proof exists for a rejected claim.
6. **On-chain.** The bound address calls `OrcClaim.claim(publicValues, proof)`. The contract
   checks the public values against its configuration, verifies the proof through the SP1
   gateway and burns the nullifier.

## Trust model and privacy

- **The notary is trusted not to collude with the prover.** One notary key (`notaryKeyHash`) is
  pinned in the contract. A notary that signs whatever a prover asks for can forge any claim. The
  notary never sees plaintext or the token: it learns transcript lengths, the session time and
  the server's ephemeral key. `sessionTime` comes from the notary's clock.
- **On-chain, the proof reveals only `PublicValues`** (below): the address, chain, campaign,
  repo `databaseId`, the threshold (not the exact count), the notary key hash, the session time
  and a nullifier. It doesn't reveal the token, the login or the commit count.
- **But `presentation.bin` reveals the full GitHub response to whoever holds it**: login,
  `databaseId`, node id, the exact commit count, repo id, branch name and head commit. Treat it
  as personal data and don't commit or publish it. An unauthenticated rate-limit 403 from GitHub
  even contains the client's public IP, which is why some spike fixtures are gitignored.
- **Whoever generates the proof sees the guest input** (the presentation). Proving locally keeps
  it on your machine. A remote prover (for example the Succinct Prover Network) sees all of it.
- **The nullifier is linkable.** `nullifier = keccak256(abi.encode(uint256(viewer.databaseId),
  campaignId))`. GitHub `databaseId`s are sequential, so anyone can brute-force a nullifier back
  to the GitHub account. A claim is pseudonymous at best.
- **TLS 1.2 only.** TLSNotary v0.1.0-alpha.15 supports TLS 1.2 (ECDHE P-256, AES-128-GCM). GitHub
  accepts it. Sites that only speak TLS 1.3 can't be used.
- **Token.** Use a fine-grained personal access token with read-only access to public
  repositories and no extra permissions. `orc` reads it only from `GITHUB_TOKEN`, never from a
  flag, and never writes it anywhere. The hidden range in the transcript is exactly the
  `Authorization` header value.

## What gets checked

### `PublicValues`

Committed by the guest as `abi.encode(PublicValues)` (8 static words, 256 bytes) and decoded by
the contract. Defined in [`crates/orc-core/src/abi.rs`](crates/orc-core/src/abi.rs) and mirrored
in [`contracts/src/OrcClaim.sol`](contracts/src/OrcClaim.sol).

```solidity
struct PublicValues {
    address ethAddress;     // who may claim (msg.sender)
    uint64  chainId;        // EVM chain the claim is for
    bytes32 campaignId;     // campaign; scopes the binding and the nullifier
    uint64  repoDatabaseId; // GitHub databaseId of the repository
    uint64  threshold;      // proven lower bound on the commit count
    bytes32 notaryKeyHash;  // keccak256 of the notary's compressed secp256k1 key
    uint64  sessionTime;    // TLS session time (notary clock), unix seconds
    bytes32 nullifier;      // keccak256(abi.encode(uint256(viewer.databaseId), campaignId))
}
```

### Guest checks (`orc_core::verify_claim`, in order)

The same function runs natively (prover self-check, tests, `orc-script`) and inside the guest. See
[`crates/orc-core/src/verify.rs`](crates/orc-core/src/verify.rs).

1. The presentation decodes with bincode, under 256 KiB and with no trailing bytes.
2. The notary key is secp256k1 (k256), 33-byte compressed. `notaryKeyHash = keccak256(key)`.
3. A full TLSNotary `Presentation::verify`: notary signature, Merkle openings, the server
   certificate chain against the Mozilla roots, the TLS handshake signature and the transcript
   hash openings. The signature algorithm must be secp256k1, the commitment hash SHA-256, and
   the server name `api.github.com`. The guest hardcodes these trust anchors, and nothing on
   stdin can change them.
4. Redaction: every received byte is revealed, and the only hidden sent bytes are exactly the
   single `Authorization` header value, at most 128 bytes (so it can't hide a smuggled second
   query).
5. Exactly one HTTP request and one response. Content-length, chunked and close-delimited
   bodies are accepted.
6. The request line is `POST /graphql HTTP/1.1`, with exactly the expected header set (no extra
   or duplicate headers) and the expected values. `X-Orc-Binding` must equal
   `keccak256(abi.encode(ethAddress, chainId, campaignId))` from the input.
7. The response is status 200, and its body parses strictly as the expected GraphQL data
   (unknown fields, including a top-level `errors`, are rejected).
8. The request body is byte-identical to the canonical query for `(owner, name, viewer.id)`, so
   the count belongs to the authenticated token owner.
9. `totalCount >= threshold`. The guest then computes the nullifier and commits `PublicValues`.

### Contract checks (`OrcClaim.claim`)

Cheap checks run first, then the proof (see the ordering note in the contract):

1. `publicValues` is exactly 256 bytes.
2. `ethAddress == msg.sender`.
3. `chainId == block.chainid`.
4. `campaignId`, `repoDatabaseId` and `notaryKeyHash` equal the contract's immutables.
5. `threshold >= ` the contract's threshold.
6. `sessionTime <= block.timestamp + 300` and `block.timestamp - sessionTime <= maxAge`.
7. The nullifier is unused.
8. `verifier.verifyProof(programVKey, publicValues, proof)` passes.
9. The nullifier is marked as used and `Claimed(account, nullifier, campaignId, sessionTime)` is emitted.

Each failed check reverts with its own custom error.

## Repository layout

```
crates/orc-core     guest-safe claim verification: verify_claim, PublicValues, GuestInput
crates/orc-notary   TCP notary: TLSNotary verifier + secp256k1 attestation signer (bin `orc-notary`)
crates/orc-prover   prover CLI (bin `orc`): preflight, MPC-TLS, presentation; offline e2e tests
crates/orc-script   SP1 host (own workspace): execute, vkey, prove, fixture
program/            SP1 guest (own workspace and Cargo.lock, SP1 precompile patches)
contracts/          Foundry: OrcClaim.sol, tests, Deploy.s.sol; lib/ holds git submodules
fixtures/           real api.github.com 401 presentation, local test-CA presentations and inputs
docker/             dev image: Rust 1.99.1, SP1 v6.10.0, Go, Foundry v1.8.7
spikes/             frozen M0a/M0b spikes
```

The root Cargo workspace contains `orc-core`, `orc-notary` and `orc-prover`. `program/` and
`crates/orc-script` have their own workspaces and lockfiles, so `cargo test --workspace` at the
root never compiles sp1-sdk or the guest.

## Quickstart (Docker dev environment)

The whole toolchain (Rust, SP1, the RISC-V C toolchain, Go, Foundry) lives in one pinned image.
Nothing but Docker with Compose v2 is needed on the host. linux/amd64 is the tested platform. See
[docker/README.md](docker/README.md) for details.

### 1. Clone and build the image

```bash
git clone --recurse-submodules https://github.com/felduque/orc-zktls-oracle.git
cd orc-zktls-oracle
# Already cloned without submodules? Run: git submodule update --init --recursive

printf 'DEV_UID=%s\nDEV_GID=%s\n' "$(id -u)" "$(id -g)" > .env   # gitignored
docker compose build
```

The `.env` file makes files written by the container belong to you. Don't use
`UID=$(id -u) docker compose build`: `UID` is read-only in bash, so compose silently falls back
to 1000. A cold build takes about 10 minutes and the image is about 9 GB.

Always run commands with `bash -c '...'`, **not** `bash -lc`: a login shell resets `PATH` and
`cargo` is not found.

### 2. Tests

```bash
# Root workspace: orc-core unit tests plus end-to-end tests that run real MPC-TLS
# sessions against a local TLS server (offline, no token needed).
docker compose run --rm -T dev bash -c 'cargo test --workspace'

# Contracts (SP1MockVerifier, fuzzing, the mock fixture from the guest).
docker compose run --rm -T dev bash -c 'cd contracts && forge test'
```

### 3. Run the SP1 guest (execute only, no proof)

`orc-script` embeds two guest ELFs: the **production** one (`api.github.com` + Mozilla roots) and
a **test-CA** one (`--test-ca`, tlsn's public test CA, for presentations from the local harness).
The test-CA ELF has a different vkey and must never be deployed. The first run compiles sp1-sdk
and both guests, which takes several minutes.

```bash
# Test-CA guest on a local-harness presentation: accepted, and the public values are
# byte-identical to the native verify_claim.
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- execute --test-ca --presentation ../../fixtures/test-ca/content-length.bin --input ../../fixtures/test-ca/content-length.input.json'

# Negative case: below threshold. The guest panics with the same error as native.
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- execute --test-ca --presentation ../../fixtures/test-ca/content-length.bin --input ../../fixtures/test-ca/neg-below-threshold.input.json'

# Production guest on a real api.github.com presentation (a 401 with a dummy token).
# Rejected at the binding check, after the full certificate-chain verify (~30M cycles).
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- execute --presentation ../../fixtures/m0b-github-graphql-401.bin --input ../../fixtures/m0b-github-graphql-401.input.json'

# Same, with a per-phase cycle breakdown.
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release --features profiling -- execute --presentation ../../fixtures/m0b-github-graphql-401.bin --input ../../fixtures/m0b-github-graphql-401.input.json'

# Program vkey of the production guest (the contract's programVKey).
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- vkey'
```

`vkey` should print
`0x00cb041834ea77fe8b6f73a952c5ea7f9956a17d38746650ed481bc4952c7834`. If yours differs, you are
not building the same guest (different image, toolchain or `program/Cargo.lock`).

`execute` exits 0 when the guest and the native verifier agree, whether both accept or both
reject.

### 4. A real GitHub run (requires a token)

> Requires a GitHub token. Not exercised in this repo yet (milestone status below).

1. Create a **fine-grained** personal access token: GitHub → Settings → Developer settings →
   Fine-grained tokens. Repository access: *Public repositories (read-only)*. No permissions.
   Short expiry.
2. Open `.env` in an editor and add a line `GITHUB_TOKEN=github_pat_...`. **Never pass the
   token on the command line**: it would end up in your shell history and process list. Compose
   passes `GITHUB_TOKEN` from `.env` into the container.
3. Generate a notary signing key straight into `.env`. The key is created inside the container
   and never appears on a command line:

   ```bash
   docker compose run --rm -T dev bash -c 'echo "ORC_NOTARY_KEY=$(openssl rand -hex 32)"' >> .env
   ```

4. Terminal 1, the notary. It prints its public key and `notaryKeyHash`, which the contract
   needs:

   ```bash
   docker compose run --rm --name orc-notary dev bash -c 'cargo run --release -p orc-notary'
   ```

5. Terminal 2, the prover. Replace owner/name/threshold with a repository where you have
   commits, and the address with yours (only that address can claim):

   ```bash
   docker compose run --rm -T dev bash -c 'cargo run --release -p orc-prover --bin orc -- prove \
     --owner tlsnotary --name tlsn --threshold 1 \
     --eth-address 0x1111111111111111111111111111111111111111 \
     --chain-id 84532 \
     --campaign-id 0x0000000000000000000000000000000000000000000000000000000000000001 \
     --notary orc-notary:7047 --out-dir out/github'
   ```

   It writes `out/github/presentation.bin` and `out/github/guest-input.json`. `out/` is
   gitignored: the presentation contains your GitHub data (see
   [Trust model](#trust-model-and-privacy)).

6. Execute the production guest on it:

   ```bash
   docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- execute --presentation ../../out/github/presentation.bin --input ../../out/github/guest-input.json'
   ```

### 5. A real Groth16 proof (requires 16+ GB of free RAM)

> Requires about 16 GB of free RAM. Not run yet (milestone M4).

```bash
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- prove --system groth16 --presentation ../../out/github/presentation.bin --input ../../out/github/guest-input.json'
```

This writes the contract fixture `fixtures/proofs/orc-production-groth16.json`
(`{programVKey, publicValues, proof}`). The first Groth16 run downloads several GB of circuit
artifacts into the `sp1-circuits` volume. Deploying `OrcClaim` (milestone M5) is driven by
[`contracts/script/Deploy.s.sol`](contracts/script/Deploy.s.sol), whose header lists the
environment variables it takes.

## Measured numbers

All measured in the dev container (SP1 v6.10.0, tlsn v0.1.0-alpha.15) unless marked as an
estimate.

| What | Number |
|---|---|
| Guest, production ELF, real `api.github.com` presentation | **30,102,178** instructions; the verify phase is 29.77M (98.9%) |
| Of that, server identity (certificate chain + TLS signature) | ~29.57M (~99%), measured in the M0a spike |
| Guest, test-CA ELF, accepted claim (content-length / chunked / close-delimited) | **2,387,112** / 2,405,281 / 2,275,541 instructions |
| Guest execute wall time (light prover, no proof), production / test-CA | ~0.6 s / ~0.15 s |
| `OrcClaim.claim` with `SP1MockVerifier` | **55,064** gas |
| `OrcClaim.claim` with the gateway + real Groth16 verify | **~365k gas per tx** (~330k execution), *estimate* |
| `OrcClaim` deployment | ~794k gas, *estimate* |

Why the real chain costs 12x more than the test CA: GitHub's chain is `*.github.com` (P-256) ←
Sectigo DV E36 (P-256) ← Root E46 (**P-384**), plus a P-256 handshake signature. ring verifies it
in software inside the zkVM (no P-256/P-384 precompile is hit), while the test CA is RSA.

Hardware for proving:

- Execute, `vkey`, mock fixtures and every test run on an ordinary dev machine (measured on 12
  cores / 23 GB).
- Real proofs are heavy. The SP1 CPU prover grows to ~7 GiB just to initialize (recursion keys)
  and was OOM-killed in every attempt under an 8 GiB limit. A Groth16 wrap needs about 14 GB at
  peak, so plan for 16+ GB of free RAM. SP1 recommends 16+ cores.
- Proving time has not been measured yet (M4).

## Milestones

| # | Work | Status |
|---|---|---|
| M0 | Docker dev environment (Rust, SP1 + C toolchain, Go, Foundry) | Done |
| M0a | Gate: full tlsn `Presentation::verify` inside SP1 (ring compiles for riscv64; ~30M cycles) | Done |
| M0b | MPC-TLS spike against `api.github.com` | Done |
| M1 | `orc-core`, `orc-notary`, `orc-prover` with offline MPC e2e tests | Done |
| M2 | SP1 guest + `orc-script` (execute, vkey, mock fixtures); guest output equals native | Done |
| M3 | `OrcClaim.sol` + Foundry tests with `SP1MockVerifier` | Done |
| - | Real authenticated `api.github.com` 200 run (needs a PAT) | Pending |
| M4 | Real Groth16 proof; `forge test` against `SP1VerifierGroth16` v6.1.0 | Pending (needs ~16 GB RAM) |
| M5 | Deploy to Base Sepolia; real claim; a replay reverts with `NullifierUsed` | Pending |

## Known limitations and future work

- **Single trusted notary.** Decentralizing it is the next design phase: k-of-n notaries, a
  TEE-hosted notary, or staking and slashing.
- **TLS 1.3.** Not supported by TLSNotary yet (paused on its roadmap), so sites that only speak
  TLS 1.3 can't be used.
- **Nullifier privacy.** The plain hash of a sequential id is linkable. A fix needs a keyed
  function, for example an OPRF or a user secret, that still yields one nullifier per account.
- **Prover network.** Outsourcing proofs (for example to the Succinct Prover Network) means the
  operator sees the presentation, including your login. Local proving avoids that but needs
  16+ GB of RAM.
- **Presentation exposure.** The guest needs the full response to parse it strictly. Revealing
  less would need selective disclosure plus more in-circuit work.
- **Freshness** relies on the notary's clock (`sessionTime`) and the contract's `maxAge`.
- **One data source.** The query, server and trust anchors are hardcoded for GitHub GraphQL.
  "Commits" means default-branch commits that GitHub attributes to the account
  (`history(author: {id})`).
- **MPC flakiness.** A rare "MPC setup timed out" (about 2 in 150 local sessions). Each MPC
  phase has a timeout and the prover retries once.
- **tlsn is alpha** and has breaking changes between tags. Everything is pinned (see below).

## Reproducibility

The program vkey is a hash of the guest ELF, so anything that changes the guest build changes the
vkey and requires redeploying `OrcClaim`. Everything that feeds it is pinned:

- the Docker image (Rust 1.99.1, SP1 v6.10.0 + C toolchain, Go 1.26.10, Foundry v1.8.7);
- the tlsn git tag `v0.1.0-alpha.15`;
- three lockfiles: root `Cargo.lock`, `program/Cargo.lock` and `crates/orc-script/Cargo.lock`;
- the contract submodules (`sp1-contracts` v6.1.1, `forge-std` v1.17.0).

That's why the repo has **no Dependabot config**: automated bumps of tlsn, SP1 or the guest
lockfile would silently change the vkey, and tlsn alpha tags break APIs. Bump by hand, rerun
`vkey`, and redeploy.

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs `cargo test --workspace --locked`
and `forge build` + `forge test`. It does not build the SP1 guest (too heavy for CI runners).

## Prior art and credits

- [TLSNotary](https://github.com/tlsnotary/tlsn): MPC-TLS, attestations and presentations. orc
  uses v0.1.0-alpha.15 and writes its own notary, since the notary server was removed in alpha.13.
- [Succinct SP1](https://github.com/succinctlabs/sp1) and
  [sp1-contracts](https://github.com/succinctlabs/sp1-contracts): the zkVM, precompile patches
  and the on-chain Groth16 verifier gateway.
- [vlayer-xyz/zk-github-contribution-verifier](https://github.com/vlayer-xyz/zk-github-contribution-verifier):
  almost the same use case, on RISC Zero.
- [skrakra/r0-tlsn-foundry](https://github.com/skrakra/r0-tlsn-foundry): TLSNotary presentation
  verification in RISC Zero with Foundry.
- [Foundry](https://github.com/foundry-rs/foundry) and [alloy](https://github.com/alloy-rs).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT)),

at your option. The Solidity sources carry `SPDX-License-Identifier: MIT`, one of the two options.
The submodules under `contracts/lib` and all dependencies keep their own licenses.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
