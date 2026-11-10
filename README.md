# orc: zk-TLS GitHub oracle (proof of concept)

> **Español:** este README está en inglés. Una traducción al español es bienvenida (abrí un PR).

orc lets a GitHub user prove on-chain that **"the account that owns my token has at least N
commits in repo X"** (counted up to a campaign snapshot), bound to one Ethereum address, without
revealing the token to anyone. The
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
- [Local end-to-end demo (anvil)](#local-end-to-end-demo-anvil)
- [Measured numbers](#measured-numbers)
- [Milestones](#milestones)
- [Security review](#security-review)
- [Known issues](#known-issues)
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
   presentation.bin   the 82 token bytes hidden (`bearer github_pat_` shown), all else revealed
   guest-input.json   eth address, chain id, campaign id, owner, name, threshold, snapshot
             |
             v  (5) orc-script: SP1 guest runs orc_core::verify_claim
          +---------------------+
          | SP1 guest           | --> commits abi.encode(PublicValues), 288 bytes
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
   the token owner's node id (`viewer.id`) and creation time. The notarized query needs the id as
   a variable, and an account created after the snapshot is refused here, before an MPC session.
2. **MPC-TLS session.** `orc` opens a TLS 1.2 connection to `api.github.com` whose session keys
   are secret-shared with `orc-notary`. Over it, `orc` sends exactly one `POST /graphql` with a
   fixed header set, including `Authorization: bearer github_pat_<82 characters>` (fine-grained
   personal access tokens only) and
   `X-Orc-Binding: keccak256(abi.encode(ethAddress, chainId, campaignId))`. The query returns the
   viewer's `login`, `databaseId`, `id` and `createdAt`, the repo's `databaseId`, and `totalCount`
   of the default-branch commits authored by the viewer up to the campaign snapshot
   (`history(author: {id: $a}, until: $u)`).
3. **Attestation.** The prover commits (SHA-256) to everything it will reveal: the whole response
   and the whole request except the 82 secret token bytes after `bearer github_pat_`. The notary
   signs an attestation over those commitments, the TLS session time (the prover's clock, which
   the notary accepts within ±5 s of its own) and the server's ephemeral key.
4. **Presentation.** `orc` builds `presentation.bin` (attestation, server identity proof,
   commitment openings) plus `guest-input.json`, and runs the same verifier natively as a
   self-check.
5. **zkVM.** `orc-script` feeds both to the SP1 guest. The guest runs `orc_core::verify_claim`
   with trust anchors compiled in (`api.github.com`, Mozilla roots) and commits
   `abi.encode(PublicValues)`. Any failed check panics, so no proof exists for a rejected claim.
6. **On-chain.** The bound address calls `OrcClaim.claim(publicValues, proof)`. The contract
   checks the public values against its configuration (including its campaign id and snapshot),
   verifies the proof through the SP1 gateway and burns the nullifier.

## Trust model and privacy

- **The notary is trusted not to collude with the prover.** One notary key (`notaryKeyHash`) is
  pinned in the contract. A notary that signs whatever a prover asks for can forge any claim. The
  notary never sees plaintext or the token: it learns transcript lengths, the session time and
  the server's ephemeral key. `sessionTime` is the prover's clock; the notary only signs it if it
  is within ±5 s of its own.
- **On-chain, the proof reveals only `PublicValues`** (below): the address, chain, campaign,
  repo `databaseId`, the threshold (not the exact count), the snapshot, the notary key hash, the
  session time and a nullifier. It doesn't reveal the token, the login or the commit count.
- **But `presentation.bin` reveals the full GitHub response to whoever holds it**: login,
  `databaseId`, node id, account creation date, the exact commit count, repo id, branch name and
  head commit, plus GitHub's response headers (including the token's expiry date). Treat it
  as personal data and don't commit or publish it. An unauthenticated rate-limit 403 from GitHub
  even contains the client's public IP, which is why some spike fixtures are gitignored.
- **Whoever generates the proof sees the guest input** (the presentation). Proving locally keeps
  it on your machine. A remote prover (for example the Succinct Prover Network) sees all of it.
- **The nullifier is linkable.** `nullifier = keccak256(abi.encode(uint256(viewer.databaseId),
  campaignId))`. GitHub `databaseId`s are sequential, so anyone can brute-force a nullifier back
  to the GitHub account. A claim is pseudonymous at best.
- **TLS 1.2 only.** TLSNotary v0.1.0-alpha.15 supports TLS 1.2 (ECDHE P-256, AES-128-GCM). GitHub
  accepts it. Sites that only speak TLS 1.3 can't be used.
- **Token: fine-grained personal access tokens only.** Use one with read-only access to public
  repositories and no extra permissions. `orc` refuses any other token type up front (classic
  `ghp_`, OAuth `gho_`, GitHub App `ghu_`/`ghs_`), reads it only from `GITHUB_TOKEN`, never from
  a flag, and never writes it anywhere. The presentation reveals `bearer github_pat_` and hides
  exactly the 82 token characters after it. The guest requires that shape, so a claim proves
  GitHub received a fine-grained PAT: someone holding another credential for the same account
  (an OAuth app or GitHub App token) cannot claim as that user.

## What gets checked

### `PublicValues`

Committed by the guest as `abi.encode(PublicValues)` (9 static words, 288 bytes) and decoded by
the contract. Defined in [`crates/orc-core/src/abi.rs`](crates/orc-core/src/abi.rs) and mirrored
in [`contracts/src/OrcClaim.sol`](contracts/src/OrcClaim.sol). The fields are grouped by role:
the binding, the claim the contract pins, the TLS session, then the nullifier.

```solidity
struct PublicValues {
    address ethAddress;     // who may claim (msg.sender)
    uint64  chainId;        // EVM chain the claim is for
    bytes32 campaignId;     // campaign; scopes the binding and the nullifier
    uint64  repoDatabaseId; // GitHub databaseId of the repository
    uint64  threshold;      // proven lower bound on the commit count
    uint64  snapshot;       // unix seconds: commits counted up to it; account created before it
    bytes32 notaryKeyHash;  // keccak256 of the notary's compressed secp256k1 key
    uint64  sessionTime;    // TLS session time (prover clock, notary-checked to ±5 s), unix s
    bytes32 nullifier;      // keccak256(abi.encode(uint256(viewer.databaseId), campaignId))
}
```

### Campaign id and snapshot

`OrcClaim` pins both, and a prover reads them from the deployed contract:

```bash
cast call <OrcClaim> "campaignId()(bytes32)"
cast call <OrcClaim> "snapshot()(uint64)"
```

- **`campaignId = keccak256(abi.encode(block.chainid, address(this), campaignSalt))`**, computed
  in the constructor from the deployer's `CAMPAIGN_SALT`. A redeploy, or the same salt on another
  chain, gets a different campaign id, so proofs and nullifiers never carry over between
  deployments.
- **`snapshot`** (unix seconds, not in the future at deploy time). The query counts only commits
  authored up to it (`until`), and the guest requires `viewer.createdAt < snapshot`. GitHub
  attributes commits to an account by email while the nullifier is per account, so without this
  someone could claim, move the email to a fresh account and claim the same commits again. Now
  only accounts that already existed at the snapshot can claim (see the residual risk in
  [Known limitations](#known-limitations-and-future-work)). The guest renders the snapshot as
  `YYYY-MM-DDTHH:MM:SSZ` and parses `createdAt` in exactly that form
  ([`crates/orc-core/src/time.rs`](crates/orc-core/src/time.rs), no date library).

### Guest checks (`orc_core::verify_claim`, in order)

The same function runs natively (prover self-check, tests, `orc-script`) and inside the guest. See
[`crates/orc-core/src/verify.rs`](crates/orc-core/src/verify.rs).

0. The snapshot is representable as `YYYY-MM-DDTHH:MM:SSZ` (year 9999 or earlier).
1. The presentation decodes with bincode, under 256 KiB and with no trailing bytes.
2. The notary key is secp256k1 (k256), 33-byte compressed. `notaryKeyHash = keccak256(key)`.
3. A full TLSNotary `Presentation::verify`: notary signature, Merkle openings, the server
   certificate chain against the Mozilla roots, the TLS handshake signature and the transcript
   hash openings. The signature algorithm must be secp256k1, the commitment hash SHA-256, and
   the server name `api.github.com`. The guest hardcodes these trust anchors, and nothing on
   stdin can change them.
4. Redaction: every received byte is revealed. The single `Authorization` value starts with the
   revealed `bearer github_pat_`, and the only hidden sent bytes are exactly the 82 bytes after
   it. So GitHub received a fine-grained PAT, and the hidden range is far too short to smuggle a
   second query whose response would pass step 7.
5. Exactly one HTTP request and one response. Content-length, chunked and close-delimited
   bodies are accepted.
6. The request line is `POST /graphql HTTP/1.1`, with exactly the expected header set (no extra
   or duplicate headers) and the expected values. `X-Orc-Binding` must equal
   `keccak256(abi.encode(ethAddress, chainId, campaignId))` from the input.
7. The response is status 200, and its body parses strictly as the expected GraphQL data
   (unknown fields, including a top-level `errors`, are rejected).
8. The request body is byte-identical to the canonical query for
   `(owner, name, viewer.id, snapshot)`, so the count belongs to the authenticated token owner and
   stops at the snapshot.
9. `viewer.createdAt` parses strictly as `YYYY-MM-DDTHH:MM:SSZ` and is before the snapshot.
10. `totalCount >= threshold`. The guest then computes the nullifier and commits `PublicValues`.

The canonical query (`orc_core::GRAPHQL_QUERY`):

```graphql
query($o:String!,$n:String!,$a:ID!,$u:GitTimestamp!){viewer{login databaseId id createdAt}
  repository(owner:$o,name:$n){databaseId defaultBranchRef{name target{... on Commit{oid
  history(author:{id:$a},until:$u,first:1){totalCount}}}}}}
```

### Contract checks (`OrcClaim.claim`)

Cheap checks run first, then the proof (see the ordering note in the contract):

1. `publicValues` is exactly 288 bytes.
2. `ethAddress == msg.sender`.
3. `chainId == block.chainid`.
4. `campaignId` (derived from chain id, contract address and salt), `repoDatabaseId` and
   `notaryKeyHash` equal the contract's immutables.
5. `threshold >= ` the contract's threshold.
6. `snapshot ==` the contract's snapshot.
7. `sessionTime <= block.timestamp + 300` and `block.timestamp - sessionTime <= maxAge`.
8. The nullifier is unused.
9. `verifier.verifyProof(programVKey, publicValues, proof)` passes.
10. The nullifier is marked as used and `Claimed(account, nullifier, campaignId, sessionTime)` is
    emitted.

Each failed check reverts with its own custom error.

## Repository layout

```
crates/orc-core     guest-safe claim verification: verify_claim, PublicValues, GuestInput
crates/orc-notary   TCP notary: TLSNotary verifier + secp256k1 attestation signer (bin `orc-notary`)
crates/orc-prover   prover CLI (bin `orc`): preflight, MPC-TLS, presentation; offline e2e tests
crates/orc-script   SP1 host (own workspace): execute, vkey, prove, fixture
program/            SP1 guest (own workspace and Cargo.lock, SP1 precompile patches)
contracts/          Foundry: OrcClaim.sol, tests, Deploy.s.sol; lib/ holds git submodules
fixtures/           real api.github.com 200 and 401 presentations, local test-CA presentations
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
mkdir -p ~/.foundry/keystores   # bind-mounted for deploy keys; must exist BEFORE compose runs
docker compose build
```

The `.env` file makes files written by the container belong to you. `~/.foundry/keystores` is
mounted into the container for encrypted Foundry keystores (testnet deployer); if it is missing,
Docker creates it on the host owned by root. Don't use
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

# Negative cases. The guest panics with the same error as native:
#   neg-below-threshold (with content-length.bin)   commit count below the threshold
#   neg-wrong-binding   (with content-length.bin)   another address in the input
#   neg-auth-hidden.bin                              whole Authorization value hidden (no
#                                                    visible `bearer github_pat_`)
#   neg-account-too-new.bin                          viewer.createdAt == snapshot
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- execute --test-ca --presentation ../../fixtures/test-ca/content-length.bin --input ../../fixtures/test-ca/neg-below-threshold.input.json'
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- execute --test-ca --presentation ../../fixtures/test-ca/neg-auth-hidden.bin --input ../../fixtures/test-ca/neg-auth-hidden.input.json'

# Production guest on the real authenticated api.github.com 200 (fixtures/github-graphql-200.*,
# the maintainer's own public data): accepted, ~30.3M instructions.
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- execute --presentation ../../fixtures/github-graphql-200.bin --input ../../fixtures/github-graphql-200.input.json'

# Same, with a per-phase cycle breakdown.
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release --features profiling -- execute --presentation ../../fixtures/github-graphql-200.bin --input ../../fixtures/github-graphql-200.input.json'

# Production guest on a real 401 from spike M0b (a dummy token, whole Authorization value
# hidden): rejected at the redaction rule, after the full certificate-chain verify.
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- execute --presentation ../../fixtures/m0b-github-graphql-401.bin --input ../../fixtures/m0b-github-graphql-401.input.json'

# Program vkey of the production guest (the contract's programVKey).
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- vkey'

# Both vkeys as PROGRAM_VKEY=... / TEST_CA_VKEY=... lines, the inputs Deploy.s.sol takes.
docker compose run --rm -T dev bash -c 'cd crates/orc-script && cargo run --release -- vkey --env'
```

`vkey` should print
`0x00ced0167fad7731d535a982b3b5e8dc8bca88d950f341bb9772d95a02d1754d`. If yours differs, you are
not building the same guest (different image, toolchain or `program/Cargo.lock`). The test-CA
guest's vkey is `0x0028c57ac09b538782d69d631ef84dd12595f5c318fa3515dc7f807fa8f9bb4f`.

> [!CAUTION]
> **Never deploy the test-CA vkey.** The test-CA guest trusts tlsn's public test CA, whose private
> key is published: anyone can mint a "GitHub" certificate for it and prove any response.
> `Deploy.s.sol` refuses `PROGRAM_VKEY == TEST_CA_VKEY`; pass both from `vkey --env`.

`execute` exits 0 when the guest and the native verifier agree, whether both accept or both
reject.

### 4. A real GitHub run (requires a token)

> Requires a GitHub fine-grained token. Done in this repo: `fixtures/github-graphql-200.*` is
> such a run. Each run costs 2 points of GitHub's 5,000-point hourly GraphQL budget (the
> preflight and the notarized query).

1. Create a **fine-grained** personal access token: GitHub → Settings → Developer settings →
   Fine-grained tokens. Repository access: *Public repositories (read-only)*. No permissions.
   Short expiry. `orc` refuses every other token type (`ghp_`, `gho_`, `ghu_`, `ghs_`), and so
   does the guest.
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

   **Notary limits.** The notary refuses connections beyond `--max-concurrent-sessions` (4) or
   `--max-sessions-per-ip` (2 per IPv4 address or IPv6 /64). It drops any connection that hasn't
   sent an acceptable config within `--setup-timeout-secs` (10 s) and caps prover-chosen record
   counts (260 sent / 1028 received). Each flag has an `ORC_NOTARY_*` env var. Behind a reverse
   proxy, raise the per-IP cap.

5. Terminal 2, the prover. Replace owner/name/threshold with a repository where you have
   commits, and the address with yours (only that address can claim). The campaign id and the
   snapshot come from the deployed `OrcClaim`
   (`cast call <OrcClaim> "campaignId()(bytes32)"`, `cast call <OrcClaim> "snapshot()(uint64)"`);
   the values below are placeholders:

   ```bash
   docker compose run --rm -T dev bash -c 'cargo run --release -p orc-prover --bin orc -- prove \
     --owner tlsnotary --name tlsn --threshold 1 \
     --eth-address 0x1111111111111111111111111111111111111111 \
     --chain-id 84532 \
     --campaign-id 0x0000000000000000000000000000000000000000000000000000000000000001 \
     --snapshot 1794322800 \
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
artifacts into the `sp1-circuits` volume.

### 6. Deploying `OrcClaim`

Deploying (milestone M5) is driven by
[`contracts/script/Deploy.s.sol`](contracts/script/Deploy.s.sol), whose header lists the
environment variables it takes: `PROGRAM_VKEY` and `TEST_CA_VKEY` (from `orc-script vkey --env`),
`NOTARY_KEY_HASH`, `CAMPAIGN_SALT`, `REPO_DATABASE_ID`, `THRESHOLD`, `SNAPSHOT`, `MAX_AGE` and
optionally `SP1_VERIFIER`. It prints the resulting `campaignId`. Its guards:

- On any chain other than anvil (31337), `SP1_VERIFIER` must be the canonical SP1 Groth16
  gateway `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B` (the default). Anything else, such as
  `SP1MockVerifier`, needs `ALLOW_NONCANONICAL_VERIFIER=1` and prints a loud warning. Never do
  that for a real campaign: the mock verifier accepts any public values.
- It refuses `PROGRAM_VKEY == TEST_CA_VKEY` on every chain (and warns off anvil when
  `TEST_CA_VKEY` is not set).
- The contract itself refuses a zero salt and a snapshot of 0 or in the future.

## Local end-to-end demo (anvil)

One command rehearses the M5 flow on a local chain, with a real GitHub session:

```bash
scripts/demo-local.sh
```

It needs `GITHUB_TOKEN` and `ORC_NOTARY_KEY` in `.env` (steps 2 and 3 of
[A real GitHub run](#4-a-real-github-run-requires-a-token)). It runs everything in one dev
container, so anvil, the notary and the prover share `localhost`:

1. Builds `orc`, `orc-notary` and `orc-script`. This is a no-op on a warm cache.
2. Starts anvil (chain id 31337) and `orc-notary` in the background. The accounts come from
   anvil's public test mnemonic: #0 deploys and claims, #1 plays the attacker.
3. Deploys `SP1MockVerifier`, then `OrcClaim` through `contracts/script/Deploy.s.sol`. The
   inputs are:
   - `PROGRAM_VKEY` and `TEST_CA_VKEY` from `orc-script vkey --env`, computed at run time, so
     they always match the guests you built;
   - `notaryKeyHash` as printed by the running notary;
   - `CAMPAIGN_SALT = keccak256("orc-poc-github-v1")`, `SNAPSHOT` = now (override with
     `ORC_DEMO_SNAPSHOT`);
   - repo `felduque/orc-zktls-oracle` (databaseId 1452696697), threshold 5, `maxAge` 3600 s.

   It reads `campaignId` back from the contract, checks it equals
   `keccak256(abi.encode(31337, address, salt))`, and reads the rest of the configuration back.
4. Dry-runs `Deploy.s.sol` with `PROGRAM_VKEY` set to the test-CA vkey. It must be refused.
5. Runs `orc prove` against the real `api.github.com`, bound to anvil #0 and chain id 31337, with
   `--campaign-id` and `--snapshot` read from the deployed contract.
6. Runs `orc-script fixture --mock --production`. The production guest executes on the
   presentation, its output is compared with the native verifier, and the mock prover returns the
   public values with an empty proof.
7. anvil #1 submits the claim. It is mined and reverts with `WrongSender`, and the nullifier
   stays unused.
8. anvil #0 submits it. `Claimed` is emitted with the expected fields, and
   `nullifierUsed(nullifier)` becomes `true`.
9. anvil #0 submits it again. It reverts with `NullifierUsed`.

The failing claims are sent with a fixed gas limit. That skips `eth_estimateGas`, so they are
mined and revert on-chain (receipt status 0) rather than being refused by the RPC. The custom
errors are decoded from the revert data. The script prints PASS/FAIL per step and exits non-zero
on any unexpected result. It cleans up anvil, the notary and the container on exit, Ctrl-C
included. Logs, the presentation, the mock fixture, the receipts and the deploy broadcast go to
the gitignored `out/demo/`, which is wiped at the start of each run.

```
================ orc local demo: summary ================
 1  preconditions + build                    PASS   34.2 s  tokens present, binaries built
 2  anvil (31337) + orc-notary               PASS    0.2 s  anvil and notary up
 3  deploy SP1MockVerifier + OrcClaim        PASS   13.2 s  OrcClaim 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512, campaignId derived on-chain, config read back OK
 4  Deploy.s.sol refuses the test-CA vkey    PASS    1.2 s  refused by the test-CA guard
 5  orc prove (real api.github.com)          PASS    2.6 s  presentation 5854 B, native self-check OK
 6  orc-script fixture --mock --production   PASS    4.6 s  production guest accepted, publicValues match the deployment
 7  anvil #1 claims -> WrongSender           PASS    0.2 s  reverted on-chain with WrongSender
 8  anvil #0 claims -> Claimed               PASS    0.4 s  Claimed emitted, nullifier burnt
 9  anvil #0 replays -> NullifierUsed        PASS    0.4 s  reverted on-chain with NullifierUsed
RESULT: PASS (9/9) in 57.2 s
```

(Step 1 recompiled the notary here; on a warm cache it is under a second.)

**What it proves:**

- The whole CLI flow works together on a real GitHub session: notary, MPC-TLS prover, the SP1
  host running the production guest, and the deploy script.
- The contract's semantics hold: the configuration the deploy script sets, the binding to
  `msg.sender` and `block.chainid`, the `Claimed` event, and one claim per nullifier.

**What it doesn't prove:**

- There is no real proof. `SP1MockVerifier` accepts *any* public values with empty proof bytes,
  so on this chain a forged `publicValues` would pass too. The guest's checks run only because
  `orc-script` refuses to write a fixture the guest and native verifier don't both accept.
- The real Groth16 path through the gateway is M4 and M5.

**Cost and timing:**

- **GitHub API.** Each run makes two GitHub GraphQL requests, the preflight (`viewer.id` and
  `createdAt`) and the notarized query. That's 2 points of the 5,000-point hourly GraphQL
  budget. The script prints the budget from the notarized response headers.
- **Time.** A warm run takes about 25 s:
  - about 13 s for the deploy step, which includes `orc-script vkey --env` (two SP1 setups);
  - about 1 s for the refused test-CA deploy;
  - about 2 s for the MPC-TLS session;
  - about 5 s for the mock fixture (SP1 setup plus the ~30M-instruction guest execute).
- **First run.** It compiles sp1-sdk and both guests, which takes several minutes. After source
  changes, expect about a minute of recompiling.

To run it with your own token, point it at a repository where you have commits. The repo's
`databaseId` is the `id` field of `https://api.github.com/repos/<owner>/<name>`.

```bash
ORC_DEMO_OWNER=you ORC_DEMO_NAME=repo ORC_DEMO_REPO_ID=<repo databaseId> ORC_DEMO_THRESHOLD=1 \
  scripts/demo-local.sh
```

## Measured numbers

All measured in the dev container (SP1 v6.10.0, tlsn v0.1.0-alpha.15) unless marked as an
estimate.

| What | Number |
|---|---|
| Guest, production ELF, real authenticated `api.github.com` 200 (accepted) | **30,333,839** instructions: verify 29.77M (98.2%), http 383K, deserialize 95K, json 24K |
| Of that, server identity (certificate chain + TLS signature) | ~29.57M (~99%), measured in the M0a spike |
| Guest, production ELF, real 401 from spike M0b (rejected at the redaction rule) | 29,977,417 instructions |
| Guest, test-CA ELF, accepted claim (content-length / chunked / close-delimited) | **2,416,269** / 2,439,559 / 2,295,426 instructions |
| Guest execute wall time (light prover, no proof), production / test-CA | ~0.6 s / ~0.1 s |
| MPC-TLS session against `api.github.com` (setup / online / prove / attestation) | ~0.4 / 0.9-1.2 / 0.3 / 0.01 s; sent 713 B, received ~1.45 KB, presentation ~5.85 KB |
| `OrcClaim.claim` with `SP1MockVerifier` | **55,425** gas |
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
| - | Real authenticated `api.github.com` 200 run; production guest accepts it | Done |
| - | Security review fixes (H1 snapshot, M1 fine-grained PATs only, M2 notary limits, L2 campaign id, L3 deploy guards) | Done |
| M4 | Real Groth16 proof; `forge test` against `SP1VerifierGroth16` v6.1.0 | Pending (needs ~16 GB RAM) |
| M5 | Deploy to Base Sepolia; real claim; a replay reverts with `NullifierUsed` | Pending |

## Security review

An independent adversarial review of `48c038b` found no critical issues. Status of each finding:

| # | Finding | Status |
|---|---|---|
| H1 | Commits are attributed by email but the nullifier is per account: move an email to a fresh account, claim again. | **Mitigated**: per-campaign `snapshot`; the query counts commits `until` it and the guest requires `viewer.createdAt < snapshot`. Residual: moving emails among accounts older than the snapshot ([Known limitations](#known-limitations-and-future-work)). |
| M1 | Any token holder for the account (OAuth app, GitHub App) could claim as the user; the hidden range left room to smuggle bytes. | **Fixed**: fine-grained PATs only. The guest requires the revealed `bearer github_pat_` and exactly 82 hidden bytes; `orc` refuses other tokens up front. GitHub answered 401 to requests carrying a second `Authorization` header (either order, tested), so one smuggled into the hidden bytes cannot authenticate. |
| M2 | Notary DoS: idle connections pinned every session slot; prover-chosen record counts were unbounded. | **Fixed**: global and per-IP session caps, a 10 s setup deadline, record-count caps (see [Notary limits](#4-a-real-github-run-requires-a-token)). Accepted residual: a client that sends a valid config and then idles holds a slot for up to the 300 s session timeout, so a few IPs can still fill the global cap. |
| L1 | A ~5 KB crafted presentation aborts *native* `verify_claim` (tlsn allocates `sent_total` bytes while decoding). | **Accepted**: only native verification of untrusted presentations is affected; the guest just fails to prove. |
| L2 | `campaignId` was not bound to the contract, so a redeploy reused campaigns and nullifiers. | **Fixed**: `campaignId = keccak256(abi.encode(chainid, address(this), campaignSalt))`. |
| L3 | The deploy script accepted a mock verifier or the test-CA vkey on public chains. | **Fixed**: off anvil only the canonical gateway (or an explicit `ALLOW_NONCANONICAL_VERIFIER=1`); `PROGRAM_VKEY == TEST_CA_VKEY` is refused. |
| L4 | The real 200 fixture reveals response metadata (token expiry, request id, edge region). | **Accepted**: it is the maintainer's own public data, audited for token bytes, IPs and emails before committing. |
| Info | `sessionTime` is the prover's clock (notary-checked to ±5 s); the notary signs prover extensions without a validator; SNI is not committed; the hidden length reveals the token type. | **Accepted / documented**: the length now always says "fine-grained PAT", which the visible prefix says anyway. |

## Known issues

**Intermittent MPC setup stall (tlsn alpha.15).** An MPC-TLS session sometimes stops making
progress in setup: both sides sit idle in mpc-tls preprocessing (`prover:commit:preprocess`,
`verifier:accept:preprocess`) with nothing left in flight on the multiplexer, until the phase
timeout. It is rare on many cores but hits about 1 in 3 sessions on 4 CPUs (reproduce with
`ORC_TEST_MPC_SLOTS=1 taskset -c 0-3 cargo test -p orc-prover --test e2e -- --test-threads=1`);
the root cause is not isolated yet. Mitigations: every MPC phase has a timeout and the `orc` CLI
retries once with a fresh notary session; the e2e harness retries timed-out sessions (3 x 45 s by
default; CI runs the suite serialized with 8 x 15 s, see the `ORC_TEST_*` variables in
[ci.yml](.github/workflows/ci.yml)). For every failed attempt the harness prints the tail of the
prover's and the notary's tracing logs and the spans that sat idle
([`harness/logs.rs`](crates/orc-prover/tests/harness/logs.rs)); CI uploads the full logs as the
`orc-e2e-mpc-diagnostics` artifact.

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
- **Freshness** relies on `sessionTime` (the prover's clock, which the notary accepts only within
  ±5 s of its own) and the contract's `maxAge`.
- **Commits are attributed by email (residual of H1).** `history(author: {id})` counts commits
  whose author email belongs to the account, while the nullifier is per account. The snapshot
  stops fresh accounts, but an email can still be moved among accounts that already existed
  before the snapshot, so a person controlling several such accounts could claim the same commits
  once per account. Pick the snapshot before the campaign is announced.
- **One data source.** The query, server and trust anchors are hardcoded for GitHub GraphQL.
  "Commits" means default-branch commits that GitHub attributes to the account
  (`history(author: {id})`).
- **MPC setup stall.** See [Known issues](#known-issues).
- **tlsn is alpha** and has breaking changes between tags. Everything is pinned (see below).

## Reproducibility

The program vkey is a hash of the guest ELF, so anything that changes the guest build changes the
vkey and requires redeploying `OrcClaim`. That includes pure reformatting of `program/` or
`crates/orc-core`: panic locations (file:line:col) are compiled into the ELF. Everything that
feeds it is pinned:

- the Docker image (Rust 1.99.1, SP1 v6.10.0 + C toolchain, Go 1.26.10, Foundry v1.8.7);
- the tlsn git tag `v0.1.0-alpha.15`;
- three lockfiles: root `Cargo.lock`, `program/Cargo.lock` and `crates/orc-script/Cargo.lock`;
- the contract submodules (`sp1-contracts` v6.1.1, `forge-std` v1.17.0).

That's why the repo has **no Dependabot config**: automated bumps of tlsn, SP1 or the guest
lockfile would silently change the vkey, and tlsn alpha tags break APIs. Bump by hand, rerun
`vkey`, and redeploy.

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs `cargo fmt --check`,
`cargo clippy -D warnings` and `cargo test --locked` (the MPC e2e suite in its own, serialized
step; see [Known issues](#known-issues)), and `forge fmt --check`, `forge build` + `forge test`.
It does not build the SP1 guest (too heavy for CI runners).

### Fixtures

- `fixtures/github-graphql-200.*`: a real authenticated run (`felduque/orc-zktls-oracle`,
  threshold 5, snapshot `2026-11-10T15:00:00Z`, chain 84532, eth address anvil #0). Audited
  before committing: no token bytes (not even 4-byte windows of the secret part, nor base64/hex
  forms), no IP addresses, no emails.
- `fixtures/test-ca/*`: local-harness sessions, rewritten by
  `cargo test -p orc-prover --test e2e -- --ignored dump_test_ca_fixtures`.
- `contracts/fixtures/orc-mock.json` and `orc-github-mock.json`: `orc-script fixture --mock`
  output for the test-CA and the real presentation.
- **campaignId convention.** The harness and the real-run fixture use the campaign id an
  `OrcClaim` at the placeholder address `0x000000000000000000000000000000000000C1a1` on chain
  84532 derives from `CAMPAIGN_SALT = keccak256("orc-poc-github-v1")`:
  `0x3276d4db55236b1233bcbdbb1e39216717f562a0841d80ca8c24a53204668aab`. The forge fixture test
  deploys `OrcClaim` at exactly that address, so the fixtures claim on it
  (`ORC_MOCK_FIXTURE=fixtures/orc-github-mock.json forge test` for the real one).

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
