# Security policy

## Status

orc is an **unaudited proof of concept**. It is meant for experiments on testnets (Base Sepolia)
only. Do not deploy `OrcClaim` to a mainnet, and do not use orc to protect funds, access or
anything else of value. There are no releases and no supported versions. Only the `main` branch
is maintained, on a best-effort basis.

## Known limitations

The following are documented design limits of the PoC, not vulnerabilities:

- a single notary is trusted not to collude with provers;
- `presentation.bin` reveals the full GitHub response (login, ids, exact commit count) to
  whoever holds it, and so does a remote prover;
- the nullifier is linkable to the GitHub account (`databaseId`s are sequential);
- TLS 1.2 only;
- `sessionTime` comes from the notary's clock.

The reasoning and the planned fixes are in the README:
[Trust model and privacy](README.md#trust-model-and-privacy) and
[Known limitations and future work](README.md#known-limitations-and-future-work). Ideas on these
are welcome as regular issues.

## What to report

Anything that breaks the guarantees the README describes **within** that trust model, for
example:

- a claim, proof or `PublicValues` that `orc_core::verify_claim` (the SP1 guest) or `OrcClaim`
  should reject but accepts: a different query or response smuggled past the transcript
  checks, someone else's commit count, a wrong binding, a replay, a bypassed freshness check;
- a way to claim for an address other than the one bound in the TLS request;
- the GitHub token leaking to the notary, into `presentation.bin`, into `guest-input.json` or
  into logs;
- a prover being able to crash the notary or make it sign something it should not.

Vulnerabilities in TLSNotary, SP1 or sp1-contracts themselves should go to those projects.

## How to report

Please report privately through GitHub's **private vulnerability reporting**: on the repository
page open **Security → Advisories → Report a vulnerability**
(<https://github.com/felduque/orc-zktls-oracle/security/advisories/new>).

Please do **not** open a public issue, discussion or pull request for an undisclosed
vulnerability. If private reporting is unavailable, open a public issue that only asks for a
private channel, with no details.

A useful report includes the affected component (`orc-core`, `orc-notary`, `orc-prover`,
`program/`, `OrcClaim.sol`), the commit, steps or a test case to reproduce, and the impact. This
is a personal project with no bug bounty, so responses are best effort.
