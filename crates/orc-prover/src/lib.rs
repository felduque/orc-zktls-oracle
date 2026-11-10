//! orc prover: proves "the owner of this GitHub token has >= N commits in
//! repo X" with TLSNotary, without revealing the token.
//!
//! Flow (see [`prove`] and the `orc prove` CLI):
//! 1. [`preflight::viewer`]: ordinary HTTPS `POST /graphql {viewer{id createdAt}}`
//!    to learn the token owner's node id and creation time (outside MPC).
//! 2. [`session::notarize`]: MPC-TLS with the notary; one `POST /graphql`
//!    with the exact orc request shape (`orc_core::request`).
//! 3. Commit and reveal everything except the token after `bearer github_pat_`
//!    (fine-grained PATs only, see [`GithubToken`]).
//! 4. Attestation (with server identity data) from the notary.
//! 5. [`session::Notarized::presentation`]: the presentation for the guest.

mod error;
pub mod preflight;
pub mod prove;
pub mod session;
mod target;
mod task;

pub use error::ProverError;
pub use prove::{ProveOutcome, prove};
pub use session::{Disclosure, Notarized, PhaseTimings, ProverOptions};
pub use target::{GithubToken, Target};
