//! Guest-safe verification of an orc claim:
//! "the GitHub account behind this token has at least N commits in repo X",
//! bound to an Ethereum address.
//!
//! The same [`verify_claim`] runs natively (prover self-check, tests) and
//! inside the SP1 guest, so this crate has no async runtime or network
//! dependencies.
//!
//! Modules:
//! - [`abi`]: `PublicValues` (Solidity ABI), binding header, nullifier, keccak.
//! - [`graphql`]: the canonical GraphQL request body and strict response types.
//! - [`http`]: strict HTTP/1.1 parsing of the notarized transcript.
//! - [`request`]: the exact HTTP request shape the prover sends.
//! - [`verify`]: [`verify_claim`] and [`VerifyParams`].

pub mod abi;
mod error;
pub mod graphql;
pub mod http;
mod input;
pub mod request;
pub mod verify;

pub use abi::{
    PublicValues, binding_digest, binding_header_value, keccak256, notary_key_hash, nullifier,
};
pub use error::ClaimError;
pub use graphql::{GRAPHQL_QUERY, graphql_body};
pub use input::GuestInput;
pub use verify::{
    DEFAULT_MAX_AUTH_VALUE_LEN, GITHUB_API_HOST, MAX_PRESENTATION_BYTES, NoTracker, Tracker,
    VerifyParams, phase, verify_claim, verify_claim_tracked,
};

/// Re-exported so callers can build [`GuestInput`] without a direct alloy dependency.
pub use alloy_primitives::{Address, B256};
