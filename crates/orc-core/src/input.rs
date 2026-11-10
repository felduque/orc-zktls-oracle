use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

/// Public claim parameters, supplied next to the presentation (as
/// `guest-input.json` on the host, as guest stdin in SP1).
///
/// Every field ends up either in the binding header the server saw, in the
/// canonical request body, or in `PublicValues`, so none of it is trusted
/// without being checked against the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestInput {
    /// Account that may claim on-chain (`msg.sender` in `OrcClaim.sol`).
    pub eth_address: Address,
    /// EVM chain id the claim is for (84532 = Base Sepolia).
    pub chain_id: u64,
    /// Campaign identifier; scopes the nullifier.
    pub campaign_id: B256,
    /// Repository owner (GitHub login or organization).
    pub owner: String,
    /// Repository name.
    pub name: String,
    /// Minimum commit count to prove.
    pub threshold: u64,
    /// Snapshot, unix seconds (`OrcClaim.snapshot()`): only commits authored
    /// up to it count, and the account must have been created before it.
    pub snapshot: u64,
}
