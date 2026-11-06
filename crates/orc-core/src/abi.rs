//! Solidity-facing values: `PublicValues`, the request binding and the nullifier.
//!
//! The `abi.encode` preimages are built by hand (all operands are static
//! 32-byte words) so the byte layout is explicit; unit tests cross-check them
//! against alloy's ABI encoder.

use core::fmt;

use alloy_primitives::{Address, B256, hex};
use alloy_sol_types::sol;
use tiny_keccak::{Hasher, Keccak};

sol! {
    /// Public outputs of a verified claim. The guest commits
    /// `abi.encode(PublicValues)` (8 static words, 256 bytes) and
    /// `OrcClaim.sol` decodes it with `abi.decode(publicValues, (PublicValues))`.
    #[derive(Debug, PartialEq, Eq)]
    struct PublicValues {
        address ethAddress;
        uint64 chainId;
        bytes32 campaignId;
        uint64 repoDatabaseId;
        uint64 threshold;
        bytes32 notaryKeyHash;
        uint64 sessionTime;
        bytes32 nullifier;
    }
}

impl fmt::Display for PublicValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ethAddress     {}", self.ethAddress)?;
        writeln!(f, "chainId        {}", self.chainId)?;
        writeln!(f, "campaignId     {}", self.campaignId)?;
        writeln!(f, "repoDatabaseId {}", self.repoDatabaseId)?;
        writeln!(f, "threshold      {}", self.threshold)?;
        writeln!(f, "notaryKeyHash  {}", self.notaryKeyHash)?;
        writeln!(f, "sessionTime    {}", self.sessionTime)?;
        write!(f, "nullifier      {}", self.nullifier)
    }
}

impl PublicValues {
    /// `abi.encode(PublicValues)`: what the guest commits.
    pub fn to_abi_bytes(&self) -> Vec<u8> {
        alloy_sol_types::SolValue::abi_encode(self)
    }
}

/// Keccak-256 (Ethereum flavour, not SHA3-256).
pub fn keccak256(data: &[u8]) -> B256 {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut out);
    B256::from(out)
}

/// `keccak256(abi.encode(ethAddress, uint64 chainId, campaignId))`.
pub fn binding_digest(eth_address: Address, chain_id: u64, campaign_id: B256) -> B256 {
    let mut preimage = [0u8; 96];
    preimage[..32].copy_from_slice(&address_word(eth_address));
    preimage[32..64].copy_from_slice(&u64_word(chain_id));
    preimage[64..].copy_from_slice(campaign_id.as_slice());
    keccak256(&preimage)
}

/// Value of the `X-Orc-Binding` request header: `0x` + lowercase hex of
/// [`binding_digest`]. It ties the notarized transcript to one address, chain
/// and campaign, so a leaked presentation is useless to anyone else.
pub fn binding_header_value(eth_address: Address, chain_id: u64, campaign_id: B256) -> String {
    format!(
        "0x{}",
        hex::encode(binding_digest(eth_address, chain_id, campaign_id))
    )
}

/// `keccak256(abi.encode(uint256(databaseId), campaignId))`: one claim per
/// GitHub account per campaign.
pub fn nullifier(database_id: u64, campaign_id: B256) -> B256 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&u64_word(database_id));
    preimage[32..].copy_from_slice(campaign_id.as_slice());
    keccak256(&preimage)
}

/// `keccak256` of the notary's 33-byte compressed SEC1 secp256k1 public key.
pub fn notary_key_hash(compressed_key: &[u8]) -> B256 {
    keccak256(compressed_key)
}

fn u64_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn address_word(address: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    word
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{U256, address, b256};
    use alloy_sol_types::SolValue;

    use super::*;

    const ADDR: Address = address!("0x00000000000000000000000000000000deadbeef");
    const CAMPAIGN: B256 =
        b256!("0x1111111111111111111111111111111111111111111111111111111111111111");

    #[test]
    fn binding_matches_alloy_abi_encode() {
        let expected = keccak256(&(ADDR, 84532u64, CAMPAIGN).abi_encode_params());
        assert_eq!(binding_digest(ADDR, 84532, CAMPAIGN), expected);
    }

    #[test]
    fn binding_header_is_lowercase_prefixed_hex() {
        let value = binding_header_value(ADDR, 84532, CAMPAIGN);
        assert_eq!(value.len(), 66);
        assert!(value.starts_with("0x"));
        assert!(
            value[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    #[test]
    fn nullifier_matches_alloy_abi_encode() {
        let expected = keccak256(&(U256::from(583231u64), CAMPAIGN).abi_encode_params());
        assert_eq!(nullifier(583231, CAMPAIGN), expected);
    }

    #[test]
    fn keccak_known_vector() {
        // keccak256("") from the Ethereum yellow paper.
        assert_eq!(
            keccak256(b""),
            b256!("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
    }

    #[test]
    fn public_values_encode_to_eight_static_words() {
        let pv = PublicValues {
            ethAddress: ADDR,
            chainId: 84532,
            campaignId: CAMPAIGN,
            repoDatabaseId: 7,
            threshold: 3,
            notaryKeyHash: keccak256(b"k"),
            sessionTime: 1_700_000_000,
            nullifier: nullifier(1, CAMPAIGN),
        };
        let encoded = pv.abi_encode();
        assert_eq!(encoded.len(), 8 * 32);
        let decoded = PublicValues::abi_decode(&encoded).expect("decode");
        assert_eq!(decoded, pv);
    }
}
