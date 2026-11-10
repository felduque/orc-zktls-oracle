// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @notice Public outputs committed by the orc SP1 guest.
/// @dev MUST mirror `PublicValues` in crates/orc-core/src/abi.rs field for field. All eight
///      fields are static, so `abi.encode(PublicValues)` is a flat 256-byte tuple (no offset
///      word), byte-identical to alloy's `abi_encode()` of the same struct.
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

/// @title OrcClaim
/// @notice One claim per GitHub account per campaign. A claim carries an SP1 proof that a
///         TLSNotary-attested api.github.com GraphQL response shows at least `threshold`
///         commits by the account in repo `repoDatabaseId`, bound to `msg.sender`.
/// @dev Trust model: a single notary key (`notaryKeyHash`) attests every TLS session, so that
///      notary colluding with a prover can forge claims.
///      The nullifier keccak256(abi.encode(uint256(githubDatabaseId), campaignId)) is linkable:
///      GitHub databaseIds are sequential, so anyone can brute-force it back to the account.
///
///      Ordering: the cheap checks run on the decoded, not yet proven, values BEFORE the
///      ~270k gas proof verification. This is sound because the transaction is atomic and every
///      check is conjunctive: `verifyProof` binds exactly the same `publicValues` bytes that were
///      decoded, and it runs before any state change, so a forged value that passes a cheap
///      check is still rejected by the proof. Decoding untrusted bytes is safe: the length is
///      pinned to 256 first, and the ABI v2 decoder reverts on dirty address/uint64 words.
///      The upside is that wrong-sender (mempool copy), replay and stale claims revert for a
///      few thousand gas instead of paying for a pairing check first.
contract OrcClaim {
    /// @notice `abi.encode(PublicValues)`: eight static 32-byte words.
    uint256 public constant PUBLIC_VALUES_LENGTH = 256;

    /// @notice Tolerated clock skew for a `sessionTime` ahead of `block.timestamp`, in seconds.
    uint256 public constant MAX_FUTURE_SKEW = 300;

    /// @notice SP1 verifier (the Groth16 gateway on public chains).
    ISP1Verifier public immutable verifier;
    /// @notice Verification key of the orc SP1 guest program.
    bytes32 public immutable programVKey;
    /// @notice keccak256 of the accepted notary's compressed secp256k1 public key.
    bytes32 public immutable notaryKeyHash;
    /// @notice Campaign this contract pays out for; part of the address binding and nullifier.
    bytes32 public immutable campaignId;
    /// @notice GitHub `databaseId` of the repository the commits must be in.
    uint64 public immutable repoDatabaseId;
    /// @notice Minimum commit count a proof must attest.
    uint64 public immutable threshold;
    /// @notice Maximum age of the notarized TLS session, in seconds.
    uint64 public immutable maxAge;

    /// @notice Nullifiers already claimed (one per GitHub account per campaign).
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice A claim was accepted.
    event Claimed(
        address indexed account,
        bytes32 indexed nullifier,
        bytes32 indexed campaignId,
        uint64 sessionTime
    );

    /// @notice A constructor argument is zero.
    error InvalidConfig(string field);
    /// @notice `publicValues` is not exactly 256 bytes.
    error InvalidPublicValuesLength(uint256 length);
    /// @notice The proof is bound to `expected`, but `actual` sent the claim.
    error WrongSender(address expected, address actual);
    /// @notice The proof is bound to chain `got`, not this chain.
    error WrongChainId(uint256 expected, uint64 got);
    /// @notice The proof is for another campaign.
    error WrongCampaign(bytes32 expected, bytes32 got);
    /// @notice The proof is for another repository.
    error WrongRepo(uint64 expected, uint64 got);
    /// @notice The TLS session was attested by another notary.
    error WrongNotary(bytes32 expected, bytes32 got);
    /// @notice The proof attests fewer commits than required.
    error ThresholdTooLow(uint64 required, uint64 proven);
    /// @notice `sessionTime` is more than MAX_FUTURE_SKEW seconds ahead of the block.
    error SessionInFuture(uint64 sessionTime, uint256 blockTimestamp);
    /// @notice The TLS session is older than `maxAge`.
    error SessionExpired(uint64 sessionTime, uint256 blockTimestamp, uint64 maxAge);
    /// @notice This account already claimed in this campaign.
    error NullifierUsed(bytes32 nullifier);

    constructor(
        ISP1Verifier _verifier,
        bytes32 _programVKey,
        bytes32 _notaryKeyHash,
        bytes32 _campaignId,
        uint64 _repoDatabaseId,
        uint64 _threshold,
        uint64 _maxAge
    ) {
        if (address(_verifier) == address(0)) revert InvalidConfig("verifier");
        if (_programVKey == bytes32(0)) revert InvalidConfig("programVKey");
        if (_notaryKeyHash == bytes32(0)) revert InvalidConfig("notaryKeyHash");
        if (_campaignId == bytes32(0)) revert InvalidConfig("campaignId");
        if (_maxAge == 0) revert InvalidConfig("maxAge");

        verifier = _verifier;
        programVKey = _programVKey;
        notaryKeyHash = _notaryKeyHash;
        campaignId = _campaignId;
        repoDatabaseId = _repoDatabaseId;
        threshold = _threshold;
        maxAge = _maxAge;
    }

    /// @notice Claims for `msg.sender` with an SP1 proof of the orc guest.
    /// @param publicValues `abi.encode(PublicValues)` as committed by the guest (256 bytes).
    /// @param proofBytes SP1 proof bytes (Groth16 on public chains; empty for the mock verifier).
    function claim(bytes calldata publicValues, bytes calldata proofBytes) external {
        // Checks, cheap ones first (see the ordering note on the contract).
        if (publicValues.length != PUBLIC_VALUES_LENGTH) {
            revert InvalidPublicValuesLength(publicValues.length);
        }
        PublicValues memory pv = abi.decode(publicValues, (PublicValues));

        if (pv.ethAddress != msg.sender) revert WrongSender(pv.ethAddress, msg.sender);
        if (pv.chainId != block.chainid) revert WrongChainId(block.chainid, pv.chainId);
        if (pv.campaignId != campaignId) revert WrongCampaign(campaignId, pv.campaignId);
        if (pv.repoDatabaseId != repoDatabaseId) {
            revert WrongRepo(repoDatabaseId, pv.repoDatabaseId);
        }
        if (pv.notaryKeyHash != notaryKeyHash) revert WrongNotary(notaryKeyHash, pv.notaryKeyHash);
        if (pv.threshold < threshold) revert ThresholdTooLow(threshold, pv.threshold);
        // Freshness window. block.timestamp is intended here: a sequencer can shift it by
        // seconds, which is negligible next to a 300 s skew and a maxAge measured in hours.
        // forge-lint: disable-next-line(block-timestamp)
        if (pv.sessionTime > block.timestamp + MAX_FUTURE_SKEW) {
            revert SessionInFuture(pv.sessionTime, block.timestamp);
        }
        // A session up to MAX_FUTURE_SKEW ahead has age 0; only subtract when it is in the past.
        // forge-lint: disable-next-line(block-timestamp)
        if (pv.sessionTime < block.timestamp && block.timestamp - pv.sessionTime > maxAge) {
            revert SessionExpired(pv.sessionTime, block.timestamp, maxAge);
        }
        if (nullifierUsed[pv.nullifier]) revert NullifierUsed(pv.nullifier);

        // Last check: the proof. `verifyProof` is `view`, so this is a STATICCALL to an immutable
        // verifier: it reverts on an invalid proof and cannot re-enter to mutate state.
        verifier.verifyProof(programVKey, publicValues, proofBytes);

        // Effects.
        nullifierUsed[pv.nullifier] = true;
        emit Claimed(msg.sender, pv.nullifier, pv.campaignId, pv.sessionTime);
    }
}
