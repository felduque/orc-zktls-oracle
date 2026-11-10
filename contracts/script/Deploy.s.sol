// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {OrcClaim} from "../src/OrcClaim.sol";

/// @notice Deploys OrcClaim. Configuration comes from the environment:
///   SP1_VERIFIER      verifier address (default: the canonical SP1 Groth16 gateway)
///   PROGRAM_VKEY      bytes32 vkey of the PRODUCTION orc guest (`orc-script vkey --env`)
///   TEST_CA_VKEY      optional bytes32 vkey of the TEST-CA guest (`orc-script vkey --env`);
///                     the deploy refuses a PROGRAM_VKEY equal to it
///   NOTARY_KEY_HASH   bytes32 keccak256 of the notary's compressed secp256k1 key
///   CAMPAIGN_SALT     bytes32; the contract derives
///                     campaignId = keccak256(abi.encode(chainid, address(OrcClaim), salt))
///   REPO_DATABASE_ID  uint64 GitHub repository databaseId
///   THRESHOLD         uint64 minimum commit count
///   SNAPSHOT          uint64 unix seconds, not in the future: only commits authored up to it
///                     count, and accounts created at or after it cannot claim
///   MAX_AGE           uint64 maximum TLS session age, in seconds
///   ALLOW_NONCANONICAL_VERIFIER  set to 1 to allow, off anvil (31337), a verifier other than
///                     the canonical gateway (for example SP1MockVerifier). Never on a real
///                     campaign: SP1MockVerifier accepts any public values.
///
/// Dry run (no --broadcast) against a local anvil:
///   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --private-key <anvil key>
contract Deploy is Script {
    /// @notice The canonical SP1VerifierGateway (Groth16), from sp1-contracts v6.1.1
    ///         deployments/84532.json (same address on every chain sp1-contracts deploys to).
    ///         Routes the v6.1.0 Groth16 selector 0x4388a21c.
    address internal constant CANONICAL_GROTH16_GATEWAY =
        0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;

    uint256 internal constant ANVIL_CHAIN_ID = 31337;

    function run() external returns (OrcClaim orc) {
        address verifier = vm.envOr("SP1_VERIFIER", CANONICAL_GROTH16_GATEWAY);
        bytes32 programVKey = vm.envBytes32("PROGRAM_VKEY");
        bytes32 testCaVKey = vm.envOr("TEST_CA_VKEY", bytes32(0));
        bytes32 notaryKeyHash = vm.envBytes32("NOTARY_KEY_HASH");
        bytes32 campaignSalt = vm.envBytes32("CAMPAIGN_SALT");
        uint64 repoDatabaseId = _envUint64("REPO_DATABASE_ID");
        uint64 threshold = _envUint64("THRESHOLD");
        uint64 snapshot = _envUint64("SNAPSHOT");
        uint64 maxAge = _envUint64("MAX_AGE");
        bool local = block.chainid == ANVIL_CHAIN_ID;

        // Off a local chain, only the canonical gateway really verifies Groth16 proofs of the
        // guest. Anything else (a mock, a fork of the gateway) needs an explicit opt-in.
        if (!local && verifier != CANONICAL_GROTH16_GATEWAY) {
            require(
                vm.envOr("ALLOW_NONCANONICAL_VERIFIER", uint256(0)) == 1,
                "SP1_VERIFIER is not the canonical SP1 Groth16 gateway (set ALLOW_NONCANONICAL_VERIFIER=1 to override)"
            );
            console2.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            console2.log("!!! WARNING: NON-CANONICAL SP1_VERIFIER on chain", block.chainid);
            console2.log("!!!", verifier);
            console2.log("!!! ALLOW_NONCANONICAL_VERIFIER=1: claims are only as sound as it is.");
            console2.log(
                "!!! SP1MockVerifier accepts ANY public values: never for a real campaign."
            );
            console2.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        }

        // A verifier without code would brick every claim. Only a local anvil dry run, where
        // the gateway does not exist, may skip this.
        if (verifier.code.length == 0) {
            require(local, "SP1_VERIFIER has no code on this chain");
            console2.log("WARNING: SP1_VERIFIER has no code here (local dry run only)");
        }

        // The test-CA guest trusts tlsn's PUBLIC test CA: anyone can forge "GitHub" responses
        // for it. Its vkey must never be a contract's programVKey.
        require(
            testCaVKey == bytes32(0) || programVKey != testCaVKey,
            "PROGRAM_VKEY is the TEST-CA guest vkey: never deploy it"
        );
        if (testCaVKey == bytes32(0) && !local) {
            console2.log(
                "WARNING: TEST_CA_VKEY not set, cannot check that PROGRAM_VKEY is not the test-CA vkey"
            );
        }

        vm.startBroadcast();
        orc = new OrcClaim(
            ISP1Verifier(verifier),
            programVKey,
            notaryKeyHash,
            campaignSalt,
            repoDatabaseId,
            threshold,
            snapshot,
            maxAge
        );
        vm.stopBroadcast();

        console2.log("chainId       ", block.chainid);
        console2.log("OrcClaim      ", address(orc));
        console2.log("verifier      ", verifier);
        console2.log("programVKey   ", vm.toString(programVKey));
        console2.log("notaryKeyHash ", vm.toString(notaryKeyHash));
        console2.log("campaignSalt  ", vm.toString(campaignSalt));
        console2.log("campaignId    ", vm.toString(orc.campaignId()));
        console2.log("repoDatabaseId", uint256(repoDatabaseId));
        console2.log("threshold     ", uint256(threshold));
        console2.log("snapshot      ", uint256(snapshot));
        console2.log("maxAge        ", uint256(maxAge));
    }

    function _envUint64(string memory name) internal view returns (uint64) {
        uint256 value = vm.envUint(name);
        require(value <= type(uint64).max, string.concat(name, " does not fit in uint64"));
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(value);
    }
}
