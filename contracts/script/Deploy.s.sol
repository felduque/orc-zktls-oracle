// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {OrcClaim} from "../src/OrcClaim.sol";

/// @notice Deploys OrcClaim. Configuration comes from the environment:
///   SP1_VERIFIER      verifier address (default: SP1 Groth16 gateway on Base Sepolia, 84532)
///   PROGRAM_VKEY      bytes32 vkey of the orc guest (`orc-script vkey`)
///   NOTARY_KEY_HASH   bytes32 keccak256 of the notary's compressed secp256k1 key
///   CAMPAIGN_ID       bytes32 campaign id
///   REPO_DATABASE_ID  uint64 GitHub repository databaseId
///   THRESHOLD         uint64 minimum commit count
///   MAX_AGE           uint64 maximum TLS session age, in seconds
///
/// Dry run (no --broadcast) against a local anvil:
///   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --private-key <anvil key>
contract Deploy is Script {
    /// @notice SP1VerifierGateway (Groth16) on Base Sepolia, from sp1-contracts v6.1.1
    ///         deployments/84532.json. Routes the v6.1.0 Groth16 selector 0x4388a21c.
    address internal constant BASE_SEPOLIA_GROTH16_GATEWAY =
        0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;

    uint256 internal constant ANVIL_CHAIN_ID = 31337;

    function run() external returns (OrcClaim orc) {
        address verifier = vm.envOr("SP1_VERIFIER", BASE_SEPOLIA_GROTH16_GATEWAY);
        bytes32 programVKey = vm.envBytes32("PROGRAM_VKEY");
        bytes32 notaryKeyHash = vm.envBytes32("NOTARY_KEY_HASH");
        bytes32 campaignId = vm.envBytes32("CAMPAIGN_ID");
        uint64 repoDatabaseId = _envUint64("REPO_DATABASE_ID");
        uint64 threshold = _envUint64("THRESHOLD");
        uint64 maxAge = _envUint64("MAX_AGE");

        // A verifier without code would brick every claim. Only a local anvil dry run, where
        // the gateway does not exist, may skip this.
        if (verifier.code.length == 0) {
            require(block.chainid == ANVIL_CHAIN_ID, "SP1_VERIFIER has no code on this chain");
            console2.log("WARNING: SP1_VERIFIER has no code here (local dry run only)");
        }

        vm.startBroadcast();
        orc = new OrcClaim(
            ISP1Verifier(verifier),
            programVKey,
            notaryKeyHash,
            campaignId,
            repoDatabaseId,
            threshold,
            maxAge
        );
        vm.stopBroadcast();

        console2.log("chainId       ", block.chainid);
        console2.log("OrcClaim      ", address(orc));
        console2.log("verifier      ", verifier);
        console2.log("programVKey   ", vm.toString(programVKey));
        console2.log("notaryKeyHash ", vm.toString(notaryKeyHash));
        console2.log("campaignId    ", vm.toString(campaignId));
        console2.log("repoDatabaseId", uint256(repoDatabaseId));
        console2.log("threshold     ", uint256(threshold));
        console2.log("maxAge        ", uint256(maxAge));
    }

    function _envUint64(string memory name) internal view returns (uint64) {
        uint256 value = vm.envUint(name);
        require(value <= type(uint64).max, string.concat(name, " does not fit in uint64"));
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(value);
    }
}
