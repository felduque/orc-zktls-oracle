// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {OrcClaim} from "../src/OrcClaim.sol";
import {Deploy} from "../script/Deploy.s.sol";

/// Guards of script/Deploy.s.sol (L3): off anvil it refuses a non-canonical verifier unless
/// ALLOW_NONCANONICAL_VERIFIER=1, and it refuses PROGRAM_VKEY == TEST_CA_VKEY everywhere.
///
/// Everything runs in ONE test function on purpose: the script reads the process environment,
/// which forge shares between test functions running in parallel.
contract DeployTest is Test {
    address internal constant GATEWAY = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
    bytes32 internal constant PROD_VKEY = keccak256("production vkey");
    bytes32 internal constant TEST_CA_VKEY = keccak256("test-ca vkey");
    bytes32 internal constant SALT = keccak256("deploy-test-salt");
    uint64 internal constant NOW = 1_800_000_000;

    Deploy internal script;
    address internal mock;

    function setUp() public {
        vm.warp(NOW);
        script = new Deploy();
        mock = address(new SP1MockVerifier());
        vm.setEnv("PROGRAM_VKEY", vm.toString(PROD_VKEY));
        vm.setEnv("TEST_CA_VKEY", vm.toString(TEST_CA_VKEY));
        vm.setEnv("NOTARY_KEY_HASH", vm.toString(keccak256("notary")));
        vm.setEnv("CAMPAIGN_SALT", vm.toString(SALT));
        vm.setEnv("REPO_DATABASE_ID", "1452696697");
        vm.setEnv("THRESHOLD", "5");
        vm.setEnv("SNAPSHOT", vm.toString(uint256(NOW - 1 days)));
        vm.setEnv("MAX_AGE", "3600");
        vm.setEnv("ALLOW_NONCANONICAL_VERIFIER", "0");
    }

    function _deployed(OrcClaim orc, address verifier) internal view {
        assertEq(address(orc.verifier()), verifier);
        assertEq(orc.programVKey(), PROD_VKEY);
        assertEq(orc.campaignSalt(), SALT);
        assertEq(orc.campaignId(), keccak256(abi.encode(vm.getChainId(), address(orc), SALT)));
        assertEq(orc.snapshot(), NOW - 1 days);
    }

    function test_DeployGuards() public {
        // ---- a public chain (Base Sepolia)
        vm.chainId(84532);

        // The canonical gateway without code here: refused.
        vm.setEnv("SP1_VERIFIER", vm.toString(GATEWAY));
        vm.expectRevert(bytes("SP1_VERIFIER has no code on this chain"));
        script.run();

        // The canonical gateway (code installed): deploys.
        vm.etch(GATEWAY, mock.code);
        _deployed(script.run(), GATEWAY);

        // ... but never with the test-CA vkey.
        vm.setEnv("TEST_CA_VKEY", vm.toString(PROD_VKEY));
        vm.expectRevert(bytes("PROGRAM_VKEY is the TEST-CA guest vkey: never deploy it"));
        script.run();
        vm.setEnv("TEST_CA_VKEY", vm.toString(TEST_CA_VKEY));

        // A non-canonical verifier (here SP1MockVerifier): refused without the opt-in ...
        vm.setEnv("SP1_VERIFIER", vm.toString(mock));
        vm.expectRevert(
            bytes(
                "SP1_VERIFIER is not the canonical SP1 Groth16 gateway (set ALLOW_NONCANONICAL_VERIFIER=1 to override)"
            )
        );
        script.run();
        // ... any value other than 1 is not an opt-in ...
        vm.setEnv("ALLOW_NONCANONICAL_VERIFIER", "2");
        vm.expectRevert();
        script.run();
        // ... and accepted with ALLOW_NONCANONICAL_VERIFIER=1.
        vm.setEnv("ALLOW_NONCANONICAL_VERIFIER", "1");
        _deployed(script.run(), mock);
        vm.setEnv("ALLOW_NONCANONICAL_VERIFIER", "0");

        // ---- local anvil: any verifier, but still never the test-CA vkey.
        vm.chainId(31337);
        _deployed(script.run(), mock);
        vm.setEnv("TEST_CA_VKEY", vm.toString(PROD_VKEY));
        vm.expectRevert(bytes("PROGRAM_VKEY is the TEST-CA guest vkey: never deploy it"));
        script.run();
    }
}
