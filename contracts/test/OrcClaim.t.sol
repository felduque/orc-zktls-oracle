// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, stdError} from "forge-std/Test.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {OrcClaim, PublicValues} from "../src/OrcClaim.sol";

contract OrcClaimTest is Test {
    // Mirrors OrcClaim.Claimed so vm.expectEmit can match it.
    event Claimed(
        address indexed account,
        bytes32 indexed nullifier,
        bytes32 indexed campaignId,
        uint64 sessionTime
    );

    uint64 internal constant CHAIN_ID = 84532; // Base Sepolia
    bytes32 internal constant VKEY = keccak256("orc-program-vkey");
    bytes32 internal constant NOTARY = keccak256("orc-notary-key");
    bytes32 internal constant CAMPAIGN = keccak256("orc-campaign-1");
    uint64 internal constant REPO = 1_296_269;
    uint64 internal constant THRESHOLD = 3;
    uint64 internal constant MAX_AGE = 1 days;
    uint64 internal constant NOW = 1_800_000_000;
    uint64 internal constant SKEW = 300;
    uint64 internal constant GITHUB_DATABASE_ID = 583_231;

    SP1MockVerifier internal mockVerifier;
    OrcClaim internal orc;
    address internal alice;

    function setUp() public {
        vm.chainId(CHAIN_ID);
        vm.warp(NOW);
        alice = makeAddr("alice");
        mockVerifier = new SP1MockVerifier();
        orc = _deploy(VKEY, NOTARY, CAMPAIGN, REPO, THRESHOLD, MAX_AGE);
    }

    // ---------------------------------------------------------------- helpers

    function _deploy(
        bytes32 vkey,
        bytes32 notary,
        bytes32 campaign,
        uint64 repo,
        uint64 threshold,
        uint64 maxAge
    ) internal returns (OrcClaim) {
        return new OrcClaim(
            ISP1Verifier(address(mockVerifier)), vkey, notary, campaign, repo, threshold, maxAge
        );
    }

    /// A valid claim for `alice`, five minutes after the TLS session.
    function _pv() internal view returns (PublicValues memory) {
        return PublicValues({
            ethAddress: alice,
            chainId: CHAIN_ID,
            campaignId: CAMPAIGN,
            repoDatabaseId: REPO,
            threshold: THRESHOLD + 2,
            notaryKeyHash: NOTARY,
            sessionTime: NOW - 5 minutes,
            nullifier: _nullifier(GITHUB_DATABASE_ID, CAMPAIGN)
        });
    }

    /// Same preimage as orc-core `nullifier()`: abi.encode(uint256(databaseId), campaignId).
    function _nullifier(uint64 databaseId, bytes32 campaign) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(databaseId), campaign));
    }

    function _claimAs(address sender, PublicValues memory pv) internal {
        vm.prank(sender);
        orc.claim(abi.encode(pv), "");
    }

    function _u64(uint256 x) internal pure returns (uint64) {
        require(x <= type(uint64).max, "u64 overflow");
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(x);
    }

    // ------------------------------------------------------------ happy path

    function test_Claim_HappyPath() public {
        PublicValues memory pv = _pv();
        assertFalse(orc.nullifierUsed(pv.nullifier));

        vm.expectEmit(true, true, true, true, address(orc));
        emit Claimed(alice, pv.nullifier, CAMPAIGN, pv.sessionTime);
        _claimAs(alice, pv);

        assertTrue(orc.nullifierUsed(pv.nullifier));
    }

    function test_Claim_ExactThreshold() public {
        PublicValues memory pv = _pv();
        pv.threshold = THRESHOLD;
        _claimAs(alice, pv);
        assertTrue(orc.nullifierUsed(pv.nullifier));
    }

    function test_Constructor_SetsImmutables() public view {
        assertEq(address(orc.verifier()), address(mockVerifier));
        assertEq(orc.programVKey(), VKEY);
        assertEq(orc.notaryKeyHash(), NOTARY);
        assertEq(orc.campaignId(), CAMPAIGN);
        assertEq(orc.repoDatabaseId(), REPO);
        assertEq(orc.threshold(), THRESHOLD);
        assertEq(orc.maxAge(), MAX_AGE);
    }

    // ------------------------------------------------------------ rejections

    function test_RevertWhen_WrongSender() public {
        address mallory = makeAddr("mallory");
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.WrongSender.selector, alice, mallory));
        _claimAs(mallory, _pv());
    }

    function test_RevertWhen_Replay() public {
        PublicValues memory pv = _pv();
        _claimAs(alice, pv);

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.NullifierUsed.selector, pv.nullifier));
        _claimAs(alice, pv);
    }

    function test_RevertWhen_ReplayFromAnotherAddress() public {
        // Same GitHub account (same nullifier), fresh proof bound to a second wallet.
        PublicValues memory pv = _pv();
        _claimAs(alice, pv);

        address bob = makeAddr("bob");
        pv.ethAddress = bob;
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.NullifierUsed.selector, pv.nullifier));
        _claimAs(bob, pv);
    }

    function test_RevertWhen_Stale() public {
        PublicValues memory pv = _pv();
        uint256 later = uint256(pv.sessionTime) + MAX_AGE + 1;
        vm.warp(later);
        vm.expectRevert(
            abi.encodeWithSelector(OrcClaim.SessionExpired.selector, pv.sessionTime, later, MAX_AGE)
        );
        _claimAs(alice, pv);
    }

    function test_RevertWhen_SessionInFuture() public {
        PublicValues memory pv = _pv();
        pv.sessionTime = NOW + SKEW + 1;
        vm.expectRevert(
            abi.encodeWithSelector(OrcClaim.SessionInFuture.selector, pv.sessionTime, NOW)
        );
        _claimAs(alice, pv);
    }

    function test_SessionTimeBoundaries() public {
        uint64[2] memory accepted = [NOW + SKEW, NOW - MAX_AGE];
        for (uint256 i = 0; i < accepted.length; i++) {
            PublicValues memory pv = _pv();
            pv.sessionTime = accepted[i];
            pv.nullifier = _nullifier(_u64(i), CAMPAIGN);
            _claimAs(alice, pv);
            assertTrue(orc.nullifierUsed(pv.nullifier));
        }
    }

    function test_RevertWhen_WrongChainId() public {
        PublicValues memory pv = _pv();
        pv.chainId = 8453; // Base mainnet
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.WrongChainId.selector, CHAIN_ID, 8453));
        _claimAs(alice, pv);
    }

    function test_RevertWhen_WrongCampaign() public {
        PublicValues memory pv = _pv();
        bytes32 other = keccak256("orc-campaign-2");
        pv.campaignId = other;
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.WrongCampaign.selector, CAMPAIGN, other));
        _claimAs(alice, pv);
    }

    function test_RevertWhen_WrongRepo() public {
        PublicValues memory pv = _pv();
        pv.repoDatabaseId = REPO + 1;
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.WrongRepo.selector, REPO, REPO + 1));
        _claimAs(alice, pv);
    }

    function test_RevertWhen_WrongNotary() public {
        PublicValues memory pv = _pv();
        bytes32 rogue = keccak256("rogue-notary");
        pv.notaryKeyHash = rogue;
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.WrongNotary.selector, NOTARY, rogue));
        _claimAs(alice, pv);
    }

    function test_RevertWhen_ThresholdTooLow() public {
        PublicValues memory pv = _pv();
        pv.threshold = THRESHOLD - 1;
        vm.expectRevert(
            abi.encodeWithSelector(OrcClaim.ThresholdTooLow.selector, THRESHOLD, THRESHOLD - 1)
        );
        _claimAs(alice, pv);
    }

    function test_RevertWhen_NonEmptyProofOnMock() public {
        // SP1MockVerifier only accepts empty proof bytes; it fails with assert -> Panic(0x01).
        PublicValues memory pv = _pv();
        vm.expectRevert(stdError.assertionError);
        vm.prank(alice);
        orc.claim(abi.encode(pv), hex"4388a21c");
        assertFalse(orc.nullifierUsed(pv.nullifier));
    }

    function test_RevertWhen_PublicValuesWrongLength() public {
        bytes memory good = abi.encode(_pv());
        uint256[4] memory lengths = [uint256(0), 255, 257, 288];
        for (uint256 i = 0; i < lengths.length; i++) {
            bytes memory bad = new bytes(lengths[i]);
            for (uint256 j = 0; j < bad.length && j < good.length; j++) {
                bad[j] = good[j];
            }
            vm.expectRevert(
                abi.encodeWithSelector(OrcClaim.InvalidPublicValuesLength.selector, lengths[i])
            );
            vm.prank(alice);
            orc.claim(bad, "");
        }
    }

    function test_RevertWhen_PublicValuesNotCanonical() public {
        // Right length, but the address word has dirty upper bytes: the ABI v2 decoder reverts.
        bytes memory bad = abi.encode(_pv());
        bad[0] = 0x01;
        vm.expectRevert(bytes(""));
        vm.prank(alice);
        orc.claim(bad, "");

        // Same for a uint64 word (chainId) with bits above 64 set.
        bad = abi.encode(_pv());
        bad[32 + 23] = 0x01;
        vm.expectRevert(bytes(""));
        vm.prank(alice);
        orc.claim(bad, "");
    }

    function test_RevertWhen_ConstructorZeroConfig() public {
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "verifier"));
        new OrcClaim(ISP1Verifier(address(0)), VKEY, NOTARY, CAMPAIGN, REPO, THRESHOLD, MAX_AGE);

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "programVKey"));
        _deploy(bytes32(0), NOTARY, CAMPAIGN, REPO, THRESHOLD, MAX_AGE);

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "notaryKeyHash"));
        _deploy(VKEY, bytes32(0), CAMPAIGN, REPO, THRESHOLD, MAX_AGE);

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "campaignId"));
        _deploy(VKEY, NOTARY, bytes32(0), REPO, THRESHOLD, MAX_AGE);

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "maxAge"));
        _deploy(VKEY, NOTARY, CAMPAIGN, REPO, THRESHOLD, 0);
    }

    // ------------------------------------------------------------------ fuzz

    function testFuzz_ThresholdAtOrAbove(uint256 seed) public {
        PublicValues memory pv = _pv();
        pv.threshold = _u64(bound(seed, THRESHOLD, type(uint64).max));
        _claimAs(alice, pv);
        assertTrue(orc.nullifierUsed(pv.nullifier));
    }

    function testFuzz_ThresholdBelow(uint256 seed) public {
        PublicValues memory pv = _pv();
        pv.threshold = _u64(bound(seed, 0, THRESHOLD - 1));
        vm.expectRevert(
            abi.encodeWithSelector(OrcClaim.ThresholdTooLow.selector, THRESHOLD, pv.threshold)
        );
        _claimAs(alice, pv);
    }

    function testFuzz_SessionTimeInWindow(uint256 seed) public {
        PublicValues memory pv = _pv();
        pv.sessionTime = _u64(bound(seed, NOW - MAX_AGE, NOW + SKEW));
        _claimAs(alice, pv);
        assertTrue(orc.nullifierUsed(pv.nullifier));
    }

    function testFuzz_SessionTimeTooOld(uint256 seed) public {
        PublicValues memory pv = _pv();
        pv.sessionTime = _u64(bound(seed, 0, NOW - MAX_AGE - 1));
        vm.expectRevert(
            abi.encodeWithSelector(OrcClaim.SessionExpired.selector, pv.sessionTime, NOW, MAX_AGE)
        );
        _claimAs(alice, pv);
    }

    function testFuzz_SessionTimeTooFarAhead(uint256 seed) public {
        PublicValues memory pv = _pv();
        pv.sessionTime = _u64(bound(seed, NOW + SKEW + 1, type(uint64).max));
        vm.expectRevert(
            abi.encodeWithSelector(OrcClaim.SessionInFuture.selector, pv.sessionTime, NOW)
        );
        _claimAs(alice, pv);
    }

    // ------------------------------------------------------- ABI cross-check

    /// `abi.encode(PublicValues)` for the vector in orc-core's
    /// `public_values_encode_to_eight_static_words` test, generated with Foundry 1.8.7:
    ///   C=0x1111111111111111111111111111111111111111111111111111111111111111
    ///   NK=$(cast keccak k)
    ///   NUL=$(cast keccak $(cast abi-encode "f(uint256,bytes32)" 1 $C))
    ///   cast abi-encode "f((address,uint64,bytes32,uint64,uint64,bytes32,uint64,bytes32))" \
    ///     "(0x00000000000000000000000000000000deadbeef,84532,$C,7,3,$NK,1700000000,$NUL)"
    /// The flat form `cast abi-encode "f(address,uint64,...,bytes32)" ...` prints the same
    /// 256 bytes: a static struct has no offset word.
    bytes internal constant CAST_ENCODED = hex"00000000000000000000000000000000000000000000000000000000deadbeef"
        hex"0000000000000000000000000000000000000000000000000000000000014a34"
        hex"1111111111111111111111111111111111111111111111111111111111111111"
        hex"0000000000000000000000000000000000000000000000000000000000000007"
        hex"0000000000000000000000000000000000000000000000000000000000000003"
        hex"f3d0adcb6a1c70832365e9da0a6b2f5199422f6a53c67cfad171114e3442aa0f"
        hex"000000000000000000000000000000000000000000000000000000006553f100"
        hex"8a1a59a536742613f251075415cb3bcfd95758a71bd84e57840cbf9f016f9cf9";
    bytes32 internal constant CAST_NOTARY_KEY_HASH =
        0xf3d0adcb6a1c70832365e9da0a6b2f5199422f6a53c67cfad171114e3442aa0f;
    bytes32 internal constant CAST_NULLIFIER =
        0x8a1a59a536742613f251075415cb3bcfd95758a71bd84e57840cbf9f016f9cf9;

    function test_AbiEncoding_MatchesCastAndOrcCore() public pure {
        bytes32 campaign = 0x1111111111111111111111111111111111111111111111111111111111111111;
        PublicValues memory pv = PublicValues({
            ethAddress: 0x00000000000000000000000000000000DeaDBeef,
            chainId: 84532,
            campaignId: campaign,
            repoDatabaseId: 7,
            threshold: 3,
            notaryKeyHash: keccak256("k"),
            sessionTime: 1_700_000_000,
            nullifier: _nullifier(1, campaign)
        });

        // Hash preimages agree with cast (and with orc-core's hand-built preimages).
        assertEq(pv.notaryKeyHash, CAST_NOTARY_KEY_HASH);
        assertEq(pv.nullifier, CAST_NULLIFIER);

        bytes memory encoded = abi.encode(pv);
        assertEq(encoded.length, 256);
        assertEq(encoded, CAST_ENCODED);
        // Struct encoding == flat 8-tuple encoding (what alloy's `abi_encode()` produces).
        assertEq(
            encoded,
            abi.encode(
                pv.ethAddress,
                pv.chainId,
                pv.campaignId,
                pv.repoDatabaseId,
                pv.threshold,
                pv.notaryKeyHash,
                pv.sessionTime,
                pv.nullifier
            )
        );

        PublicValues memory back = abi.decode(CAST_ENCODED, (PublicValues));
        assertEq(keccak256(abi.encode(back)), keccak256(encoded));
    }

    // ------------------------------------------------ cross-agent integration

    /// Claims with the mock-prover fixture written by the SP1 host (M2):
    /// `{"programVKey":"0x..","publicValues":"0x..","proof":"0x"}`. Skipped until it exists.
    /// `ORC_MOCK_FIXTURE` overrides the path (relative to contracts/, must stay in fixtures/).
    function test_Fixture_OrcMock() public {
        string memory rel = vm.envOr("ORC_MOCK_FIXTURE", string("fixtures/orc-mock.json"));
        string memory path = string.concat(vm.projectRoot(), "/", rel);
        if (!vm.exists(path)) {
            vm.skip(true, string.concat(rel, " not written yet (M2)"));
            return;
        }

        string memory json = vm.readFile(path);
        bytes32 vkey = vm.parseJsonBytes32(json, ".programVKey");
        bytes memory publicValues = vm.parseJsonBytes(json, ".publicValues");
        bytes memory proof = vm.parseJsonBytes(json, ".proof");

        assertEq(publicValues.length, 256, "publicValues must be 8 static words");
        assertEq(proof.length, 0, "mock fixture must carry an empty proof");
        PublicValues memory pv = abi.decode(publicValues, (PublicValues));

        // Rebuild the chain context the guest committed to.
        vm.chainId(pv.chainId);
        vm.warp(uint256(pv.sessionTime) + 60);
        OrcClaim fixtureOrc = _deployFor(vkey, pv);

        vm.expectEmit(true, true, true, true, address(fixtureOrc));
        emit Claimed(pv.ethAddress, pv.nullifier, pv.campaignId, pv.sessionTime);
        vm.prank(pv.ethAddress);
        fixtureOrc.claim(publicValues, proof);
        assertTrue(fixtureOrc.nullifierUsed(pv.nullifier));

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.NullifierUsed.selector, pv.nullifier));
        vm.prank(pv.ethAddress);
        fixtureOrc.claim(publicValues, proof);
    }

    function _deployFor(bytes32 vkey, PublicValues memory pv) internal returns (OrcClaim) {
        return
            _deploy(vkey, pv.notaryKeyHash, pv.campaignId, pv.repoDatabaseId, pv.threshold, MAX_AGE);
    }
}
