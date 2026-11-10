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
    bytes32 internal constant SALT = keccak256("orc-campaign-1");
    uint64 internal constant REPO = 1_296_269;
    uint64 internal constant THRESHOLD = 3;
    uint64 internal constant MAX_AGE = 1 days;
    uint64 internal constant NOW = 1_800_000_000;
    uint64 internal constant SNAPSHOT = NOW - 30 days;
    uint64 internal constant SKEW = 300;
    uint64 internal constant GITHUB_DATABASE_ID = 583_231;

    /// Fixture convention (README, "Fixtures"): harness and real-run fixtures carry the
    /// campaignId an OrcClaim at this placeholder address derives from this salt.
    address internal constant FIXTURE_ORC = 0x000000000000000000000000000000000000C1a1;
    bytes32 internal constant FIXTURE_SALT = keccak256("orc-poc-github-v1");

    SP1MockVerifier internal mockVerifier;
    OrcClaim internal orc;
    bytes32 internal campaign;
    address internal alice;

    function setUp() public {
        vm.chainId(CHAIN_ID);
        vm.warp(NOW);
        alice = makeAddr("alice");
        mockVerifier = new SP1MockVerifier();
        orc = _deploy(VKEY, NOTARY, SALT, REPO, THRESHOLD, MAX_AGE);
        campaign = orc.campaignId();
    }

    // ---------------------------------------------------------------- helpers

    function _deploy(
        bytes32 vkey,
        bytes32 notary,
        bytes32 salt,
        uint64 repo,
        uint64 threshold,
        uint64 maxAge
    ) internal returns (OrcClaim) {
        return new OrcClaim(
            ISP1Verifier(address(mockVerifier)),
            vkey,
            notary,
            salt,
            repo,
            threshold,
            SNAPSHOT,
            maxAge
        );
    }

    /// Same derivation as the OrcClaim constructor (and orc-core `campaign_id()`).
    function _campaignId(uint256 chainId, address orcAddress, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(chainId, orcAddress, salt));
    }

    /// A valid claim for `alice` on `orc`, five minutes after the TLS session.
    function _pv() internal view returns (PublicValues memory) {
        return PublicValues({
            ethAddress: alice,
            chainId: CHAIN_ID,
            campaignId: campaign,
            repoDatabaseId: REPO,
            threshold: THRESHOLD + 2,
            snapshot: SNAPSHOT,
            notaryKeyHash: NOTARY,
            sessionTime: NOW - 5 minutes,
            nullifier: _nullifier(GITHUB_DATABASE_ID, campaign)
        });
    }

    /// Same preimage as orc-core `nullifier()`: abi.encode(uint256(databaseId), campaignId).
    function _nullifier(uint64 databaseId, bytes32 campaignId) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(databaseId), campaignId));
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
        emit Claimed(alice, pv.nullifier, campaign, pv.sessionTime);
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
        assertEq(orc.campaignSalt(), SALT);
        assertEq(orc.campaignId(), _campaignId(CHAIN_ID, address(orc), SALT));
        assertEq(orc.repoDatabaseId(), REPO);
        assertEq(orc.threshold(), THRESHOLD);
        assertEq(orc.snapshot(), SNAPSHOT);
        assertEq(orc.maxAge(), MAX_AGE);
    }

    // ------------------------------------------------------------ campaign id

    function test_CampaignId_DiffersAcrossDeploymentsWithTheSameSalt() public {
        OrcClaim other = _deploy(VKEY, NOTARY, SALT, REPO, THRESHOLD, MAX_AGE);
        assertTrue(address(other) != address(orc));
        assertEq(other.campaignSalt(), orc.campaignSalt());
        assertTrue(other.campaignId() != orc.campaignId());
        assertEq(other.campaignId(), _campaignId(CHAIN_ID, address(other), SALT));
    }

    function test_CampaignId_DiffersAcrossChains() public {
        // Same deployer nonce on two chains gives the same address: only chainid differs.
        uint256 snap = vm.snapshotState();
        OrcClaim a = _deploy(VKEY, NOTARY, SALT, REPO, THRESHOLD, MAX_AGE);
        bytes32 idA = a.campaignId();
        vm.revertToState(snap);
        vm.chainId(8453);
        OrcClaim b = _deploy(VKEY, NOTARY, SALT, REPO, THRESHOLD, MAX_AGE);
        assertEq(address(a), address(b));
        assertTrue(b.campaignId() != idA);
        assertEq(b.campaignId(), _campaignId(8453, address(b), SALT));
    }

    function test_RevertWhen_ClaimForAnotherDeployment() public {
        // A claim valid for deployment A (same config, same salt) ...
        PublicValues memory pv = _pv();
        OrcClaim b = _deploy(VKEY, NOTARY, SALT, REPO, THRESHOLD, MAX_AGE);
        // ... is rejected by deployment B, whose campaignId (and nullifier scope) differs.
        vm.expectRevert(
            abi.encodeWithSelector(OrcClaim.WrongCampaign.selector, b.campaignId(), campaign)
        );
        vm.prank(alice);
        b.claim(abi.encode(pv), "");
        assertFalse(b.nullifierUsed(pv.nullifier));

        // A still accepts it.
        _claimAs(alice, pv);
        assertTrue(orc.nullifierUsed(pv.nullifier));
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
            pv.nullifier = _nullifier(_u64(i), campaign);
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
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.WrongCampaign.selector, campaign, other));
        _claimAs(alice, pv);
    }

    function test_RevertWhen_SaltInsteadOfCampaignId() public {
        // A prover that put the raw salt in its input (not the derived campaignId) is refused.
        PublicValues memory pv = _pv();
        pv.campaignId = SALT;
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.WrongCampaign.selector, campaign, SALT));
        _claimAs(alice, pv);
    }

    function test_RevertWhen_WrongSnapshot() public {
        uint64[2] memory others = [SNAPSHOT - 1, SNAPSHOT + 1];
        for (uint256 i = 0; i < others.length; i++) {
            PublicValues memory pv = _pv();
            pv.snapshot = others[i];
            vm.expectRevert(
                abi.encodeWithSelector(OrcClaim.WrongSnapshot.selector, SNAPSHOT, others[i])
            );
            _claimAs(alice, pv);
        }
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
        assertEq(good.length, 288);
        // 256 is the pre-snapshot 8-word encoding.
        uint256[5] memory lengths = [uint256(0), 256, 287, 289, 320];
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

        // And for the snapshot word (word 5).
        bad = abi.encode(_pv());
        bad[5 * 32 + 23] = 0x01;
        vm.expectRevert(bytes(""));
        vm.prank(alice);
        orc.claim(bad, "");
    }

    function test_RevertWhen_ConstructorZeroConfig() public {
        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "verifier"));
        new OrcClaim(
            ISP1Verifier(address(0)), VKEY, NOTARY, SALT, REPO, THRESHOLD, SNAPSHOT, MAX_AGE
        );

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "programVKey"));
        _deploy(bytes32(0), NOTARY, SALT, REPO, THRESHOLD, MAX_AGE);

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "notaryKeyHash"));
        _deploy(VKEY, bytes32(0), SALT, REPO, THRESHOLD, MAX_AGE);

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "campaignSalt"));
        _deploy(VKEY, NOTARY, bytes32(0), REPO, THRESHOLD, MAX_AGE);

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "maxAge"));
        _deploy(VKEY, NOTARY, SALT, REPO, THRESHOLD, 0);
    }

    function test_RevertWhen_ConstructorSnapshotZeroOrInFuture() public {
        uint64[2] memory bad = [uint64(0), NOW + 1];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(abi.encodeWithSelector(OrcClaim.InvalidConfig.selector, "snapshot"));
            new OrcClaim(
                ISP1Verifier(address(mockVerifier)), VKEY, NOTARY, SALT, REPO, THRESHOLD, bad[i], 1
            );
        }
        // The deployment block's own timestamp is fine.
        OrcClaim atNow = new OrcClaim(
            ISP1Verifier(address(mockVerifier)), VKEY, NOTARY, SALT, REPO, THRESHOLD, NOW, MAX_AGE
        );
        assertEq(atNow.snapshot(), NOW);
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
    /// `public_values_encode_to_nine_static_words` test, generated with Foundry 1.8.7:
    ///   C=0x1111111111111111111111111111111111111111111111111111111111111111
    ///   NK=$(cast keccak k)
    ///   NUL=$(cast keccak $(cast abi-encode "f(uint256,bytes32)" 1 $C))
    ///   cast abi-encode \
    ///     "f((address,uint64,bytes32,uint64,uint64,uint64,bytes32,uint64,bytes32))" \
    ///     "(0x00000000000000000000000000000000deadbeef,84532,$C,7,3,1690000000,$NK,1700000000,$NUL)"
    /// The flat form `cast abi-encode "f(address,uint64,...,bytes32)" ...` prints the same
    /// 288 bytes: a static struct has no offset word.
    bytes internal constant CAST_ENCODED = hex"00000000000000000000000000000000000000000000000000000000deadbeef"
        hex"0000000000000000000000000000000000000000000000000000000000014a34"
        hex"1111111111111111111111111111111111111111111111111111111111111111"
        hex"0000000000000000000000000000000000000000000000000000000000000007"
        hex"0000000000000000000000000000000000000000000000000000000000000003"
        hex"0000000000000000000000000000000000000000000000000000000064bb5a80"
        hex"f3d0adcb6a1c70832365e9da0a6b2f5199422f6a53c67cfad171114e3442aa0f"
        hex"000000000000000000000000000000000000000000000000000000006553f100"
        hex"8a1a59a536742613f251075415cb3bcfd95758a71bd84e57840cbf9f016f9cf9";
    bytes32 internal constant CAST_NOTARY_KEY_HASH =
        0xf3d0adcb6a1c70832365e9da0a6b2f5199422f6a53c67cfad171114e3442aa0f;
    bytes32 internal constant CAST_NULLIFIER =
        0x8a1a59a536742613f251075415cb3bcfd95758a71bd84e57840cbf9f016f9cf9;

    function test_AbiEncoding_MatchesCastAndOrcCore() public pure {
        bytes32 c = 0x1111111111111111111111111111111111111111111111111111111111111111;
        PublicValues memory pv = PublicValues({
            ethAddress: 0x00000000000000000000000000000000DeaDBeef,
            chainId: 84532,
            campaignId: c,
            repoDatabaseId: 7,
            threshold: 3,
            snapshot: 1_690_000_000,
            notaryKeyHash: keccak256("k"),
            sessionTime: 1_700_000_000,
            nullifier: _nullifier(1, c)
        });

        // Hash preimages agree with cast (and with orc-core's hand-built preimages).
        assertEq(pv.notaryKeyHash, CAST_NOTARY_KEY_HASH);
        assertEq(pv.nullifier, CAST_NULLIFIER);

        bytes memory encoded = abi.encode(pv);
        assertEq(encoded.length, 288);
        assertEq(encoded, CAST_ENCODED);
        // Struct encoding == flat 9-tuple encoding (what alloy's `abi_encode()` produces).
        assertEq(
            encoded,
            abi.encode(
                pv.ethAddress,
                pv.chainId,
                pv.campaignId,
                pv.repoDatabaseId,
                pv.threshold,
                pv.snapshot,
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
    /// The fixture's campaignId must follow the fixture convention (FIXTURE_ORC, FIXTURE_SALT):
    /// OrcClaim is deployed at exactly that address so it derives the same campaignId.
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

        assertEq(publicValues.length, 288, "publicValues must be 9 static words");
        assertEq(proof.length, 0, "mock fixture must carry an empty proof");
        PublicValues memory pv = abi.decode(publicValues, (PublicValues));

        // Rebuild the chain context the guest committed to.
        vm.chainId(pv.chainId);
        vm.warp(uint256(pv.sessionTime) + 60);
        OrcClaim fixtureOrc = _deployFor(vkey, pv);
        assertEq(
            fixtureOrc.campaignId(),
            pv.campaignId,
            "fixture campaignId must be keccak256(abi.encode(chainId, FIXTURE_ORC, FIXTURE_SALT))"
        );
        assertEq(fixtureOrc.snapshot(), pv.snapshot);

        vm.expectEmit(true, true, true, true, address(fixtureOrc));
        emit Claimed(pv.ethAddress, pv.nullifier, pv.campaignId, pv.sessionTime);
        vm.prank(pv.ethAddress);
        fixtureOrc.claim(publicValues, proof);
        assertTrue(fixtureOrc.nullifierUsed(pv.nullifier));

        vm.expectRevert(abi.encodeWithSelector(OrcClaim.NullifierUsed.selector, pv.nullifier));
        vm.prank(pv.ethAddress);
        fixtureOrc.claim(publicValues, proof);
    }

    /// Deploys OrcClaim for the fixture at FIXTURE_ORC (what forge-std's deployCodeTo does: run
    /// the init code at that address, then install the runtime code it returns), so its
    /// constructor sees address(this) == FIXTURE_ORC.
    function _deployFor(bytes32 vkey, PublicValues memory pv) internal returns (OrcClaim) {
        bytes memory args = abi.encode(
            address(mockVerifier),
            vkey,
            pv.notaryKeyHash,
            FIXTURE_SALT,
            pv.repoDatabaseId,
            pv.threshold,
            pv.snapshot,
            MAX_AGE
        );
        vm.etch(FIXTURE_ORC, abi.encodePacked(type(OrcClaim).creationCode, args));
        (bool ok, bytes memory runtime) = FIXTURE_ORC.call("");
        require(ok, "OrcClaim constructor reverted for the fixture");
        vm.etch(FIXTURE_ORC, runtime);
        return OrcClaim(FIXTURE_ORC);
    }

    /// The fixture convention, pinned: harness fixtures (chain 84532) carry this campaignId.
    function test_FixtureConvention_CampaignId() public pure {
        assertEq(
            _campaignId(84532, FIXTURE_ORC, FIXTURE_SALT),
            0x3276d4db55236b1233bcbdbb1e39216717f562a0841d80ca8c24a53204668aab
        );
        assertEq(FIXTURE_SALT, 0xad9658d77497a2be2118b3b2bb1a1ab3718565faa76cc253ce3f84c0b0e0d5fc);
    }
}
