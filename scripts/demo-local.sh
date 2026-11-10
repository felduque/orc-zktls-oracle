#!/usr/bin/env bash
# One-command local end-to-end rehearsal of milestone M5 on anvil.
#
#   scripts/demo-local.sh            # run from the host, at any cwd
#
# It starts ONE dev container (docker compose run) and runs everything inside it, so anvil,
# the notary and the prover share localhost:
#   1. preconditions + build (orc, orc-notary, orc-script)
#   2. anvil (chain 31337) + orc-notary in the background
#   3. deploy SP1MockVerifier + OrcClaim through contracts/script/Deploy.s.sol
#      (programVKey from `orc-script vkey`, notaryKeyHash from the running notary)
#   4. `orc prove` against the REAL api.github.com (MPC-TLS with the local notary)
#   5. `orc-script fixture --mock --production` (production guest, empty mock proof)
#   6. anvil #1 claims  -> must revert WrongSender
#   7. anvil #0 claims  -> must succeed: Claimed event, nullifierUsed == true
#   8. anvil #0 replays -> must revert NullifierUsed
#
# Needs GITHUB_TOKEN and ORC_NOTARY_KEY in .env (README, "A real GitHub run"). Each run makes
# two GitHub GraphQL requests (the preflight and the notarized query). Outputs go to the
# gitignored out/demo/: the presentation there holds your GitHub data, don't publish it.
#
# Defaults prove felduque/orc-zktls-oracle. With your own token, point it at a repository
# where you have commits:
#   ORC_DEMO_OWNER=you ORC_DEMO_NAME=repo ORC_DEMO_REPO_ID=<repo databaseId> \
#   ORC_DEMO_THRESHOLD=1 scripts/demo-local.sh
#
# Secrets: never `set -x` in this file. The token and the notary key reach the processes
# through the environment only (compose passes them from .env); nothing here prints them.

set -euo pipefail

CONTAINER_NAME=orc-demo-local

# ---------------------------------------------------------------------------------------------
# Host side: preconditions, then one `docker compose run` that re-enters this script.
# ---------------------------------------------------------------------------------------------
host_main() {
    local repo_root
    repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
    cd "$repo_root"

    command -v docker >/dev/null || { echo "error: docker not found" >&2; exit 1; }
    docker compose version >/dev/null 2>&1 || { echo "error: docker compose v2 not found" >&2; exit 1; }

    # Presence checks only (grep -c prints a count, never the value).
    local missing=()
    for var in GITHUB_TOKEN ORC_NOTARY_KEY; do
        local n=0
        [[ -f .env ]] && n=$(grep -cE "^${var}=.+" .env || true)
        if [[ "$n" -lt 1 && -z "${!var:-}" ]]; then
            missing+=("$var")
        fi
    done
    if ((${#missing[@]})); then
        cat >&2 <<EOF
error: missing ${missing[*]} in .env.
  GITHUB_TOKEN    a fine-grained PAT (public repositories, read-only). Add the line
                  GITHUB_TOKEN=github_pat_... to .env with an editor, never on a command line.
  ORC_NOTARY_KEY  docker compose run --rm -T dev bash -c 'echo "ORC_NOTARY_KEY=\$(openssl rand -hex 32)"' >> .env
See README.md, "A real GitHub run (requires a token)".
EOF
        exit 1
    fi

    # A container left over from an interrupted run would hold the name.
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    trap 'docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true' EXIT
    trap 'exit 130' INT TERM

    echo "orc local demo: starting dev container '$CONTAINER_NAME' (anvil + notary + prover inside)"
    local rc=0
    docker compose run --rm -T --name "$CONTAINER_NAME" \
        -e ORC_DEMO_OWNER -e ORC_DEMO_NAME -e ORC_DEMO_REPO_ID -e ORC_DEMO_THRESHOLD \
        dev bash -c 'bash scripts/demo-local.sh --in-container' || rc=$?
    exit "$rc"
}

# ---------------------------------------------------------------------------------------------
# Container side.
# ---------------------------------------------------------------------------------------------

# anvil's PUBLIC development mnemonic. Its keys are known to everyone: local chains only.
ANVIL_MNEMONIC="test test test test test test test test test test test junk"
RPC=http://127.0.0.1:8545
NOTARY_ADDR=127.0.0.1:7047
OUT=out/demo
# A fixed gas limit skips eth_estimateGas, so a failing claim is MINED and reverts on-chain
# (receipt status 0) instead of being refused by the RPC before it is sent.
NEG_GAS_LIMIT=1000000

STEP_NAMES=(
    "preconditions + build"
    "anvil (31337) + orc-notary"
    "deploy SP1MockVerifier + OrcClaim"
    "orc prove (real api.github.com)"
    "orc-script fixture --mock --production"
    "anvil #1 claims -> WrongSender"
    "anvil #0 claims -> Claimed"
    "anvil #0 replays -> NullifierUsed"
)
STEP_RESULT=()
STEP_TIME=()
STEP_NOTE=()
CUR=-1
STEP_T0=0
FAILED=0
PIDS=()
T_START=$EPOCHREALTIME

elapsed() { awk -v a="$1" -v b="$EPOCHREALTIME" 'BEGIN { printf "%.1f", b - a }'; }

step() {
    CUR=$1
    STEP_T0=$EPOCHREALTIME
    printf '\n=== [%d/%d] %s ===\n' "$((CUR + 1))" "${#STEP_NAMES[@]}" "${STEP_NAMES[$CUR]}"
}

pass() {
    STEP_RESULT[CUR]=PASS
    STEP_TIME[CUR]=$(elapsed "$STEP_T0")
    STEP_NOTE[CUR]=${1:-}
    echo "--> PASS (${STEP_TIME[CUR]} s)${1:+: $1}"
}

fail() {
    STEP_RESULT[CUR]=FAIL
    STEP_TIME[CUR]=$(elapsed "$STEP_T0")
    STEP_NOTE[CUR]=$1
    FAILED=1
    echo "--> FAIL (${STEP_TIME[CUR]} s): $1" >&2
}

# A failed prerequisite makes every later step meaningless: stop (the EXIT trap summarizes).
die() {
    fail "$1"
    exit 1
}

show_log_tail() {
    echo "----- last lines of $1 -----" >&2
    tail -n "${2:-25}" "$1" >&2 || true
}

summary() {
    local rc=$1 i res
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    # A command that failed under `set -e` mid-step leaves that step unrecorded.
    if ((CUR >= 0)) && [[ -z "${STEP_RESULT[CUR]:-}" ]]; then
        fail "unexpected error (exit $rc), see the output above"
    fi

    printf '\n================ orc local demo: summary ================\n'
    for i in "${!STEP_NAMES[@]}"; do
        res=${STEP_RESULT[i]:-SKIP}
        printf ' %d  %-40s %-4s %6s s  %s\n' "$((i + 1))" "${STEP_NAMES[i]}" "$res" \
            "${STEP_TIME[i]:--}" "${STEP_NOTE[i]:-}"
    done
    if ((FAILED == 0 && ${#STEP_RESULT[@]} == ${#STEP_NAMES[@]})); then
        printf 'RESULT: PASS (%d/%d) in %s s\n' "${#STEP_NAMES[@]}" "${#STEP_NAMES[@]}" "$(elapsed "$T_START")"
        exit 0
    fi
    printf 'RESULT: FAIL in %s s (logs in %s/)\n' "$(elapsed "$T_START")" "$OUT"
    exit 1
}

# Top-level field of a JSON file ("" when absent).
json_get() {
    python3 -I -c 'import json, sys
v = json.load(open(sys.argv[1])).get(sys.argv[2])
print("" if v is None else v)' "$1" "$2"
}

# The revert data of a mined, reverted claim: anvil puts it in the receipt's revertReason; if
# not, replay the call from the same sender and read it from the error.
revert_data() {
    local receipt=$1 from=$2 data
    data=$(python3 -I -c 'import json, re, sys
m = re.search(r"data: \"(0x[0-9a-fA-F]*)\"", json.load(open(sys.argv[1])).get("revertReason") or "")
print(m.group(1) if m else "")' "$receipt")
    if [[ -z "$data" ]]; then
        data=$(cast call "$ORC" 'claim(bytes,bytes)' "$PV" "$PROOF" --from "$from" --rpc-url "$RPC" 2>&1 \
            | grep -oE 'data: "0x[0-9a-fA-F]*"' | head -n1 | grep -oE '0x[0-9a-fA-F]*' || true)
    fi
    echo "$data"
}

# Sends claim(PV, PROOF) as `pk` and requires an on-chain revert with custom error `sig`.
expect_revert() {
    local pk=$1 sig=$2 receipt=$3 from rc=0 status data want
    from=$(cast wallet address --private-key "$pk")
    cast send "$ORC" 'claim(bytes,bytes)' "$PV" "$PROOF" --private-key "$pk" --rpc-url "$RPC" \
        --gas-limit "$NEG_GAS_LIMIT" --json >"$receipt" 2>"$receipt.err" || rc=$?
    status=$(json_get "$receipt" status 2>/dev/null || true)
    if [[ -z "$status" ]]; then
        cat "$receipt.err" >&2
        fail "cast send failed before mining (exit $rc)"
        return
    fi
    echo "tx $(json_get "$receipt" transactionHash) from $from"
    echo "block $(cast to-dec "$(json_get "$receipt" blockNumber)"), status $status, gasUsed $(cast to-dec "$(json_get "$receipt" gasUsed)")"
    if [[ "$status" != "0x0" ]]; then
        fail "the claim was ACCEPTED (status $status), expected a revert with $sig"
        return
    fi
    data=$(revert_data "$receipt" "$from")
    want=$(cast sig "$sig")
    if [[ "${data:0:10}" != "$want" ]]; then
        fail "reverted with ${data:-<no data>}, expected $sig ($want)"
        return
    fi
    echo "revert data $data"
    echo "decoded     ${sig%%(*}($(cast decode-error --sig "$sig" "$data" | paste -sd, - | sed 's/,/, /g'))"
    pass "reverted on-chain with ${sig%%(*}"
}

container_main() {
    cd /workspace
    trap 'summary $?' EXIT
    trap 'exit 130' INT TERM

    local owner=${ORC_DEMO_OWNER:-felduque}
    local name=${ORC_DEMO_NAME:-orc-zktls-oracle}
    local repo_id=${ORC_DEMO_REPO_ID:-1452696697}
    local threshold=${ORC_DEMO_THRESHOLD:-5}
    local max_age=3600
    local bin=${CARGO_TARGET_DIR:-/cargo-target}/release

    # ---------------------------------------------------------------- 1
    step 0
    [[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN is empty inside the container (.env not passed?)"
    [[ -n "${ORC_NOTARY_KEY:-}" ]] || die "ORC_NOTARY_KEY is empty inside the container"
    for tool in cargo anvil cast forge python3; do
        command -v "$tool" >/dev/null || die "$tool not found in the dev image"
    done
    mkdir -p "$OUT"
    rm -rf "${OUT:?}"/*
    echo "outputs: $OUT/ (gitignored)"
    echo "building orc + orc-notary (root workspace) ..."
    cargo build --release --locked -p orc-notary -p orc-prover >"$OUT/build.log" 2>&1 \
        || { show_log_tail "$OUT/build.log"; die "cargo build (root workspace) failed"; }
    echo "building orc-script (SP1 host + both guest ELFs) ..."
    (cd crates/orc-script && cargo build --release --locked) >>"$OUT/build.log" 2>&1 \
        || { show_log_tail "$OUT/build.log"; die "cargo build (orc-script) failed"; }
    pass "tokens present, binaries built"

    # ---------------------------------------------------------------- 2
    step 1
    PK0=$(cast wallet private-key "$ANVIL_MNEMONIC" 0)
    PK1=$(cast wallet private-key "$ANVIL_MNEMONIC" 1)
    A0=$(cast wallet address --private-key "$PK0")
    A1=$(cast wallet address --private-key "$PK1")
    anvil --chain-id 31337 --host 127.0.0.1 --port 8545 >"$OUT/anvil.log" 2>&1 &
    PIDS+=($!)
    "$bin/orc-notary" --listen "$NOTARY_ADDR" >"$OUT/notary.log" 2>&1 &
    PIDS+=($!)
    local i chain_id=""
    for i in $(seq 100); do
        chain_id=$(cast chain-id --rpc-url "$RPC" 2>/dev/null) && break
        sleep 0.1
    done
    [[ "$chain_id" == 31337 ]] || { show_log_tail "$OUT/anvil.log"; die "anvil did not come up on $RPC"; }
    for i in $(seq 100); do
        grep -q '^listening on' "$OUT/notary.log" && break
        kill -0 "${PIDS[1]}" 2>/dev/null || break
        sleep 0.1
    done
    grep -q '^listening on' "$OUT/notary.log" || { show_log_tail "$OUT/notary.log"; die "orc-notary did not start"; }
    NOTARY_KEY_HASH=$(sed -n 's/^notaryKeyHash: \(0x[0-9a-f]\{64\}\)$/\1/p' "$OUT/notary.log")
    [[ -n "$NOTARY_KEY_HASH" ]] || die "could not read notaryKeyHash from the notary output"
    echo "anvil       $RPC, chain id $chain_id"
    echo "claimant    anvil #0 $A0"
    echo "attacker    anvil #1 $A1"
    echo "orc-notary  $NOTARY_ADDR, $(grep '^notary public key' "$OUT/notary.log")"
    echo "            notaryKeyHash $NOTARY_KEY_HASH"
    pass "anvil and notary up"

    # ---------------------------------------------------------------- 3
    step 2
    "$bin/orc-script" vkey >"$OUT/vkey.log" 2>&1 \
        || { show_log_tail "$OUT/vkey.log"; die "orc-script vkey failed"; }
    PROGRAM_VKEY=$(grep -oE '^0x[0-9a-f]{64}$' "$OUT/vkey.log" | tail -n1 || true)
    [[ -n "$PROGRAM_VKEY" ]] || { show_log_tail "$OUT/vkey.log"; die "orc-script vkey printed no vkey"; }
    CAMPAIGN_ID=$(cast keccak "orc-poc-github-v1")
    echo "programVKey    $PROGRAM_VKEY (orc-script vkey, production guest)"
    echo "campaignId     $CAMPAIGN_ID (keccak256(\"orc-poc-github-v1\"))"
    (cd contracts && forge create lib/sp1-contracts/contracts/src/SP1MockVerifier.sol:SP1MockVerifier \
        --rpc-url "$RPC" --private-key "$PK0" --broadcast) >"$OUT/deploy.log" 2>&1 \
        || { show_log_tail "$OUT/deploy.log"; die "forge create SP1MockVerifier failed"; }
    MOCK=$(sed -n 's/^Deployed to: \(0x[0-9a-fA-F]\{40\}\)$/\1/p' "$OUT/deploy.log")
    [[ -n "$MOCK" ]] || die "could not read the SP1MockVerifier address"
    echo "SP1MockVerifier $MOCK"
    # FOUNDRY_BROADCAST keeps the demo's broadcast receipts under out/demo/ (relative to contracts/).
    (cd contracts && FOUNDRY_BROADCAST="../$OUT/broadcast" SP1_VERIFIER="$MOCK" \
        PROGRAM_VKEY="$PROGRAM_VKEY" NOTARY_KEY_HASH="$NOTARY_KEY_HASH" CAMPAIGN_ID="$CAMPAIGN_ID" \
        REPO_DATABASE_ID="$repo_id" THRESHOLD="$threshold" MAX_AGE="$max_age" \
        forge script script/Deploy.s.sol --rpc-url "$RPC" --private-key "$PK0" --broadcast) \
        >>"$OUT/deploy.log" 2>&1 \
        || { show_log_tail "$OUT/deploy.log" 40; die "forge script Deploy.s.sol failed"; }
    ORC=$(awk '$1 == "OrcClaim" && $2 ~ /^0x[0-9a-fA-F]{40}$/ { print $2 }' "$OUT/deploy.log" | tail -n1)
    [[ -n "$ORC" ]] || { show_log_tail "$OUT/deploy.log" 40; die "could not read the OrcClaim address"; }
    echo "OrcClaim        $ORC (Deploy.s.sol, broadcast by anvil #0)"
    # Read the configuration back from the chain.
    local got bad=""
    check_cfg() {
        got=$(cast call "$ORC" "$1" --rpc-url "$RPC" | awk '{ print $1 }')
        printf '  %-26s %s\n' "$1" "$got"
        [[ "${got,,}" == "${2,,}" ]] || bad+=" $1"
    }
    check_cfg 'verifier()(address)' "$MOCK"
    check_cfg 'programVKey()(bytes32)' "$PROGRAM_VKEY"
    check_cfg 'notaryKeyHash()(bytes32)' "$NOTARY_KEY_HASH"
    check_cfg 'campaignId()(bytes32)' "$CAMPAIGN_ID"
    check_cfg 'repoDatabaseId()(uint64)' "$repo_id"
    check_cfg 'threshold()(uint64)' "$threshold"
    check_cfg 'maxAge()(uint64)' "$max_age"
    [[ -z "$bad" ]] || die "on-chain config mismatch:$bad"
    pass "OrcClaim $ORC, config read back OK"

    # ---------------------------------------------------------------- 4
    step 3
    echo "orc prove --owner $owner --name $name --threshold $threshold --eth-address $A0 --chain-id 31337"
    echo "          --campaign-id $CAMPAIGN_ID --notary $NOTARY_ADDR --out-dir $OUT"
    # The full output (with tlsn's per-session "record layer is not ready" warnings) is in prove.log.
    "$bin/orc" prove --owner "$owner" --name "$name" --threshold "$threshold" \
        --eth-address "$A0" --chain-id 31337 --campaign-id "$CAMPAIGN_ID" \
        --notary "$NOTARY_ADDR" --out-dir "$OUT" 2>&1 | tee "$OUT/prove.log" \
        | { grep -v 'record layer is not ready, skipping flush' || true; } \
        || { show_log_tail "$OUT/notary.log"; die "orc prove failed"; }
    # The notarized response reveals GitHub's rate-limit headers (each run makes two GraphQL
    # requests, the preflight and the notarized query, at one point each).
    local rl
    rl=$(grep -aoiE 'x-ratelimit-(remaining|limit|used): [0-9]+' "$OUT/presentation.bin" \
        | awk -F': ' '{ printf "%s%s=%s", sep, tolower(substr($1, 13)), $2; sep = ", " }' || true)
    [[ -z "$rl" ]] || echo "GitHub GraphQL budget (from the notarized response headers): $rl"
    pass "presentation $(stat -c %s "$OUT/presentation.bin") B, native self-check OK"

    # ---------------------------------------------------------------- 5
    step 4
    "$bin/orc-script" fixture --mock --production \
        --presentation "$OUT/presentation.bin" --input "$OUT/guest-input.json" \
        --out "$OUT/orc-demo-mock.json" >"$OUT/fixture.log" 2>&1 \
        || { show_log_tail "$OUT/fixture.log" 40; die "orc-script fixture failed"; }
    grep -E '^\[(claim|native)\]' "$OUT/fixture.log" || true
    PV=$(json_get "$OUT/orc-demo-mock.json" publicValues)
    PROOF=$(json_get "$OUT/orc-demo-mock.json" proof)
    local fixture_vkey
    fixture_vkey=$(json_get "$OUT/orc-demo-mock.json" programVKey)
    [[ "$fixture_vkey" == "$PROGRAM_VKEY" ]] || die "fixture programVKey $fixture_vkey != deployed $PROGRAM_VKEY"
    [[ "$PROOF" == "0x" ]] || die "mock proof is not empty: $PROOF"
    local -a pv
    mapfile -t pv < <(cast decode-abi 'f()(address,uint64,bytes32,uint64,uint64,bytes32,uint64,bytes32)' "$PV" | awk '{ print $1 }')
    ((${#pv[@]} == 8)) || die "could not decode publicValues"
    NULLIFIER=${pv[7]}
    printf '  %-15s %s\n' ethAddress "${pv[0]}" chainId "${pv[1]}" campaignId "${pv[2]}" \
        repoDatabaseId "${pv[3]}" threshold "${pv[4]}" notaryKeyHash "${pv[5]}" \
        sessionTime "${pv[6]} ($(date -u -d "@${pv[6]}" '+%F %T UTC'))" nullifier "${pv[7]}"
    echo "  proof           $PROOF (empty: SP1MockVerifier only)"
    [[ "${pv[0],,}" == "${A0,,}" && "${pv[1]}" == 31337 && "${pv[2]}" == "$CAMPAIGN_ID" \
        && "${pv[3]}" == "$repo_id" && "${pv[5]}" == "$NOTARY_KEY_HASH" ]] \
        || die "publicValues do not match the deployment"
    pass "production guest accepted, publicValues match the deployment"

    # ---------------------------------------------------------------- 6
    step 5
    expect_revert "$PK1" 'WrongSender(address,address)' "$OUT/receipt-attacker.json"
    local used
    used=$(cast call "$ORC" 'nullifierUsed(bytes32)(bool)' "$NULLIFIER" --rpc-url "$RPC")
    echo "nullifierUsed($NULLIFIER) = $used"
    if [[ "$used" != false && "${STEP_RESULT[5]:-}" == PASS ]]; then
        fail "the nullifier is burnt after a reverted claim"
    fi

    # ---------------------------------------------------------------- 7
    step 6
    local rc=0 status
    cast send "$ORC" 'claim(bytes,bytes)' "$PV" "$PROOF" --private-key "$PK0" --rpc-url "$RPC" \
        --json >"$OUT/receipt-claim.json" 2>"$OUT/receipt-claim.err" || rc=$?
    status=$(json_get "$OUT/receipt-claim.json" status 2>/dev/null || true)
    if [[ "$status" != 0x1 ]]; then
        cat "$OUT/receipt-claim.err" >&2
        fail "claim by anvil #0 did not succeed (exit $rc, status ${status:-none})"
    else
        echo "tx $(json_get "$OUT/receipt-claim.json" transactionHash) from $A0"
        echo "block $(cast to-dec "$(json_get "$OUT/receipt-claim.json" blockNumber)"), status $status, gasUsed $(cast to-dec "$(json_get "$OUT/receipt-claim.json" gasUsed)")"
        local event
        event=$(python3 -I -c 'import json, sys
r = json.load(open(sys.argv[1]))
topic0, orc = sys.argv[2].lower(), sys.argv[3].lower()
logs = [l for l in r["logs"] if l["address"].lower() == orc and l["topics"][0].lower() == topic0]
if len(logs) != 1:
    sys.exit("expected exactly one Claimed log, got %d" % len(logs))
t = logs[0]["topics"]
print("0x" + t[1][-40:], t[2], t[3], int(logs[0]["data"], 16))' \
            "$OUT/receipt-claim.json" "$(cast keccak 'Claimed(address,bytes32,bytes32,uint64)')" "$ORC") \
            || event=""
        local ev_account ev_nullifier ev_campaign ev_time
        read -r ev_account ev_nullifier ev_campaign ev_time <<<"$event"
        echo "Claimed(account=${ev_account:-?}, nullifier=${ev_nullifier:-?}, campaignId=${ev_campaign:-?}, sessionTime=${ev_time:-?})"
        used=$(cast call "$ORC" 'nullifierUsed(bytes32)(bool)' "$NULLIFIER" --rpc-url "$RPC")
        echo "nullifierUsed($NULLIFIER) = $used"
        if [[ -z "$event" ]]; then
            fail "no Claimed event in the receipt"
        elif [[ "${ev_account,,}" != "${A0,,}" || "$ev_nullifier" != "$NULLIFIER" \
            || "$ev_campaign" != "$CAMPAIGN_ID" || "$ev_time" != "${pv[6]}" ]]; then
            fail "Claimed event fields do not match the publicValues"
        elif [[ "$used" != true ]]; then
            fail "nullifierUsed is $used after the claim"
        else
            pass "Claimed emitted, nullifier burnt"
        fi
    fi

    # ---------------------------------------------------------------- 8
    step 7
    expect_revert "$PK0" 'NullifierUsed(bytes32)' "$OUT/receipt-replay.json"
}

if [[ "${1:-}" == "--in-container" ]]; then
    container_main
else
    host_main "$@"
fi
