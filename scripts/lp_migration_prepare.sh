#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
LP migration helper (minimal MVP): prepare a fresh-deposit LP cell spec.

Usage:
  bash scripts/lp_migration_prepare.sh \
    --pool-id 0x<64hex> \
    --owner-lock-hash 0x<64hex> \
    --operator-lock-hash 0x<64hex> \
    [--available-ckb 20000000000] \
    [--reserved-ckb 0] \
    [--fee-rate-bps 30] \
    [--policy-flags 0] \
    [--policy-version 1] \
    [--max-trading-volume 0] \
    [--nonce 0] \
    [--network dev|release] \
    [--out migrations_lp/lp_cell_spec.json] \
    [--monitoring-checklist-out migrations_lp/lp_monitoring_checklist.md]

Output:
  - Writes a JSON spec file for LP cell initialization from fresh deposits.
  - Prints a minimal deployment + transaction command skeleton.

Notes:
  - This helper intentionally avoids legacy migration paths.
  - Use one LP cell per funding transaction in MVP.
EOF
}

POOL_ID=""
OWNER_LOCK_HASH=""
OPERATOR_LOCK_HASH=""
AVAILABLE_CKB="20000000000"
RESERVED_CKB="0"
FEE_RATE_BPS="30"
POLICY_FLAGS="0"
POLICY_VERSION="1"
MAX_TRADING_VOLUME="0"
NONCE="0"
NETWORK="dev"
OUT_FILE="migrations_lp/lp_cell_spec.json"
MONITORING_CHECKLIST_OUT="migrations_lp/lp_monitoring_checklist.md"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pool-id)
      POOL_ID="$2"; shift 2 ;;
    --owner-lock-hash)
      OWNER_LOCK_HASH="$2"; shift 2 ;;
    --operator-lock-hash)
      OPERATOR_LOCK_HASH="$2"; shift 2 ;;
    --available-ckb)
      AVAILABLE_CKB="$2"; shift 2 ;;
    --reserved-ckb)
      RESERVED_CKB="$2"; shift 2 ;;
    --fee-rate-bps)
      FEE_RATE_BPS="$2"; shift 2 ;;
    --policy-flags)
      POLICY_FLAGS="$2"; shift 2 ;;
    --policy-version)
      POLICY_VERSION="$2"; shift 2 ;;
    --max-trading-volume)
      MAX_TRADING_VOLUME="$2"; shift 2 ;;
    --nonce)
      NONCE="$2"; shift 2 ;;
    --network)
      NETWORK="$2"; shift 2 ;;
    --out)
      OUT_FILE="$2"; shift 2 ;;
    --monitoring-checklist-out)
      MONITORING_CHECKLIST_OUT="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1 ;;
  esac
done

require_hex32() {
  local v="$1"
  local n="$2"
  local t="${v#0x}"
  if [[ ! "$t" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "$n must be 32-byte hex (0x + 64 hex chars)" >&2
    exit 1
  fi
}

require_u64() {
  local v="$1"
  local n="$2"
  if [[ ! "$v" =~ ^[0-9]+$ ]]; then
    echo "$n must be an unsigned integer" >&2
    exit 1
  fi
}

if [[ -z "$POOL_ID" || -z "$OWNER_LOCK_HASH" || -z "$OPERATOR_LOCK_HASH" ]]; then
  echo "Missing required args: --pool-id --owner-lock-hash --operator-lock-hash" >&2
  usage
  exit 1
fi

if [[ "$NETWORK" != "dev" && "$NETWORK" != "release" ]]; then
  echo "--network must be one of: dev, release" >&2
  exit 1
fi

require_hex32 "$POOL_ID" "pool-id"
require_hex32 "$OWNER_LOCK_HASH" "owner-lock-hash"
require_hex32 "$OPERATOR_LOCK_HASH" "operator-lock-hash"
require_u64 "$AVAILABLE_CKB" "available-ckb"
require_u64 "$RESERVED_CKB" "reserved-ckb"
require_u64 "$FEE_RATE_BPS" "fee-rate-bps"
require_u64 "$POLICY_FLAGS" "policy-flags"
require_u64 "$POLICY_VERSION" "policy-version"
require_u64 "$MAX_TRADING_VOLUME" "max-trading-volume"
require_u64 "$NONCE" "nonce"

if (( RESERVED_CKB > AVAILABLE_CKB )); then
  echo "reserved-ckb must be <= available-ckb for fresh deposit flow" >&2
  exit 1
fi

if (( FEE_RATE_BPS == 0 )); then
  echo "fee-rate-bps must be > 0 for LP policy" >&2
  exit 1
fi

if (( POLICY_VERSION == 0 )); then
  echo "policy-version must be > 0" >&2
  exit 1
fi

if (( (POLICY_FLAGS & ~7) != 0 )); then
  echo "policy-flags contains unsupported bits; allowed mask is 0x7" >&2
  exit 1
fi

OUT_DIR="$(dirname "$OUT_FILE")"
mkdir -p "$OUT_DIR"

DEPLOY_CFG="deployment/${NETWORK}/deployment_lp.toml"
DEPLOY_INFO="${OUT_DIR}/lp_deploy_info_${NETWORK}.json"
TX_TEMPLATE="${OUT_DIR}/lp_deposit_tx_template.json"

cat > "$OUT_FILE" <<EOF
{
  "version": "lp-cell-spec-v1",
  "network": "$NETWORK",
  "pool_id": "${POOL_ID#0x}",
  "owner_lock_hash": "${OWNER_LOCK_HASH#0x}",
  "operator_lock_hash": "${OPERATOR_LOCK_HASH#0x}",
  "available_ckb": $AVAILABLE_CKB,
  "reserved_ckb": $RESERVED_CKB,
  "cumulative_fees_earned_ckb": 0,
  "policy": {
    "max_trading_volume": $MAX_TRADING_VOLUME,
    "fee_rate_bps": $FEE_RATE_BPS,
    "policy_flags": $POLICY_FLAGS,
    "policy_version": $POLICY_VERSION
  },
  "nonce": $NONCE,
  "active": true,
  "mvp_constraints": {
    "single_lp_per_funding_tx": true,
    "single_operator_model": true
  }
}
EOF

MONITORING_DIR="$(dirname "$MONITORING_CHECKLIST_OUT")"
mkdir -p "$MONITORING_DIR"

cat > "$MONITORING_CHECKLIST_OUT" <<EOF
# LP Rollout Monitoring Checklist

Network: $NETWORK

## Pre-rollout

- [ ] LP binaries rebuilt: \
  source ./setup_env.sh build && make build
- [ ] Deployment manifest present: $DEPLOY_CFG
- [ ] Migration spec reviewed: $OUT_FILE
- [ ] Operator and owner lock hashes cross-checked.

## Staged rollout

- [ ] Deploy scripts via deployment manifest.
- [ ] Create bootstrap LP cell from fresh deposit.
- [ ] Execute one canary funding tx (single LP cell).
- [ ] Execute one canary settlement tx and verify reserve conservation.

## Monitoring metrics

- [ ] Failed tx classes tracked: signer-auth failures.
- [ ] Failed tx classes tracked: policy violations.
- [ ] Failed tx classes tracked: reserve mismatch/conservation failures.
- [ ] Fee attribution drift monitored against expected fee-rate-bps.
- [ ] Unmatched-order backlog growth monitored by operator process.

## Exit gate

- [ ] No unexplained signer-auth failures in canary window.
- [ ] No reserve-conservation violations.
- [ ] Fee accounting deltas match policy expectations.
- [ ] Rollback plan validated.
EOF

cat <<EOF
Created LP migration spec: $OUT_FILE
Created LP monitoring checklist: $MONITORING_CHECKLIST_OUT

Suggested next commands:
1) Build artifacts (if needed)
   source ./setup_env.sh build && make build

2) Deploy LP scripts with dedicated manifest
   ckb-cli deploy gen-txs --deployment-config $DEPLOY_CFG --from-account <ACCOUNT_ADDRESS> --info-file $DEPLOY_INFO
   ckb-cli deploy apply-txs --info-file $DEPLOY_INFO

3) Prepare fresh-deposit tx template for LP cell creation
   ckb-cli tx init --output-file $TX_TEMPLATE

4) Fill tx template using values from $OUT_FILE, then sign/send:
   ckb-cli tx sign-inputs --tx-file $TX_TEMPLATE --from-account <ACCOUNT_ADDRESS>
   ckb-cli tx send --tx-file $TX_TEMPLATE
EOF
