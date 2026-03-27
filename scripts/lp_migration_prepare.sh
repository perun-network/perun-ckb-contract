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
    [--max-trading-volume 0] \
    [--nonce 0] \
    [--network dev|release] \
    [--out migrations_lp/lp_cell_spec.json]

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
MAX_TRADING_VOLUME="0"
NONCE="0"
NETWORK="dev"
OUT_FILE="migrations_lp/lp_cell_spec.json"

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
    --max-trading-volume)
      MAX_TRADING_VOLUME="$2"; shift 2 ;;
    --nonce)
      NONCE="$2"; shift 2 ;;
    --network)
      NETWORK="$2"; shift 2 ;;
    --out)
      OUT_FILE="$2"; shift 2 ;;
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
require_u64 "$MAX_TRADING_VOLUME" "max-trading-volume"
require_u64 "$NONCE" "nonce"

OUT_DIR="$(dirname "$OUT_FILE")"
mkdir -p "$OUT_DIR"

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
    "policy_flags": 0,
    "policy_version": 1
  },
  "nonce": $NONCE,
  "active": true,
  "mvp_constraints": {
    "single_lp_per_funding_tx": true,
    "single_operator_model": true
  }
}
EOF

DEPLOY_CFG="deployment/${NETWORK}/deployment_lp.toml"
DEPLOY_INFO="${OUT_DIR}/lp_deploy_info_${NETWORK}.json"
TX_TEMPLATE="${OUT_DIR}/lp_deposit_tx_template.json"

cat <<EOF
Created LP migration spec: $OUT_FILE

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
