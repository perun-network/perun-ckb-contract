use super::*;
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder},
    packed::{Byte32, CellDep, CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
use perun_common::perun_types::ChannelStatus;
use perun_common::pool::{LPCell, LPPolicy, PoolWitness};
use std::env;
use std::fs;
use std::path::PathBuf;

const MAX_CYCLES: u64 = 100 * 10_000_000;
const LP_IN_CAP: u64 = 20_000_000_000;
const TOPUP_CAP_DELTA: u64 = 5_000_000_000;
const AUTH_INPUT_CAP: u64 = 10_000_000_000;
const EXTRACT_CKB: u64 = 2_000_000_000;

fn load_lp_typescript_binary() -> Option<Bytes> {
    let mode = match env::var("MODE") {
        Ok(val) if val.eq_ignore_ascii_case("debug") => "debug",
        _ => "release",
    };

    let mut base = match env::var("TOP") {
        Ok(val) => {
            let mut p = PathBuf::from(val);
            p.push("build");
            p
        }
        Err(_) => {
            let mut p = PathBuf::from("build");
            if !p.exists() {
                p = PathBuf::from("..");
                p.push("build");
            }
            p
        }
    };
    base.push(mode);

    let candidates = [
        "liquidity-pool-typescript",
        "liquidity-pool-typescript.debug",
    ];
    for candidate in candidates {
        let mut path = base.clone();
        path.push(candidate);
        if let Ok(bin) = fs::read(path) {
            return Some(Bytes::from(bin));
        }
    }
    None
}

fn deploy_lp_typescript(
    context: &mut Context,
) -> (ckb_testtool::ckb_types::packed::OutPoint, CellDep) {
    let lp_ts_bin = load_lp_typescript_binary().expect(
        "LP typescript binary is missing. Build liquidity-pool-typescript artifacts before running LP e2e tests.",
    );
    let out_point = context.deploy_cell(lp_ts_bin);
    let dep = CellDep::new_builder().out_point(out_point.clone()).build();
    (out_point, dep)
}

fn deploy_always_success(
    context: &mut Context,
) -> (ckb_testtool::ckb_types::packed::OutPoint, CellDep) {
    let out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let dep = CellDep::new_builder().out_point(out_point.clone()).build();
    (out_point, dep)
}

fn build_lock(
    context: &mut Context,
    always_success_out_point: &ckb_testtool::ckb_types::packed::OutPoint,
    tag: u8,
) -> Script {
    context
        .build_script(always_success_out_point, Bytes::from(vec![tag]))
        .expect("build lock script")
}

fn lp_policy() -> LPPolicy {
    LPPolicy {
        max_trading_volume: 0,
        fee_rate_bps: 30,
        policy_flags: 0,
        policy_version: 1,
    }
}

fn script_hash_array(script: &Script) -> [u8; 32] {
    script.calc_script_hash().unpack()
}

fn channel_status_data(channel_id: [u8; 32]) -> Bytes {
    let base = ChannelStatus::default();
    let state = base
        .state()
        .as_builder()
        .channel_id(Byte32::from_slice(&channel_id).expect("channel id"))
        .build();
    let status = base.as_builder().state(state).build();
    status.as_bytes()
}

#[test]
fn lp_deposit_topup_success() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x11; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 0,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP + TOPUP_CAP_DELTA,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 1,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    let owner_change_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(owner_lock.clone())
            .build(),
        Bytes::new(),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(PoolWitness::LPDeposit.encode())).pack())
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(owner_change_out_point)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP + TOPUP_CAP_DELTA).pack())
                .lock(owner_lock.clone())
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((AUTH_INPUT_CAP - TOPUP_CAP_DELTA).pack())
                .lock(owner_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES).expect("LP deposit top-up should pass");
}

#[test]
fn lp_extract_missing_channel_output_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x22; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 7,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP - EXTRACT_CKB,
        reserved_ckb: EXTRACT_CKB,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 8,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    let operator_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::FundChannelExtract {
                    channel_id: [0xAB; 32],
                    contribution_id: [0xCD; 32],
                    extract_ckb: EXTRACT_CKB,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_input)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP - EXTRACT_CKB).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((AUTH_INPUT_CAP + EXTRACT_CKB).pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract without matching channel output must fail"
    );
}

#[test]
fn lp_settle_success() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x33; 32];
    let channel_id = [0xC1; 32];
    let principal_returned = 2_000_000_000u64;
    let fee_ckb = 500_000_000u64;
    let total_return = principal_returned + fee_ckb;

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: 8_000_000_000,
        reserved_ckb: 3_000_000_000,
        cumulative_fees_earned_ckb: 10,
        policy: lp_policy(),
        nonce: 10,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: 8_000_000_000 + total_return,
        reserved_ckb: 3_000_000_000 - principal_returned,
        cumulative_fees_earned_ckb: 10 + fee_ckb,
        policy: lp_policy(),
        nonce: 11,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(11_000_000_000u64.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    // Channel input is consumed by settlement and must not appear in outputs.
    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(4_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let operator_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(10_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::SettleChannelInsert {
                    channel_id,
                    contribution_id: [0xE1; 32],
                    principal_returned,
                    fee_ckb,
                    price_x64: 1,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_input)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((11_000_000_000u64 + total_return).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((10_000_000_000u64 + 4_000_000_000u64 - total_return).pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES)
        .expect("settlement insertion with sufficient consumed channel capacity should pass");
}

#[test]
fn lp_settle_insufficient_channel_capacity_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x44; 32];
    let channel_id = [0xC2; 32];
    let principal_returned = 2_000_000_000u64;
    let fee_ckb = 0u64;
    let total_return = principal_returned + fee_ckb;

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: 8_000_000_000,
        reserved_ckb: 3_000_000_000,
        cumulative_fees_earned_ckb: 10,
        policy: lp_policy(),
        nonce: 20,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: 10_000_000_000,
        reserved_ckb: 1_000_000_000,
        cumulative_fees_earned_ckb: 10,
        policy: lp_policy(),
        nonce: 21,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(11_000_000_000u64.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    // Deliberately too small: contract requires consumed channel capacity >= principal+fee.
    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let operator_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(10_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::SettleChannelInsert {
                    channel_id,
                    contribution_id: [0xE2; 32],
                    principal_returned,
                    fee_ckb,
                    price_x64: 1,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_input)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((11_000_000_000u64 + total_return).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((10_000_000_000u64 + 1_000_000_000u64 - total_return).pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "settlement must fail when consumed channel capacity is below principal+fee"
    );
}

#[test]
fn lp_extract_wrong_channel_delta_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x55; 32];
    let channel_id = [0xD1; 32];

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 30,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP - EXTRACT_CKB,
        reserved_ckb: EXTRACT_CKB,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 31,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    let operator_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    // Channel input/output exist for the same channel_id, but delta is intentionally wrong.
    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::FundChannelExtract {
                    channel_id,
                    contribution_id: [0xF1; 32],
                    extract_ckb: EXTRACT_CKB,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_input)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_input_out_point)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP - EXTRACT_CKB).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            // Output channel increases by only 1_000_000_000, not EXTRACT_CKB.
            CellOutput::new_builder()
                .capacity(4_000_000_000u64.pack())
                .lock(operator_lock.clone())
                .build(),
            CellOutput::new_builder()
                .capacity((AUTH_INPUT_CAP + 2_000_000_000u64).pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            channel_status_data(channel_id).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract must fail when channel capacity delta does not equal extract_ckb"
    );
}

#[test]
fn lp_settle_channel_still_in_outputs_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x66; 32];
    let channel_id = [0xD2; 32];
    let principal_returned = 2_000_000_000u64;
    let fee_ckb = 500_000_000u64;
    let total_return = principal_returned + fee_ckb;

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: 8_000_000_000,
        reserved_ckb: 3_000_000_000,
        cumulative_fees_earned_ckb: 10,
        policy: lp_policy(),
        nonce: 40,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: 8_000_000_000 + total_return,
        reserved_ckb: 3_000_000_000 - principal_returned,
        cumulative_fees_earned_ckb: 10 + fee_ckb,
        policy: lp_policy(),
        nonce: 41,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(11_000_000_000u64.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(4_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let operator_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(10_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::SettleChannelInsert {
                    channel_id,
                    contribution_id: [0xF2; 32],
                    principal_returned,
                    fee_ckb,
                    price_x64: 1,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_input)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((11_000_000_000u64 + total_return).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            // Intentionally keep the same channel alive in outputs, which should fail.
            CellOutput::new_builder()
                .capacity(1_000_000_000u64.pack())
                .lock(operator_lock.clone())
                .build(),
            CellOutput::new_builder()
                .capacity(
                    (10_000_000_000u64 + 4_000_000_000u64 - total_return - 1_000_000_000u64).pack(),
                )
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            channel_status_data(channel_id).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "settlement must fail if channel with same channel_id still exists in outputs"
    );
}

#[test]
fn lp_extract_without_operator_signer_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x77; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 50,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP - EXTRACT_CKB,
        reserved_ckb: EXTRACT_CKB,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 51,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    // Provide only owner-side extra input; no operator-locked input exists.
    let owner_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(owner_lock.clone())
            .build(),
        Bytes::new(),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::FundChannelExtract {
                    channel_id: [0xA7; 32],
                    contribution_id: [0xB7; 32],
                    extract_ckb: EXTRACT_CKB,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(owner_auth_input)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP - EXTRACT_CKB).pack())
                .lock(owner_lock.clone())
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((AUTH_INPUT_CAP + EXTRACT_CKB).pack())
                .lock(owner_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract must fail when no operator lock hash appears in tx inputs"
    );
}

#[test]
fn lp_withdraw_owner_hash_not_signing_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x88; 32];
    let fake_owner_hash = [0xEE; 32];
    let ckb_out = 1_000_000_000u64;

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: fake_owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 60,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: fake_owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP - ckb_out,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 61,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    // Extra input is operator-locked, so fake owner hash does not appear in inputs.
    let operator_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(PoolWitness::LPWithdraw { ckb_out }.encode())).pack())
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_input)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP - ckb_out).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((AUTH_INPUT_CAP + ckb_out).pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "withdraw must fail when LP owner_lock_hash from state is not represented in tx inputs"
    );
}

#[test]
fn lp_extract_success() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x99; 32];
    let channel_id = [0xD3; 32];

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 70,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP - EXTRACT_CKB,
        reserved_ckb: EXTRACT_CKB,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 71,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    let operator_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::FundChannelExtract {
                    channel_id,
                    contribution_id: [0xC3; 32],
                    extract_ckb: EXTRACT_CKB,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_input)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_input_out_point)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP - EXTRACT_CKB).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((3_000_000_000u64 + EXTRACT_CKB).pack())
                .lock(operator_lock.clone())
                .build(),
            CellOutput::new_builder()
                .capacity(AUTH_INPUT_CAP.pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            channel_status_data(channel_id).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES)
        .expect("extract should pass when channel capacity delta matches extract_ckb");
}

#[test]
fn lp_extract_then_settle_success() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xAA; 32];
    let channel_id = [0xD4; 32];
    let principal_returned = EXTRACT_CKB;
    let fee_ckb = 500_000_000u64;
    let total_return = principal_returned + fee_ckb;

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let lp_before_extract = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 80,
        active: true,
    };

    let lp_after_extract = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP - EXTRACT_CKB,
        reserved_ckb: EXTRACT_CKB,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 81,
        active: true,
    };

    let lp_after_settle = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP + fee_ckb,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: fee_ckb,
        policy: lp_policy(),
        nonce: 82,
        active: true,
    };

    // Step 1: extract
    let lp_extract_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(lp_before_extract.encode()),
    );
    let operator_extract_auth = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );
    let channel_extract_in = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let extract_witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::FundChannelExtract {
                    channel_id,
                    contribution_id: [0xC4; 32],
                    extract_ckb: EXTRACT_CKB,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let extract_tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_extract_input)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_extract_auth)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_extract_in)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP - EXTRACT_CKB).pack())
                .lock(owner_lock.clone())
                .type_(Some(lp_type.clone()).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((3_000_000_000u64 + EXTRACT_CKB).pack())
                .lock(operator_lock.clone())
                .build(),
            CellOutput::new_builder()
                .capacity(AUTH_INPUT_CAP.pack())
                .lock(operator_lock.clone())
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(lp_after_extract.encode()).pack(),
            channel_status_data(channel_id).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep.clone(), always_success_dep.clone()])
        .witness(extract_witness.as_bytes().pack())
        .build();

    let extract_tx = context.complete_tx(extract_tx);
    verify_and_dump_failed_tx(&context, &extract_tx, MAX_CYCLES)
        .expect("extract step should pass in chained flow");

    // Step 2: settle (seeded from expected post-extract state)
    let lp_settle_input = context.create_cell(
        CellOutput::new_builder()
            .capacity((LP_IN_CAP - EXTRACT_CKB).pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(lp_after_extract.encode()),
    );
    let channel_settle_input = context.create_cell(
        CellOutput::new_builder()
            .capacity((3_000_000_000u64 + EXTRACT_CKB + fee_ckb).pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );
    let operator_settle_auth = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    let settle_witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::SettleChannelInsert {
                    channel_id,
                    contribution_id: [0xC4; 32],
                    principal_returned,
                    fee_ckb,
                    price_x64: 1,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let settle_tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_settle_input)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_settle_input)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_settle_auth)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP + fee_ckb).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((AUTH_INPUT_CAP + 3_000_000_000u64).pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(lp_after_settle.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(settle_witness.as_bytes().pack())
        .build();

    let settle_tx = context.complete_tx(settle_tx);
    verify_and_dump_failed_tx(&context, &settle_tx, MAX_CYCLES)
        .expect("settle step should pass in chained flow");
}

#[test]
fn lp_extract_nonce_not_incremented_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xBB; 32];
    let channel_id = [0xD5; 32];

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 90,
        active: true,
    };

    // Intentionally invalid: nonce unchanged (should be +1).
    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP - EXTRACT_CKB,
        reserved_ckb: EXTRACT_CKB,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 90,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );
    let operator_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );
    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::FundChannelExtract {
                    channel_id,
                    contribution_id: [0xC5; 32],
                    extract_ckb: EXTRACT_CKB,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_input)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_input_out_point)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP - EXTRACT_CKB).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((3_000_000_000u64 + EXTRACT_CKB).pack())
                .lock(operator_lock.clone())
                .build(),
            CellOutput::new_builder()
                .capacity(AUTH_INPUT_CAP.pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            channel_status_data(channel_id).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract must fail when output LP nonce is not incremented by 1"
    );
}

#[test]
fn lp_extract_over_max_trading_volume_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xCC; 32];
    let channel_id = [0xD6; 32];

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: LPPolicy {
            max_trading_volume: EXTRACT_CKB - 1,
            fee_rate_bps: 30,
            policy_flags: 0,
            policy_version: 1,
        },
        nonce: 100,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP - EXTRACT_CKB,
        reserved_ckb: EXTRACT_CKB,
        cumulative_fees_earned_ckb: 0,
        policy: LPPolicy {
            max_trading_volume: EXTRACT_CKB - 1,
            fee_rate_bps: 30,
            policy_flags: 0,
            policy_version: 1,
        },
        nonce: 101,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );
    let operator_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );
    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::FundChannelExtract {
                    channel_id,
                    contribution_id: [0xC6; 32],
                    extract_ckb: EXTRACT_CKB,
                }
                .encode(),
            ))
            .pack(),
        )
        .build();

    let tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_out_point)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_input)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_input_out_point)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP - EXTRACT_CKB).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((3_000_000_000u64 + EXTRACT_CKB).pack())
                .lock(operator_lock.clone())
                .build(),
            CellOutput::new_builder()
                .capacity(AUTH_INPUT_CAP.pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            channel_status_data(channel_id).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract must fail when extract_ckb exceeds max_trading_volume"
    );
}
