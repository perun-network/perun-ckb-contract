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

fn load_lp_lockscript_binary() -> Option<Bytes> {
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
        "liquidity-pool-lockscript",
        "liquidity-pool-lockscript.debug",
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

fn deploy_lp_lockscript(
    context: &mut Context,
) -> (ckb_testtool::ckb_types::packed::OutPoint, CellDep) {
    let lp_ls_bin = load_lp_lockscript_binary().expect(
        "LP lockscript binary is missing. Build liquidity-pool-lockscript artifacts before running LP e2e tests.",
    );
    let out_point = context.deploy_cell(lp_ls_bin);
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

fn build_lp_lock(
    context: &mut Context,
    lp_lockscript_out_point: &ckb_testtool::ckb_types::packed::OutPoint,
    lp_typescript_hash: [u8; 32],
) -> Script {
    context
        .build_script_with_hash_type(
            lp_lockscript_out_point,
            ScriptHashType::Data1,
            Bytes::from(lp_typescript_hash.to_vec()),
        )
        .expect("build lp lockscript")
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
fn lp_lockscript_rejects_without_owner_or_operator_signer() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (lp_ls_out_point, lp_ls_dep) = deploy_lp_lockscript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x13; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let outsider_lock = build_lock(&mut context, &always_success_out_point, 9);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");
    let lp_lock = build_lp_lock(
        &mut context,
        &lp_ls_out_point,
        lp_type.calc_script_hash().unpack(),
    );

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
            .lock(lp_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    let outsider_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(outsider_lock.clone())
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
                .previous_output(outsider_auth_input)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP + TOPUP_CAP_DELTA).pack())
                .lock(lp_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((AUTH_INPUT_CAP - TOPUP_CAP_DELTA).pack())
                .lock(outsider_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(output_lp.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, lp_ls_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "LP lockscript should reject when neither owner nor operator signs"
    );
}

#[test]
fn lp_lockscript_rejects_wrong_typescript_hash_arg() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (lp_ls_out_point, lp_ls_dep) = deploy_lp_lockscript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x15; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = context
        .build_script_with_hash_type(
            &lp_ts_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript");
    let wrong_ts_hash = [0xEE; 32];
    let lp_lock = build_lp_lock(&mut context, &lp_ls_out_point, wrong_ts_hash);

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
            .lock(lp_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(input_lp.encode()),
    );

    let owner_auth_input = context.create_cell(
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
                .previous_output(owner_auth_input)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP + TOPUP_CAP_DELTA).pack())
                .lock(lp_lock)
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
        .cell_deps(vec![lp_ts_dep, lp_ls_dep, always_success_dep])
        .witness(witness.as_bytes().pack())
        .build();

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "LP lockscript must reject when lock args typescript hash does not match any input typescript"
    );
}

#[test]
fn lp_happy_path_deposit_extract_settle_success() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0x99; 32];
    let extract_channel_id = [0xD3; 32];
    let settle_channel_id = [0xC1; 32];
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

    let initial_lp = LPCell {
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

    // Step 1: deposit top-up by owner.
    let after_deposit_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP + TOPUP_CAP_DELTA,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 71,
        active: true,
    };

    let lp_input_deposit = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(initial_lp.encode()),
    );

    let owner_auth_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(owner_lock.clone())
            .build(),
        Bytes::new(),
    );

    let deposit_witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(PoolWitness::LPDeposit.encode())).pack())
        .build();

    let deposit_tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_deposit)
                .build(),
            CellInput::new_builder()
                .previous_output(owner_auth_input)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP + TOPUP_CAP_DELTA).pack())
                .lock(owner_lock.clone())
                .type_(Some(lp_type.clone()).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((AUTH_INPUT_CAP - TOPUP_CAP_DELTA).pack())
                .lock(owner_lock.clone())
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(after_deposit_lp.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep.clone(), always_success_dep.clone()])
        .witness(deposit_witness.as_bytes().pack())
        .build();

    let deposit_tx = context.complete_tx(deposit_tx);
    verify_and_dump_failed_tx(&context, &deposit_tx, MAX_CYCLES)
        .expect("deposit top-up should pass");

    // Step 2: extract from LP into channel.
    let after_extract_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB,
        reserved_ckb: EXTRACT_CKB,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 72,
        active: true,
    };

    let lp_input_extract = context.create_cell(
        CellOutput::new_builder()
            .capacity((LP_IN_CAP + TOPUP_CAP_DELTA).pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(after_deposit_lp.encode()),
    );

    let operator_auth_extract = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    let channel_input_extract = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(extract_channel_id),
    );

    let extract_witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::FundChannelExtract {
                    channel_id: extract_channel_id,
                    contribution_id: [0xC3; 32],
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
                .previous_output(lp_input_extract)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_extract)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_input_extract)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB).pack())
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
            Bytes::from(after_extract_lp.encode()).pack(),
            channel_status_data(extract_channel_id).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep.clone(), always_success_dep.clone()])
        .witness(extract_witness.as_bytes().pack())
        .build();

    let extract_tx = context.complete_tx(extract_tx);
    verify_and_dump_failed_tx(&context, &extract_tx, MAX_CYCLES)
        .expect("extract should pass when channel capacity delta matches extract_ckb");

    // Step 3: settle and return principal + fee to LP.
    let after_settle_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB + total_return,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: fee_ckb,
        policy: lp_policy(),
        nonce: 73,
        active: true,
    };

    let lp_input_settle = context.create_cell(
        CellOutput::new_builder()
            .capacity((LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB).pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(after_extract_lp.encode()),
    );

    let operator_auth_settle = context.create_cell(
        CellOutput::new_builder()
            .capacity(AUTH_INPUT_CAP.pack())
            .lock(operator_lock.clone())
            .build(),
        Bytes::new(),
    );

    let channel_input_settle = context.create_cell(
        CellOutput::new_builder()
            .capacity(4_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(settle_channel_id),
    );

    let settle_witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                PoolWitness::SettleChannelInsert {
                    channel_id: settle_channel_id,
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

    let settle_tx = TransactionBuilder::default()
        .inputs(vec![
            CellInput::new_builder()
                .previous_output(lp_input_settle)
                .build(),
            CellInput::new_builder()
                .previous_output(channel_input_settle)
                .build(),
            CellInput::new_builder()
                .previous_output(operator_auth_settle)
                .build(),
        ])
        .outputs(vec![
            CellOutput::new_builder()
                .capacity((LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB + total_return).pack())
                .lock(owner_lock)
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity((AUTH_INPUT_CAP + 4_000_000_000u64 - total_return).pack())
                .lock(operator_lock)
                .build(),
        ])
        .outputs_data(vec![
            Bytes::from(after_settle_lp.encode()).pack(),
            Bytes::new().pack(),
        ])
        .cell_deps(vec![lp_ts_dep, always_success_dep])
        .witness(settle_witness.as_bytes().pack())
        .build();

    let settle_tx = context.complete_tx(settle_tx);
    verify_and_dump_failed_tx(&context, &settle_tx, MAX_CYCLES)
        .expect("settlement insertion with sufficient consumed channel capacity should pass");
}

#[test]
fn lp_extract_without_owner_signer_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xCD; 32];
    let channel_id = [0xD7; 32];
    let fake_owner_hash = [0xAB; 32];

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
        nonce: 110,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: fake_owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: LP_IN_CAP - EXTRACT_CKB,
        reserved_ckb: EXTRACT_CKB,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 111,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock)
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
                    contribution_id: [0xC7; 32],
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
                .lock(operator_lock.clone())
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
        "extract must fail when LP owner hash from state does not appear in tx inputs"
    );
}

#[test]
fn lp_cancel_reservation_with_channel_present_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xD3; 32];
    let channel_id = [0xDB; 32];
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
        available_ckb: 7_000_000_000,
        reserved_ckb: 2_000_000_000,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 134,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: operator_hash,
        available_ckb: 9_000_000_000,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 135,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(9_000_000_000u64.pack())
            .lock(owner_lock)
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

    // Cancel should fail if referenced channel is currently present.
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
                PoolWitness::CancelReservation {
                    channel_id,
                    contribution_id: [0xCB; 32],
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
                .capacity(9_000_000_000u64.pack())
                .lock(operator_lock.clone())
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity(AUTH_INPUT_CAP.pack())
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
        "cancel reservation must fail when referenced channel is still present"
    );
}

#[test]
fn lp_rotate_operator_zero_hash_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xD1; 32];
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
        nonce: 150,
        active: true,
    };

    let output_lp = LPCell {
        pool_id,
        owner_lock_hash: owner_hash,
        operator_lock_hash: [0u8; 32],
        available_ckb: LP_IN_CAP,
        reserved_ckb: 0,
        cumulative_fees_earned_ckb: 0,
        policy: lp_policy(),
        nonce: 151,
        active: true,
    };

    let lp_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(LP_IN_CAP.pack())
            .lock(owner_lock)
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
                PoolWitness::RotateOperator {
                    new_operator_lock_hash: [0u8; 32],
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
                .capacity(LP_IN_CAP.pack())
                .lock(operator_lock.clone())
                .type_(Some(lp_type).pack())
                .build(),
            CellOutput::new_builder()
                .capacity(AUTH_INPUT_CAP.pack())
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
        "rotate operator must fail when new operator lock hash is all zeros"
    );
}
