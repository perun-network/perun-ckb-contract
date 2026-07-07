use super::lp_harness::*;
use super::*;
use ckb_testtool::ckb_types::{bytes::Bytes, packed::CellOutput, prelude::*};
use ckb_testtool::context::Context;
use perun_common::pool::{LPPolicyFlag, LPPolicyFlags, PoolWitness};

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

    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);
    let lp_lock = build_lp_lock(&mut context, &lp_ls_out_point, script_hash_array(&lp_type));

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 0);

    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP + TOPUP_CAP_DELTA,
        0,
        0,
        1,
    );

    let lp_input_out_point = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        lp_lock.clone(),
        lp_type.clone(),
        &input_lp,
    );

    let outsider_auth_input = create_auth_cell(&mut context, AUTH_INPUT_CAP, outsider_lock.clone());

    let witness = witness_from_pool(PoolWitness::LPDeposit);

    let tx = build_tx_from_specs(
        vec![lp_input_out_point, outsider_auth_input],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP + TOPUP_CAP_DELTA,
                lock: lp_lock,
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP - TOPUP_CAP_DELTA,
                lock: outsider_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, lp_ls_dep, always_success_dep],
        witness,
    );

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

    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);
    let wrong_ts_hash = [0xEE; 32];
    let lp_lock = build_lp_lock(&mut context, &lp_ls_out_point, wrong_ts_hash);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 0);

    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP + TOPUP_CAP_DELTA,
        0,
        0,
        1,
    );

    let lp_input_out_point = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        lp_lock.clone(),
        lp_type.clone(),
        &input_lp,
    );

    let owner_auth_input = create_auth_cell(&mut context, AUTH_INPUT_CAP, owner_lock.clone());

    let witness = witness_from_pool(PoolWitness::LPDeposit);

    let tx = build_tx_from_specs(
        vec![lp_input_out_point, owner_auth_input],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP + TOPUP_CAP_DELTA,
                lock: lp_lock,
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP - TOPUP_CAP_DELTA,
                lock: owner_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, lp_ls_dep, always_success_dep],
        witness,
    );

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
    let settle_channel_id = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC,
        0xFE, 0x55, 0xAA, 0x11, 0x22, 0x33, 0x44, 0x66, 0x77, 0x88, 0x99, 0xBB, 0xCC, 0xDD, 0xEE,
        0x13, 0x37,
    ];
    // Real swap shape: traded_ckb of the extract was sold to the peer during
    // the swap; only the remainder returns to the pool as principal.
    let traded_ckb = 1_500_000_000u64;
    let principal_returned = EXTRACT_CKB - traded_ckb;
    let fee_ckb = 500_000_000u64;
    let total_return = principal_returned + fee_ckb;

    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let initial_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 70);

    // Step 1: deposit top-up by owner.
    let after_deposit_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP + TOPUP_CAP_DELTA,
        0,
        0,
        71,
    );

    let lp_input_deposit = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock.clone(),
        lp_type.clone(),
        &initial_lp,
    );

    let owner_auth_input = create_auth_cell(&mut context, AUTH_INPUT_CAP, owner_lock.clone());

    let deposit_witness = witness_from_pool(PoolWitness::LPDeposit);

    let deposit_tx = build_tx_from_specs(
        vec![lp_input_deposit, owner_auth_input],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP + TOPUP_CAP_DELTA,
                lock: owner_lock.clone(),
                type_script: Some(lp_type.clone()),
                data: Bytes::from(after_deposit_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP - TOPUP_CAP_DELTA,
                lock: owner_lock.clone(),
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep.clone(), always_success_dep.clone()],
        deposit_witness,
    );

    let deposit_tx = context.complete_tx(deposit_tx);
    verify_and_dump_failed_tx(&context, &deposit_tx, MAX_CYCLES)
        .expect("deposit top-up should pass");

    // Step 2: extract from LP into channel.
    let after_extract_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        72,
    );

    let lp_input_extract = context.create_cell(
        CellOutput::new_builder()
            .capacity((LP_IN_CAP + TOPUP_CAP_DELTA).pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(after_deposit_lp.encode()),
    );

    let operator_auth_extract =
        create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());

    let channel_input_extract = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(extract_channel_id),
    );

    let extract_witness = witness_from_pool(PoolWitness::FundChannelExtract {
        channel_id: extract_channel_id,
        contribution_id: [0xC3; 32],
        extract_ckb: EXTRACT_CKB,
    });

    let extract_tx = build_tx_from_specs(
        vec![
            lp_input_extract,
            operator_auth_extract,
            channel_input_extract,
        ],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB,
                lock: owner_lock.clone(),
                type_script: Some(lp_type.clone()),
                data: Bytes::from(after_extract_lp.encode()),
            },
            TxOutputSpec {
                capacity: 3_000_000_000u64 + EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: None,
                data: channel_status_data(extract_channel_id),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock.clone(),
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep.clone(), always_success_dep.clone()],
        extract_witness,
    );

    let extract_tx = context.complete_tx(extract_tx);
    verify_and_dump_failed_tx(&context, &extract_tx, MAX_CYCLES)
        .expect("extract should pass when channel capacity delta matches extract_ckb");

    // Step 3: settle and return principal + fee to LP.
    let after_settle_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB + total_return,
        0,
        fee_ckb,
        73,
    );

    let lp_input_settle = context.create_cell(
        CellOutput::new_builder()
            .capacity((LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB).pack())
            .lock(owner_lock.clone())
            .type_(Some(lp_type.clone()).pack())
            .build(),
        Bytes::from(after_extract_lp.encode()),
    );

    let operator_settle_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let settle_witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id: settle_channel_id,
        contribution_id: [0xE1; 32],
        principal_returned,
        fee_ckb,
        traded_ckb,
        price_x64: 1,
    });

    let settle_tx = build_tx_from_specs(
        vec![lp_input_settle, operator_settle_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB + total_return,
                lock: owner_lock,
                type_script: Some(lp_type),
                data: Bytes::from(after_settle_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        settle_witness,
    );

    let settle_tx = context.complete_tx(settle_tx);
    verify_and_dump_failed_tx(&context, &settle_tx, MAX_CYCLES)
        .expect("settlement insertion should pass when operator directly funds LP return");
}

#[test]
fn lp_extract_without_operator_signer_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xCD; 32];
    let channel_id = [0xD7; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 110);

    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        111,
    );

    let lp_input_out_point = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock.clone(),
        lp_type.clone(),
        &input_lp,
    );

    let owner_auth_input = create_auth_cell(&mut context, AUTH_INPUT_CAP, owner_lock.clone());

    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(owner_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::FundChannelExtract {
        channel_id,
        contribution_id: [0xC7; 32],
        extract_ckb: EXTRACT_CKB,
    });

    let tx = build_tx_from_specs(
        vec![
            lp_input_out_point,
            owner_auth_input,
            channel_input_out_point,
        ],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: 3_000_000_000u64 + EXTRACT_CKB,
                lock: owner_lock.clone(),
                type_script: None,
                data: channel_status_data(channel_id),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract must fail when operator hash from state does not appear in tx inputs"
    );
}

#[test]
fn lp_extract_without_owner_signer_succeeds_operator_only() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xC4; 32];
    let channel_id = [0xCA; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);

    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 11);
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        12,
    );

    let lp_input_out_point = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        operator_lock.clone(),
        lp_type.clone(),
        &input_lp,
    );

    let operator_auth_input = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());

    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::FundChannelExtract {
        channel_id,
        contribution_id: [0xC8; 32],
        extract_ckb: EXTRACT_CKB,
    });

    let tx = build_tx_from_specs(
        vec![
            lp_input_out_point,
            operator_auth_input,
            channel_input_out_point,
        ],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: 3_000_000_000u64 + EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: None,
                data: channel_status_data(channel_id),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_ok(),
        "extract must succeed when operator signs even if owner hash from state does not appear in tx inputs"
    );
}

#[test]
fn lp_settle_rejects_when_channel_still_live_in_tx() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xAB; 32];
    let channel_id = [0xBB; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = EXTRACT_CKB;
    let fee_ckb = 100_000_000u64;
    let total_return = principal_returned + fee_ckb;

    let input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - principal_returned,
        principal_returned,
        0,
        66,
    );
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - principal_returned + total_return,
        0,
        fee_ckb,
        67,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - principal_returned,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );
    let live_channel = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0xCB; 32],
        principal_returned,
        fee_ckb,
        traded_ckb: 0,
        price_x64: 1,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding, live_channel],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - principal_returned + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock.clone(),
                type_script: None,
                data: Bytes::new(),
            },
            TxOutputSpec {
                capacity: 3_000_000_000u64,
                lock: operator_lock,
                type_script: None,
                data: channel_status_data(channel_id),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "settle must fail when referenced channel is still live in the settle tx"
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

    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        7_000_000_000,
        2_000_000_000,
        0,
        134,
    );

    let output_lp = make_lp_cell(pool_id, owner_hash, operator_hash, 9_000_000_000, 0, 0, 135);

    let lp_input_out_point = create_typed_lp_cell(
        &mut context,
        9_000_000_000,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );

    let operator_auth_input = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());

    // Cancel should fail if referenced channel is currently present.
    let channel_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::CancelReservation {
        channel_id,
        contribution_id: [0xCB; 32],
    });

    let tx = build_tx_from_specs(
        vec![
            lp_input_out_point,
            operator_auth_input,
            channel_input_out_point,
        ],
        vec![
            TxOutputSpec {
                capacity: 9_000_000_000u64,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

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

    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 150);

    let output_lp = make_lp_cell(pool_id, owner_hash, [0u8; 32], LP_IN_CAP, 0, 0, 151);

    let lp_input_out_point = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );

    let operator_auth_input = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());

    let witness = witness_from_pool(PoolWitness::RotateOperator {
        new_operator_lock_hash: [0u8; 32],
    });

    let tx = build_tx_from_specs(
        vec![lp_input_out_point, operator_auth_input],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "rotate operator must fail when new operator lock hash is all zeros"
    );
}

#[test]
fn lp_withdraw_over_available_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA1; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let available = 1_000_000_000u64;
    let withdraw_ckb = available + 1;

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, available, 0, 0, 10);
    let output_lp = make_lp_cell(pool_id, owner_hash, operator_hash, 0, 0, 0, 11);

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock.clone(),
        lp_type.clone(),
        &input_lp,
    );
    let owner_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, owner_lock.clone());

    let witness = witness_from_pool(PoolWitness::LPWithdraw {
        ckb_out: withdraw_ckb,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, owner_auth],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - withdraw_ckb,
                lock: owner_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: owner_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "withdraw must fail when requested amount exceeds available_ckb"
    );
}

#[test]
fn lp_extract_over_policy_limit_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA2; 32];
    let channel_id = [0xB2; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let mut input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 20);
    input_lp.policy.max_trading_volume = EXTRACT_CKB - 1;
    let mut output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        21,
    );
    output_lp.policy.max_trading_volume = EXTRACT_CKB - 1;

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock.clone(),
        lp_type.clone(),
        &input_lp,
    );
    let owner_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, owner_lock.clone());
    let operator_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());
    let channel_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::FundChannelExtract {
        channel_id,
        contribution_id: [0x22; 32],
        extract_ckb: EXTRACT_CKB,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, owner_auth, operator_auth, channel_input],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB,
                lock: owner_lock,
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: 3_000_000_000u64 + EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: None,
                data: channel_status_data(channel_id),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract must fail when witness extract_ckb exceeds policy max_trading_volume"
    );
}

#[test]
fn lp_deposit_nonce_not_incremented_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA3; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 30);
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP + TOPUP_CAP_DELTA,
        0,
        0,
        30,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock.clone(),
        lp_type.clone(),
        &input_lp,
    );
    let owner_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, owner_lock.clone());

    let witness = witness_from_pool(PoolWitness::LPDeposit);

    let tx = build_tx_from_specs(
        vec![lp_input, owner_auth],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP + TOPUP_CAP_DELTA,
                lock: owner_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP - TOPUP_CAP_DELTA,
                lock: owner_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "deposit must fail when output nonce does not increment by one"
    );
}

#[test]
fn lp_settle_rejects_when_operator_does_not_fund_return() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA4; 32];
    let channel_id = [0xB4; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let outsider_lock = build_lock(&mut context, &always_success_out_point, 9);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = EXTRACT_CKB;
    let fee_ckb = 500_000_000u64;
    let total_return = principal_returned + fee_ckb;

    let input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        40,
    );
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB + total_return,
        0,
        fee_ckb,
        41,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - EXTRACT_CKB,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());
    let outsider_funding = create_auth_cell(&mut context, total_return, outsider_lock.clone());

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x44; 32],
        principal_returned,
        fee_ckb,
        traded_ckb: 0,
        price_x64: 1,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_auth, outsider_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "settlement must fail when principal+fee is funded by non-operator inputs"
    );
}

#[test]
fn lp_settle_fee_exceeds_rate_with_cap_flag_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA5; 32];
    let channel_id = [0xB5; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = 200_000_000u64;
    let traded_ckb = 1_000_000_000u64;
    let extract_ckb = principal_returned + traded_ckb;
    let fee_ckb = 60_000_000u64;
    let total_return = principal_returned + fee_ckb;
    let flags = LPPolicyFlags::empty().with(LPPolicyFlag::EnforceMaxFee);

    let mut input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - extract_ckb,
        extract_ckb,
        0,
        50,
    );
    input_lp.policy = lp_policy_with(500, flags);

    let mut output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - extract_ckb + total_return,
        0,
        fee_ckb,
        51,
    );
    output_lp.policy = lp_policy_with(500, flags);

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - extract_ckb,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x55; 32],
        principal_returned,
        fee_ckb,
        traded_ckb,
        price_x64: 1,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - extract_ckb + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "settlement must fail when fee exceeds policy cap under policy_flags"
    );
}

#[test]
fn lp_settle_fee_below_rate_with_min_flag_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA8; 32];
    let channel_id = [0xB8; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = 200_000_000u64;
    let traded_ckb = 1_000_000_000u64;
    let extract_ckb = principal_returned + traded_ckb;
    let fee_ckb = 1u64;
    let total_return = principal_returned + fee_ckb;
    let flags = LPPolicyFlags::empty().with(LPPolicyFlag::EnforceMinFee);

    let mut input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - extract_ckb,
        extract_ckb,
        0,
        54,
    );
    input_lp.policy = lp_policy_with(500, flags);

    let mut output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - extract_ckb + total_return,
        0,
        fee_ckb,
        55,
    );
    output_lp.policy = lp_policy_with(500, flags);

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - extract_ckb,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x58; 32],
        principal_returned,
        fee_ckb,
        traded_ckb,
        price_x64: 1,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - extract_ckb + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "settlement must fail when fee is below policy minimum under policy_flags"
    );
}

#[test]
fn lp_settle_zero_price_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA6; 32];
    let channel_id = [0xB6; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = EXTRACT_CKB;
    let fee_ckb = 1u64;
    let total_return = principal_returned + fee_ckb;
    let flags = LPPolicyFlags::empty().with(LPPolicyFlag::RequirePrice);

    let input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        52,
    );
    let mut input_lp = input_lp;
    input_lp.policy = lp_policy_with(30, flags);
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB + total_return,
        0,
        fee_ckb,
        53,
    );
    let mut output_lp = output_lp;
    output_lp.policy = lp_policy_with(30, flags);

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - EXTRACT_CKB,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x66; 32],
        principal_returned,
        fee_ckb,
        traded_ckb: 0,
        price_x64: 0,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "settlement must fail when price_x64 is zero and REQUIRE_PRICE flag is set"
    );
}

#[test]
fn lp_settle_price_outside_safe_interval_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA7; 32];
    let channel_id = [0xB7; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = EXTRACT_CKB;
    let fee_ckb = 1u64;
    let total_return = principal_returned + fee_ckb;
    let flags = LPPolicyFlags::empty().with(LPPolicyFlag::SafePrice);

    let mut input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        64,
    );
    input_lp.policy = lp_policy_with_price_range(30, flags, 1_000, 2_000);

    let mut output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB + total_return,
        0,
        fee_ckb,
        65,
    );
    output_lp.policy = lp_policy_with_price_range(30, flags, 1_000, 2_000);

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - EXTRACT_CKB,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x67; 32],
        principal_returned,
        fee_ckb,
        traded_ckb: 0,
        price_x64: 999,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "settlement must fail when price_x64 falls outside SAFE_PRICE interval"
    );
}

#[test]
fn lp_settle_price_at_safe_interval_boundary_passes() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA8; 32];
    let channel_id = [0xB8; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = EXTRACT_CKB;
    let fee_ckb = 1u64;
    let total_return = principal_returned + fee_ckb;
    let flags = LPPolicyFlags::empty().with(LPPolicyFlag::SafePrice);

    let mut input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        66,
    );
    input_lp.policy = lp_policy_with_price_range(30, flags, 1_000, 2_000);

    let mut output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB + total_return,
        0,
        fee_ckb,
        67,
    );
    output_lp.policy = lp_policy_with_price_range(30, flags, 1_000, 2_000);

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - EXTRACT_CKB,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x68; 32],
        principal_returned,
        fee_ckb,
        traded_ckb: 0,
        price_x64: 1_000,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_ok(),
        "settlement should pass when price_x64 is inside SAFE_PRICE interval"
    );
}

#[test]
fn lp_settle_fee_at_max_policy_boundary_passes() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA9; 32];
    let channel_id = [0xB9; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = 200_000_000u64;
    let traded_ckb = 1_000_000_000u64;
    let extract_ckb = principal_returned + traded_ckb;
    let fee_ckb = 50_000_000u64;
    let total_return = principal_returned + fee_ckb;
    let flags = LPPolicyFlags::empty().with(LPPolicyFlag::EnforceMaxFee);

    let mut input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - extract_ckb,
        extract_ckb,
        0,
        56,
    );
    input_lp.policy = lp_policy_with(500, flags);

    let mut output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - extract_ckb + total_return,
        0,
        fee_ckb,
        57,
    );
    output_lp.policy = lp_policy_with(500, flags);

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - extract_ckb,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x59; 32],
        principal_returned,
        fee_ckb,
        traded_ckb,
        price_x64: 1,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - extract_ckb + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_ok(),
        "settlement should pass when fee equals max-policy boundary"
    );
}

#[test]
fn lp_settle_fee_at_min_policy_boundary_passes() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xAA; 32];
    let channel_id = [0xBA; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = 200_000_000u64;
    let traded_ckb = 1_000_000_000u64;
    let extract_ckb = principal_returned + traded_ckb;
    let fee_ckb = 50_000_000u64;
    let total_return = principal_returned + fee_ckb;
    let flags = LPPolicyFlags::empty().with(LPPolicyFlag::EnforceMinFee);

    let mut input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - extract_ckb,
        extract_ckb,
        0,
        58,
    );
    input_lp.policy = lp_policy_with(500, flags);

    let mut output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - extract_ckb + total_return,
        0,
        fee_ckb,
        59,
    );
    output_lp.policy = lp_policy_with(500, flags);

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - extract_ckb,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x5A; 32],
        principal_returned,
        fee_ckb,
        traded_ckb,
        price_x64: 1,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - extract_ckb + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_ok(),
        "settlement should pass when fee equals min-policy boundary"
    );
}

#[test]
fn lp_settle_zero_price_passes_without_require_price_flag() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xAB; 32];
    let channel_id = [0xBB; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = EXTRACT_CKB;
    let fee_ckb = 1u64;
    let total_return = principal_returned + fee_ckb;

    let input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        62,
    );
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB + total_return,
        0,
        fee_ckb,
        63,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - EXTRACT_CKB,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x6B; 32],
        principal_returned,
        fee_ckb,
        traded_ckb: 0,
        price_x64: 0,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_ok(),
        "settlement should pass with zero price_x64 when REQUIRE_PRICE flag is not set"
    );
}

#[test]
fn lp_extract_zero_contribution_id_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA7; 32];
    let channel_id = [0xB7; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 60);
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        61,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());
    let channel_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::FundChannelExtract {
        channel_id,
        contribution_id: [0u8; 32],
        extract_ckb: EXTRACT_CKB,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_auth, channel_input],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: 3_000_000_000u64 + EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: None,
                data: channel_status_data(channel_id),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract must fail when contribution_id is all zeros"
    );
}

#[test]
fn lp_extract_zero_channel_id_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA8; 32];
    let channel_id = [0u8; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 70);
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        71,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());
    let channel_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::FundChannelExtract {
        channel_id,
        contribution_id: [0x11; 32],
        extract_ckb: EXTRACT_CKB,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_auth, channel_input],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: 3_000_000_000u64 + EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: None,
                data: channel_status_data(channel_id),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract must fail when channel_id is all zeros"
    );
}

#[test]
fn lp_settle_zero_contribution_id_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xAC; 32];
    let channel_id = [0xBC; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let principal_returned = EXTRACT_CKB;
    let fee_ckb = 1u64;
    let total_return = principal_returned + fee_ckb;

    let input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        80,
    );
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB + total_return,
        0,
        fee_ckb,
        81,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - EXTRACT_CKB,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_funding = create_auth_cell(
        &mut context,
        AUTH_INPUT_CAP + total_return,
        operator_lock.clone(),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0u8; 32],
        principal_returned,
        fee_ckb,
        traded_ckb: 0,
        price_x64: 1,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_funding],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "settlement must fail when contribution_id is all zeros"
    );
}

#[test]
fn lp_cancel_zero_channel_id_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xAD; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        90,
    );
    let output_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 91);

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());

    let witness = witness_from_pool(PoolWitness::CancelReservation {
        channel_id: [0u8; 32],
        contribution_id: [0x22; 32],
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_auth],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "cancel reservation must fail when channel_id is all zeros"
    );
}

#[test]
fn lp_withdraw_requires_owner_destination() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xAE; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);
    let ckb_out = 1_000_000_000u64;

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 100);
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - ckb_out,
        0,
        0,
        101,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock.clone(),
        lp_type.clone(),
        &input_lp,
    );
    let owner_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, owner_lock);

    let witness = witness_from_pool(PoolWitness::LPWithdraw { ckb_out });

    let tx = build_tx_from_specs(
        vec![lp_input, owner_auth],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - ckb_out,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP + ckb_out,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "withdraw must fail when withdrawn capacity is not returned to owner lock"
    );
}

#[test]
fn lp_extract_rejects_channel_binding_mismatch() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xAF; 32];
    let channel_id = [0xCF; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let other_lock = build_lock(&mut context, &always_success_out_point, 3);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let input_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 110);
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        111,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());
    let channel_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(3_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::FundChannelExtract {
        channel_id,
        contribution_id: [0x33; 32],
        extract_ckb: EXTRACT_CKB,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, operator_auth, channel_input],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: 3_000_000_000u64 + EXTRACT_CKB,
                lock: other_lock,
                type_script: None,
                data: channel_status_data(channel_id),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP,
                lock: operator_lock,
                type_script: None,
                data: Bytes::new(),
            },
        ],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "extract must fail when channel lock/type binding changes between input and output"
    );
}

#[test]
fn lp_init_deposit_succeeds() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xAF; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let output_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 0);

    let funding_input = create_auth_cell(&mut context, LP_IN_CAP, owner_lock.clone());
    let witness = witness_from_pool(PoolWitness::LPDeposit);

    let tx = build_tx_from_specs(
        vec![funding_input],
        vec![TxOutputSpec {
            capacity: LP_IN_CAP,
            lock: owner_lock,
            type_script: Some(lp_type),
            data: Bytes::from(output_lp.encode()),
        }],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES)
        .expect("init deposit should allow LP cell creation");
}

#[test]
fn lp_init_rejects_zero_fee_policy() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xB0; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let mut output_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 0);
    output_lp.policy.fee_rate_bps = 0;

    let funding_input = create_auth_cell(&mut context, LP_IN_CAP, owner_lock.clone());
    let witness = witness_from_pool(PoolWitness::LPDeposit);

    let tx = build_tx_from_specs(
        vec![funding_input],
        vec![TxOutputSpec {
            capacity: LP_IN_CAP,
            lock: owner_lock,
            type_script: Some(lp_type),
            data: Bytes::from(output_lp.encode()),
        }],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "init deposit must reject zero fee_rate_bps policy"
    );
}

#[test]
fn lp_init_rejects_zero_policy_version() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xB1; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let mut output_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 0);
    output_lp.policy.policy_version = 0;

    let funding_input = create_auth_cell(&mut context, LP_IN_CAP, owner_lock.clone());
    let witness = witness_from_pool(PoolWitness::LPDeposit);

    let tx = build_tx_from_specs(
        vec![funding_input],
        vec![TxOutputSpec {
            capacity: LP_IN_CAP,
            lock: owner_lock,
            type_script: Some(lp_type),
            data: Bytes::from(output_lp.encode()),
        }],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "init deposit must reject zero policy_version"
    );
}

#[test]
fn lp_init_rejects_unknown_policy_flag_bits() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xB2; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
    let lp_type = build_lp_type(&mut context, &lp_ts_out_point, pool_id);

    let owner_hash = script_hash_array(&owner_lock);
    let operator_hash = script_hash_array(&operator_lock);

    let mut output_lp = make_lp_cell(pool_id, owner_hash, operator_hash, LP_IN_CAP, 0, 0, 0);
    output_lp.policy.policy_flags = LPPolicyFlags::ALLOWED_MASK | (1 << 8);

    let funding_input = create_auth_cell(&mut context, LP_IN_CAP, owner_lock.clone());
    let witness = witness_from_pool(PoolWitness::LPDeposit);

    let tx = build_tx_from_specs(
        vec![funding_input],
        vec![TxOutputSpec {
            capacity: LP_IN_CAP,
            lock: owner_lock,
            type_script: Some(lp_type),
            data: Bytes::from(output_lp.encode()),
        }],
        vec![lp_ts_dep, always_success_dep],
        witness,
    );

    let tx = context.complete_tx(tx);
    let result = verify_and_dump_failed_tx(&context, &tx, MAX_CYCLES);
    assert!(
        result.is_err(),
        "init deposit must reject policy_flags containing unknown bits"
    );
}
