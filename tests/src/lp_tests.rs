use super::lp_harness::*;
use super::*;
use ckb_testtool::ckb_types::{bytes::Bytes, packed::CellOutput, prelude::*};
use ckb_testtool::context::Context;
use perun_common::pool::PoolWitness;

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
    let settle_channel_id = [0xC1; 32];
    let principal_returned = EXTRACT_CKB;
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

    let operator_auth_settle =
        create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());

    let channel_input_settle = context.create_cell(
        CellOutput::new_builder()
            .capacity(4_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(settle_channel_id),
    );

    let settle_witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id: settle_channel_id,
        contribution_id: [0xE1; 32],
        principal_returned,
        fee_ckb,
        price_x64: 1,
    });

    let settle_tx = build_tx_from_specs(
        vec![lp_input_settle, channel_input_settle, operator_auth_settle],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP + TOPUP_CAP_DELTA - EXTRACT_CKB + total_return,
                lock: owner_lock,
                type_script: Some(lp_type),
                data: Bytes::from(after_settle_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP + 4_000_000_000u64 - total_return,
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
        .expect("settlement insertion with sufficient consumed channel capacity should pass");
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
fn lp_extract_without_owner_signer_fails() {
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
        result.is_err(),
        "extract must fail when owner hash from state does not appear in tx inputs"
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
fn lp_settle_return_exceeds_consumed_channel_fails() {
    let mut context = Context::default();
    let (lp_ts_out_point, lp_ts_dep) = deploy_lp_typescript(&mut context);
    let (always_success_out_point, always_success_dep) = deploy_always_success(&mut context);

    let pool_id = [0xA4; 32];
    let channel_id = [0xB4; 32];
    let owner_lock = build_lock(&mut context, &always_success_out_point, 1);
    let operator_lock = build_lock(&mut context, &always_success_out_point, 2);
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
    let channel_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(EXTRACT_CKB.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x44; 32],
        principal_returned,
        fee_ckb,
        price_x64: 1,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, channel_input, operator_auth],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP + EXTRACT_CKB - total_return,
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
        "settlement must fail when consumed channel capacity is below principal+fee return"
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
    let principal_returned = 1_000_000_000u64;
    let fee_ckb = 60_000_000u64;
    let total_return = principal_returned + fee_ckb;

    let mut input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - principal_returned,
        principal_returned,
        0,
        50,
    );
    input_lp.policy.fee_rate_bps = 500;
    input_lp.policy.policy_flags = 0x1;

    let mut output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - principal_returned + total_return,
        0,
        fee_ckb,
        51,
    );
    output_lp.policy.fee_rate_bps = 500;
    output_lp.policy.policy_flags = 0x1;

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - principal_returned,
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

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x55; 32],
        principal_returned,
        fee_ckb,
        price_x64: 1,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, channel_input, operator_auth],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - principal_returned + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP + 3_000_000_000u64 - total_return,
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

    let input_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB,
        EXTRACT_CKB,
        0,
        52,
    );
    let output_lp = make_lp_cell(
        pool_id,
        owner_hash,
        operator_hash,
        LP_IN_CAP - EXTRACT_CKB + total_return,
        0,
        fee_ckb,
        53,
    );

    let lp_input = create_typed_lp_cell(
        &mut context,
        LP_IN_CAP - EXTRACT_CKB,
        owner_lock,
        lp_type.clone(),
        &input_lp,
    );
    let operator_auth = create_auth_cell(&mut context, AUTH_INPUT_CAP, operator_lock.clone());
    let channel_input = context.create_cell(
        CellOutput::new_builder()
            .capacity(4_000_000_000u64.pack())
            .lock(operator_lock.clone())
            .build(),
        channel_status_data(channel_id),
    );

    let witness = witness_from_pool(PoolWitness::SettleChannelInsert {
        channel_id,
        contribution_id: [0x66; 32],
        principal_returned,
        fee_ckb,
        price_x64: 0,
    });

    let tx = build_tx_from_specs(
        vec![lp_input, channel_input, operator_auth],
        vec![
            TxOutputSpec {
                capacity: LP_IN_CAP - EXTRACT_CKB + total_return,
                lock: operator_lock.clone(),
                type_script: Some(lp_type),
                data: Bytes::from(output_lp.encode()),
            },
            TxOutputSpec {
                capacity: AUTH_INPUT_CAP + 4_000_000_000u64 - total_return,
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
        "settlement must fail when price_x64 is zero"
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
