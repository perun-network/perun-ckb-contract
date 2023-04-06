use super::*;
use ckb_testtool::ckb_error::Error;
use ckb_testtool::ckb_types::{
    bytes::Bytes, core::HeaderBuilder, core::TransactionBuilder, packed::*, prelude::*,
};
use ckb_testtool::context::Context;
use perun;
use perun::test;

const MAX_CYCLES: u64 = 10_000_000;

// error numbers
const ERROR_EMPTY_ARGS: i8 = 5;

fn assert_script_error(err: Error, err_code: i8) {
    let error_string = err.to_string();
    assert!(
        error_string.contains(format!("error code {} ", err_code).as_str()),
        "error_string: {}, expected_error_code: {}",
        error_string,
        err_code
    );
}

#[test]
fn test_success() {
    // Deploy contracts into environment.
    let mut context = Context::default();
    let pe = perun::harness::prepare_env(&mut context).expect("preparing environment");

    // Prepare cells.
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(pe.always_success_script.clone())
            .build(),
        Bytes::new(),
    );

    // Prepare transaction fields.
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(pe.always_success_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(pe.always_success_script.clone())
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // Build transaction.
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(pe.always_success_script_dep)
        .build();
    let tx = context.complete_tx(tx);

    // Run transaction.
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn channel_test_bench() {
    [
        test_funding_abort,
        test_multiple_disputes,
        test_successful_funding,
    ]
    .iter()
    .for_each(|test| {
        let mut context = Context::default();
        let pe = perun::harness::prepare_env(&mut context).expect("preparing environment");

        test(&mut context, &pe);
    });
}

fn create_channel_test<P>(
    _context: &mut Context,
    _env: &perun::harness::Env,
    _parts: &[P],
    _test: impl Fn(&mut perun::channel::Channel<P, perun::State>) -> Result<(), perun::Error>,
) {
    // TODO: Implement test creation:
    //
    // Create the test channel struct containing all participants and make sure
    // to prepare the context to allow deploying and using a channel.
}

fn test_funding_abort(context: &mut Context, env: &perun::harness::Env) {
    let parts @ [alice, bob] = ["alice", "bob"];
    let funding_timeout = 10;
    let funding_agreement = test::FundingAgreement::new(parts.len());
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.delay(funding_timeout);

        chan.with(bob)
            .invalid()
            .fund(&funding_agreement)
            .expect("invalid funding channel");

        chan.with(alice).abort().expect("aborting channel");

        chan.assert();
        Ok(())
    });
}

fn test_successful_funding(context: &mut Context, env: &perun::harness::Env) {
    let parts @ [alice, bob] = ["alice", "bob"];
    let funding_agreement = test::FundingAgreement::new(parts.len());
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.assert();
        Ok(())
    });
}

fn test_multiple_disputes(context: &mut Context, env: &perun::harness::Env) {
    let parts @ [alice, bob] = ["alice", "bob"];
    let funding_agreement = test::FundingAgreement::new(parts.len());
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .valid()
            .dispute()
            .expect("disputing channel");

        chan.with(bob).valid().dispute().expect("disputing channel");

        chan.with(alice)
            .invalid()
            .dispute()
            .expect("disputing channel");

        chan.assert();
        Ok(())
    });
}
