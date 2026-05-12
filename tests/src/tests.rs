use crate::perun::mutators::*;
use crate::perun::random;
use crate::perun::virtual_channel::*;

use super::*;
use ckb_occupied_capacity::Capacity;
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use perun;
use perun::{test, virtual_channel};
use perun_common::perun_types::{
    Allocation, AnyBalances, AnyBalancesUnion, Balances, ChannelState, CKByteDistribution,
    LockedBalances, SubAlloc,
};
use perun_common::sig::ethereum_message_hash;
use perun_common::sol::convert_ckb_state;
use perun_common::{cfalse, ctrue};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

const MAX_CYCLES: u64 = 100 * 10_000_000;
const CHALLENGE_DURATION_MS: u64 = 10 * 1000;

// Include your tests here
// See https://github.com/xxuejie/ckb-native-build-sample/blob/main/tests/src/tests.rs for more examples

#[test]
// TODO: Add mutator to channel state that can be passed to dispute, and close.
fn channel_test_bench() -> Result<(), perun::Error> {
    let res = [
        test_successful_funding_with_udt_and_eth,
        test_funding_abort,
        test_successful_funding_with_udt,
        test_successful_funding_without_udt,
        test_early_force_close,
        test_close,
        test_close_with_eth,
        test_force_close,
        test_multiple_disputes,
        test_multiple_disputes_same_version,
        test_multi_asset_payment,
        test_multi_asset_abort,
        test_multi_asset_abort_zero_sudt_balance,
        test_multi_asset_force_close,
        test_dispute_wrong_signer,
        test_dispute_corrupted_signature,
        test_dispute_version_regression,
        test_dispute_inflated_balances,
        test_eth_payment_and_force_close,
        test_channel_id_matches_ethereum,
    ]
    .iter()
    .map(|test| {
        let mut context = Rc::new(Mutex::new(RefCell::new(Context::default())));
        let pe = perun::harness::Env::new(context.clone(), MAX_CYCLES, CHALLENGE_DURATION_MS)
            .expect("preparing environment");
        test(context, &pe)
    })
    .collect::<Vec<_>>();
    res.into_iter().collect()
}

#[test]
fn channel_vc_test_bench() -> Result<(), perun::Error> {
    let res = [
        test_vc_start,
        test_vc_start2,
        test_vc_progress_no_update,
        test_vc_progress_update1,
        test_vc_progress_update2,
        test_vc_merge,
        test_vc_close1,
        test_close_with_locked_funds,
        test_normal_dispute_with_locked_funds,
        test_vc_close2,
        test_vc_happy,
        test_vc_happy_multi_asset,
        test_vc_happy_with_merge,
        test_vc_happy_multi_asset_with_merge,
    ]
    .iter()
    .map(|test| {
        let context = Rc::new(Mutex::new(RefCell::new(Context::default())));
        let pe = perun::harness::Env::new(context.clone(), MAX_CYCLES, CHALLENGE_DURATION_MS)
            .expect("preparing environment");
        test(context, &pe)
    })
    .collect::<Vec<_>>();
    res.into_iter().collect()
}

fn create_channel_test(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
    parts: &[perun::TestAccount],
    test: impl Fn(&mut perun::channel::Channel<perun::State>) -> Result<(), perun::Error>,
) -> Result<(), perun::Error> {
    let mut chan = perun::channel::Channel::new(context, env, parts);
    test(&mut chan)
}

fn create_vc_channel_test(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
    parts_ai: &[perun::TestAccount],
    parts_bi: &[perun::TestAccount],
    test: impl Fn(
        &mut perun::channel::Channel<perun::State>,
        &mut perun::channel::Channel<perun::State>,
    ) -> Result<(), perun::Error>,
) -> Result<(), perun::Error> {
    // Create channels
    let mut chan_ai = perun::channel::Channel::new(context.clone(), env, parts_ai);
    let mut chan_bi = perun::channel::Channel::new(context.clone(), env, parts_bi);

    // Run the test function with mutable references
    test(&mut chan_ai, &mut chan_bi)
}

fn test_funding_abort(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding_timeout = 10;
    let funding = [
        Capacity::bytes(1000)?.as_u64(),
        Capacity::bytes(1000)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.delay(funding_timeout);

        chan.with(alice).abort().expect("aborting channel");

        chan.assert();
        Ok(())
    })
}

fn test_successful_funding_without_udt(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.assert();
        Ok(())
    })
}

fn test_successful_funding_with_udt_and_eth(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let asset_funding = [20u128, 30u128];
    let eth_funding = [5u128, 10u128]; // ETH amounts
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();
    // FundingAgreement with both UDT and ETH assets
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_assets(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.assert();
        Ok(())
    })
}

fn test_successful_funding_with_udt(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [20u128, 30u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.assert();
        Ok(())
    })
}

fn test_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .finalize()
            .close()
            .expect("closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_close_with_eth(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let asset_funding = [20u128, 30u128]; // UDT amounts
    let eth_funding = [5u128, 10u128]; // ETH amounts

    // Calculate ETH max capacity (sum of eth_funding amounts as u64)
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();

    // Construct FundingAgreement with both UDT and ETH assets
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_assets(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .finalize()
            .close()
            .expect("closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_force_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(bob).dispute().expect("invalid channel dispute");

        chan.delay(env.challenge_duration);

        chan.with(bob).force_close().expect("force closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_early_force_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(bob).dispute().expect("invalid channel dispute");

        chan.with(bob)
            .invalid()
            .force_close()
            .expect("force closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_multiple_disputes_same_version(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
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

        chan.with(bob)
            .invalid()
            .dispute()
            .expect("disputing channel");

        chan.assert();
        Ok(())
    })
}

fn test_multiple_disputes(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
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

        chan.with(bob)
            .valid()
            .update(bump_version())
            .dispute()
            .expect("disputing channel");

        chan.assert();
        Ok(())
    })
}

fn test_multi_asset_payment(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [20u128, 30u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.update(pay_ckbytes(Direction::AtoB, 50));
        chan.update(pay_sudt(Direction::BtoA, 10, 0));

        chan.with(alice)
            .finalize()
            .close()
            .expect("closing channel");

        chan.assert();
        Ok(())
    })
}

pub fn test_multi_asset_abort(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [Capacity::bytes(0)?.as_u64(), Capacity::bytes(0)?.as_u64()];
    let asset_funding = [30u128, 20u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(alice).abort().expect("aborting channel");

        chan.assert();
        Ok(())
    })
}

pub fn test_multi_asset_abort_zero_sudt_balance(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [Capacity::bytes(0)?.as_u64(), Capacity::bytes(0)?.as_u64()];
    let asset_funding = [0u128, 0u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(alice).abort().expect("aborting channel");

        chan.assert();
        Ok(())
    })
}

fn test_multi_asset_force_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [20u128, 30u128];
    let funding_agreement = test::FundingAgreement::new_with_capacities_and_sudt(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");

        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.update(pay_ckbytes(Direction::AtoB, 50));
        chan.update(pay_sudt(Direction::BtoA, 10, 0));

        chan.with(bob).dispute().expect("disputing channel");

        chan.delay(env.challenge_duration);

        chan.with(bob).force_close().expect("force closing channel");

        chan.assert();
        Ok(())
    })
}

fn test_vc_start(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_START");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// register a disupte for a lc state without locked funds
// followed by a dispute for the virtual channel with  lc state having locked funds
fn test_vc_start2(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_START2");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            chan_ai.with(alice).dispute().expect("invalid dispute");

            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_ai
                .with(alice)
                .vc_start(&mut vc_ab)
                .expect("invalid vc_start");
            chan_ai.assert();
            Ok(())
        },
    )
}

fn test_vc_progress_no_update(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_PROGRESS_NO_UPDATE");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            println!("opening vc dispute no progress on C_BI using Ingrid");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// state update in vc but no update in lc
fn test_vc_progress_update1(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_PROGRESS_UPDATE1");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// state updates for both lc and vc
fn test_vc_progress_update2(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_PROGRESS_UPDATE2");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));
            //simulate state update for lc
            chan_ai.with(alice).update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_lc_update(&mut vc_ab)
                .expect("vc_lc_update");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_merge(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    let delay = 10u64;

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_MERGE");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let nonce = random::nonce();
            //First vc cell is created by Alice so she is the owner
            let owner_participants1 = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_alice = owner_participants1.get(0).unwrap();

            let mut vc_ab_1 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_alice,
            );
            //Second owner is Bob so he is the owner of second vc cell
            let owner_participants1 = funding_agreement_bi.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_bob = owner_participants1.get(0).unwrap();
            let mut vc_ab_2 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_bob,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_1.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_2.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai
                .with(alice)
                .vc_start(&mut vc_ab_1)
                .expect("vc_start by alice using C_AI");
            chan_bi.delay(delay);
            chan_bi
                .with(bob)
                .vc_start(&mut vc_ab_2)
                .expect("vc_start by bob using C_BI");

            chan_bi
                .with(ingrid)
                .vc_merge(&vc_ab_1, &vc_ab_2, 0u8)
                .expect("vc_merge");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_close1(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_CLOSE1");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_with_dir = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_with_dir)
                .expect("vc_close1");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// test that contract doesn't allow to close a lc cell with locked funds.
fn test_close_with_locked_funds(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_CLOSE_WITH_LOCKED_FUNDS");
            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);

            chan_ai
                .with(alice)
                .invalid()
                .finalize()
                .close()
                .expect("closing channel");

            chan_ai.assert();
            Ok(())
        },
    )
}

// test that contract doesn't allow to register a normal dispute for a lc state having locked funds
fn test_normal_dispute_with_locked_funds(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_NORMAL_DISPUTE_WITH_LOCKED_FUNDS");
            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_ai
                .with(alice)
                .invalid()
                .dispute()
                .expect("invalid dispute");
            chan_ai.assert();
            Ok(())
        },
    )
}

fn test_vc_close2(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_CLOSE2");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY");
            chan_ai
                .with(alice)
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy_multi_asset(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [50u128, 50u128];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let asset_funding_vc = [20u128, 20u128];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ai
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_bi
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ab
            .iter()
            .cloned()
            .zip(asset_funding_vc.iter().cloned())
            .collect(),
    );
    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY_MULTI_ASSET");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            //Alice sends vc_start to tx and is thus the owner
            let owner_participants = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner = owner_participants.get(0).unwrap();

            let mut vc_ab = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &random::nonce(),
                &owner,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai.with(alice).vc_start(&mut vc_ab).expect("vc_start");
            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab)
                .expect("vc_progress_no_update");
            // simulate state update for vc
            vc_ab.update(pay_ckbytes(Direction::AtoB, 30));
            vc_ab.update(pay_sudt(Direction::AtoB, 10, 0));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy_with_merge(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
    );

    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };
    let delay = 10u64;
    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY_WITH_MERGE");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let nonce = random::nonce();
            //First vc cell is created by Alice so she is the owner
            let owner_participants1 = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_alice = owner_participants1.get(0).unwrap();

            let mut vc_ab_1 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_alice,
            );
            //Second owner is Bob so he is the owner of second vc cell
            let owner_participants1 = funding_agreement_bi.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_bob = owner_participants1.get(0).unwrap();
            let mut vc_ab_2 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_bob,
            );
            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_1.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_2.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai
                .with(alice)
                .vc_start(&mut vc_ab_1)
                .expect("vc_start");
            chan_bi.delay(delay);

            chan_bi.with(bob).vc_start(&mut vc_ab_2).expect("vc_start");

            let result = chan_bi
                .with(ingrid)
                .vc_merge(&vc_ab_1, &vc_ab_2, 0u8)
                .expect("vc_merge");

            vc_ab_1.set_cell(result);

            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab_1)
                .expect("vc_progress_no_update");

            // simulate state update for vc
            vc_ab_1.update(pay_ckbytes(Direction::AtoB, 30));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab_1)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab_1, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab_1, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

fn test_vc_happy_multi_asset_with_merge(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob, ingrid) = ("alice", "bob", "ingrid");
    let alice_acc = random::account(alice);
    let bob_acc = random::account(bob);
    let ingrid_acc = random::account(ingrid);

    let parts_ai = [alice_acc.clone(), ingrid_acc.clone()];
    let parts_bi = [bob_acc.clone(), ingrid_acc.clone()];
    let parts_ab = [alice_acc.clone(), bob_acc.clone()];

    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [50u128, 50u128];

    let funding_vc = [Capacity::bytes(50)?.as_u64(), Capacity::bytes(50)?.as_u64()];

    let asset_funding_vc = [20u128, 20u128];

    let funding_agreement_ai = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_ai
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ai
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_bi = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_bi
            .iter()
            .cloned()
            .zip(funding.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_bi
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
    );

    let funding_agreement_ab = test::FundingAgreement::new_with_capacities_and_sudt(
        parts_ab
            .iter()
            .cloned()
            .zip(funding_vc.iter().cloned())
            .collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts_ab
            .iter()
            .cloned()
            .zip(asset_funding_vc.iter().cloned())
            .collect(),
    );
    // Alice is proposer of C_AI
    // Bob is proposer of C_IB
    // Alice is proposer of VC_AB
    // Parent1 is C_AI and Parent2 is C_IB
    // idx_map maps participant roles from vc to lc
    let idx_map = virtual_channel::VCIndexMap {
        parent1: [0u8, 1u8],
        parent2: [1u8, 0u8],
    };

    create_vc_channel_test(
        context.clone(),
        env,
        &parts_ai,
        &parts_bi,
        |chan_ai, chan_bi| {
            println!("TEST_VC_HAPPY_MULTI_ASSET_WITH_MERGE");
            chan_ai
                .with(alice) //use borrow_mut in case of Rc cell
                .open(&funding_agreement_ai)
                .expect("opening channel");

            chan_bi
                .with(bob)
                .open(&funding_agreement_bi)
                .expect("opening channel");

            chan_ai
                .with(ingrid)
                .fund(&funding_agreement_ai)
                .expect("funding channel");

            chan_bi
                .with(ingrid)
                .fund(&funding_agreement_bi)
                .expect("funding channel");

            let ctx = match context.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let nonce = random::nonce();
            //First vc cell is created by Alice so she is the owner
            let owner_participants1 = funding_agreement_ai.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_alice = owner_participants1.get(0).unwrap();

            let mut vc_ab_1 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_alice,
            );
            //Second owner is Bob so he is the owner of second vc cell
            let owner_participants1 = funding_agreement_bi.mk_participants(
                &mut ctx.borrow_mut(),
                env,
                env.min_capacity_no_script,
            );
            let owner_bob = owner_participants1.get(0).unwrap();
            let mut vc_ab_2 = perun::virtual_channel::VirtualChannel::new(
                &mut ctx.borrow_mut(),
                env,
                &parts_ab,
                &funding_agreement_ab,
                &chan_ai,
                &chan_bi,
                &idx_map,
                &nonce,
                &owner_bob,
            );

            drop(ctx);
            // Simulate creating virtual channels
            chan_ai.with(alice).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_1.id().clone(),
                &idx_map.parent1,
            ));
            chan_bi.with(ingrid).update(update_virtual_channel(
                &funding_agreement_ab,
                vc_ab_2.id().clone(),
                &idx_map.parent2,
            ));

            chan_ai
                .with(alice)
                .vc_start(&mut vc_ab_1)
                .expect("vc_start");
            chan_bi.delay(10u64);
            chan_bi.with(bob).vc_start(&mut vc_ab_2).expect("vc_start");

            let result = chan_bi
                .with(ingrid)
                .vc_merge(&vc_ab_1, &vc_ab_2, 0u8)
                .expect("vc_merge");
            vc_ab_1.set_cell(result);

            chan_bi
                .with(ingrid)
                .vc_progress_no_update(&mut vc_ab_1)
                .expect("vc_progress_no_update");
            // simulate state update for vc
            vc_ab_1.update(pay_ckbytes(Direction::AtoB, 30));
            vc_ab_1.update(pay_sudt(Direction::AtoB, 10, 0));

            // Alice posts higher version of vc state to the chain
            chan_ai
                .with(alice)
                .vc_update_only(&mut vc_ab_1)
                .expect("only_vc_update");

            chan_ai.delay(env.challenge_duration);
            chan_ai.delay(env.challenge_duration);
            let idx_map_parent1 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(0 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_ai
                .with(alice)
                .vc_close1(&mut vc_ab_1, &idx_map_parent1)
                .expect("vc_close1");

            let idx_map_parent2 = virtual_channel::IdxMapWithDirection {
                idx_map: idx_map.clone().invert_map(1 as usize),
                direction: IdxMapDirection::LedgerChannelToVirtualChannel,
            };
            chan_bi
                .with(ingrid)
                .vc_close2(&mut vc_ab_1, &idx_map_parent2)
                .expect("vc_close2");
            chan_ai.assert();
            chan_bi.assert();
            Ok(())
        },
    )
}

// =============================================================================
// Security tests: signature forgery, version regression, balance inflation
// =============================================================================

fn test_dispute_wrong_signer(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    let carol = random::account("carol");
    let carol_client = test::Client::new(2, "carol".into(), carol.sk.clone());

    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        let alice_client = test::Client::new(0, "alice".into(), parts[0].sk.clone());
        let sig_a = alice_client.sign(chan.state().state())?;
        let sig_carol = carol_client.sign(chan.state().state())?;

        chan.with(alice)
            .invalid()
            .dispute_with_custom_sigs([sig_a, sig_carol])
            .expect("dispute with wrong signer must fail");
        Ok(())
    })
}

fn test_dispute_corrupted_signature(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        let alice_client = test::Client::new(0, "alice".into(), parts[0].sk.clone());
        let bob_client = test::Client::new(1, "bob".into(), parts[1].sk.clone());
        let sig_a = alice_client.sign(chan.state().state())?;
        let mut sig_b = bob_client.sign(chan.state().state())?;
        if sig_b.len() > 10 {
            sig_b[10] ^= 0xff;
        }

        chan.with(alice)
            .invalid()
            .dispute_with_custom_sigs([sig_a, sig_b])
            .expect("dispute with corrupted signature must fail");
        Ok(())
    })
}

fn test_dispute_version_regression(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .valid()
            .update(bump_version())
            .update(bump_version())
            .dispute()
            .expect("valid dispute at version 2");

        chan.with(bob)
            .invalid()
            .update(set_version(1))
            .dispute()
            .expect("dispute with version regression must fail");
        Ok(())
    })
}

fn test_dispute_inflated_balances(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let funding_agreement = test::FundingAgreement::new_with_capacities(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
    );
    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .invalid()
            .update(inflate_ckbytes(0, Capacity::bytes(50)?.as_u64()))
            .dispute()
            .expect("dispute with inflated balances must fail");
        Ok(())
    })
}

fn test_eth_payment_and_force_close(
    context: Rc<Mutex<RefCell<Context>>>,
    env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let (alice, bob) = ("alice", "bob");
    let parts = [random::account(alice), random::account(bob)];
    let funding = [
        Capacity::bytes(100)?.as_u64(),
        Capacity::bytes(100)?.as_u64(),
    ];
    let asset_funding = [20u128, 30u128];
    let eth_funding = [50u128, 50u128];
    let eth_chain_id = eth_funding.iter().cloned().sum::<u128>();

    let funding_agreement = test::FundingAgreement::new_with_capacities_and_assets(
        parts.iter().cloned().zip(funding.iter().cloned()).collect(),
        &env.sample_udt_script,
        env.sample_udt_max_cap.as_u64(),
        parts
            .iter()
            .cloned()
            .zip(asset_funding.iter().cloned())
            .collect(),
        eth_chain_id,
        parts
            .iter()
            .cloned()
            .zip(eth_funding.iter().cloned())
            .collect(),
    );

    create_channel_test(context, env, &parts, |chan| {
        chan.with(alice)
            .open(&funding_agreement)
            .expect("opening channel");
        chan.with(bob)
            .fund(&funding_agreement)
            .expect("funding channel");

        chan.with(alice)
            .update(pay_eth(Direction::AtoB, 20, 0))
            .dispute()
            .expect("dispute after ETH payment");

        chan.delay(env.challenge_duration);

        chan.with(alice)
            .force_close()
            .expect("force close after ETH payment");

        chan.assert();
        Ok(())
    })
}

fn test_channel_id_matches_ethereum(
    _context: Rc<Mutex<RefCell<Context>>>,
    _env: &perun::harness::Env,
) -> Result<(), perun::Error> {
    let balances = Balances::new_builder()
        .assets(
            Allocation::new_builder()
                .push(
                    AnyBalances::new_builder()
                        .set(AnyBalancesUnion::CKByteDistribution(
                            CKByteDistribution::new_builder()
                                .set([100u64.pack(), 200u64.pack()])
                                .build(),
                        ))
                        .build(),
                )
                .build(),
        )
        .locked(LockedBalances::new_builder().push(SubAlloc::new_builder().build()).build())
        .build();

    let state = ChannelState::new_builder()
        .channel_id(Byte32::zero())
        .balances(balances)
        .version(1u64.pack())
        .is_final(Bool::from_bool(false))
        .build();

    let state_eth = convert_ckb_state(&state);
    let encoded = state_eth.abi_encode();
    let hash = ethereum_message_hash(&encoded);

    assert_eq!(hash.len(), 32);
    let hash2 = ethereum_message_hash(&convert_ckb_state(&state).abi_encode());
    assert_eq!(hash, hash2, "state encoding must be deterministic");
    assert!(encoded.iter().any(|&b| b != 0), "ABI encoding must not be empty");
    assert!(encoded.len() > 64, "ABI encoding must contain actual data");
    Ok(())
}
