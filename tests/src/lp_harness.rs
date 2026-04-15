use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder, TransactionView},
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
use perun_common::perun_types::{Bool, ChannelStatus};
use perun_common::pool::{LPCell, LPPolicy, PoolWitness};
use std::env;
use std::fs;
use std::path::PathBuf;

pub const MAX_CYCLES: u64 = 100 * 10_000_000;
pub const LP_IN_CAP: u64 = 20_000_000_000;
pub const TOPUP_CAP_DELTA: u64 = 5_000_000_000;
pub const AUTH_INPUT_CAP: u64 = 10_000_000_000;
pub const EXTRACT_CKB: u64 = 2_000_000_000;

#[derive(Clone)]
pub struct TxOutputSpec {
    pub capacity: u64,
    pub lock: Script,
    pub type_script: Option<Script>,
    pub data: Bytes,
}

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

pub fn deploy_lp_typescript(
    context: &mut Context,
) -> (ckb_testtool::ckb_types::packed::OutPoint, CellDep) {
    let lp_ts_bin = load_lp_typescript_binary().expect(
        "LP typescript binary is missing. Build liquidity-pool-typescript artifacts before running LP e2e tests.",
    );
    let out_point = context.deploy_cell(lp_ts_bin);
    let dep = CellDep::new_builder().out_point(out_point.clone()).build();
    (out_point, dep)
}

pub fn deploy_lp_lockscript(
    context: &mut Context,
) -> (ckb_testtool::ckb_types::packed::OutPoint, CellDep) {
    let lp_ls_bin = load_lp_lockscript_binary().expect(
        "LP lockscript binary is missing. Build liquidity-pool-lockscript artifacts before running LP e2e tests.",
    );
    let out_point = context.deploy_cell(lp_ls_bin);
    let dep = CellDep::new_builder().out_point(out_point.clone()).build();
    (out_point, dep)
}

pub fn deploy_always_success(
    context: &mut Context,
) -> (ckb_testtool::ckb_types::packed::OutPoint, CellDep) {
    let out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let dep = CellDep::new_builder().out_point(out_point.clone()).build();
    (out_point, dep)
}

pub fn build_lock(
    context: &mut Context,
    always_success_out_point: &ckb_testtool::ckb_types::packed::OutPoint,
    tag: u8,
) -> Script {
    context
        .build_script(always_success_out_point, Bytes::from(vec![tag]))
        .expect("build lock script")
}

pub fn lp_policy() -> LPPolicy {
    LPPolicy {
        max_trading_volume: 0,
        fee_rate_bps: 30,
        policy_flags: 0,
        policy_version: 1,
    }
}

pub fn script_hash_array(script: &Script) -> [u8; 32] {
    script.calc_script_hash().unpack()
}

pub fn build_lp_lock(
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

pub fn build_lp_type(
    context: &mut Context,
    lp_typescript_out_point: &ckb_testtool::ckb_types::packed::OutPoint,
    pool_id: [u8; 32],
) -> Script {
    context
        .build_script_with_hash_type(
            lp_typescript_out_point,
            ScriptHashType::Data1,
            Bytes::from(pool_id.to_vec()),
        )
        .expect("build lp typescript")
}

pub fn make_lp_cell(
    pool_id: [u8; 32],
    owner_lock_hash: [u8; 32],
    operator_lock_hash: [u8; 32],
    available_ckb: u64,
    reserved_ckb: u64,
    cumulative_fees_earned_ckb: u64,
    nonce: u64,
) -> LPCell {
    LPCell {
        pool_id,
        owner_lock_hash,
        operator_lock_hash,
        available_ckb,
        reserved_ckb,
        cumulative_fees_earned_ckb,
        policy: lp_policy(),
        nonce,
        active: true,
    }
}

pub fn create_typed_lp_cell(
    context: &mut Context,
    capacity: u64,
    lock: Script,
    type_script: Script,
    lp_cell: &LPCell,
) -> ckb_testtool::ckb_types::packed::OutPoint {
    context.create_cell(
        CellOutput::new_builder()
            .capacity(capacity.pack())
            .lock(lock)
            .type_(Some(type_script).pack())
            .build(),
        Bytes::from(lp_cell.encode()),
    )
}

pub fn create_auth_cell(
    context: &mut Context,
    capacity: u64,
    lock: Script,
) -> ckb_testtool::ckb_types::packed::OutPoint {
    context.create_cell(
        CellOutput::new_builder()
            .capacity(capacity.pack())
            .lock(lock)
            .build(),
        Bytes::new(),
    )
}

pub fn witness_from_pool(pool_witness: PoolWitness) -> WitnessArgs {
    WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(pool_witness.encode())).pack())
        .build()
}

pub fn build_tx_from_specs(
    inputs: Vec<OutPoint>,
    outputs: Vec<TxOutputSpec>,
    cell_deps: Vec<CellDep>,
    witness: WitnessArgs,
) -> TransactionView {
    let inputs = inputs
        .into_iter()
        .map(|previous_output| {
            CellInput::new_builder()
                .previous_output(previous_output)
                .build()
        })
        .collect::<Vec<_>>();

    let outputs_data = outputs
        .iter()
        .map(|o| o.data.clone().pack())
        .collect::<Vec<_>>();

    let outputs = outputs
        .into_iter()
        .map(|o| {
            CellOutput::new_builder()
                .capacity(o.capacity.pack())
                .lock(o.lock)
                .type_(o.type_script.pack())
                .build()
        })
        .collect::<Vec<_>>();

    TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data)
        .cell_deps(cell_deps)
        .witness(witness.as_bytes().pack())
        .build()
}

pub fn channel_status_data(channel_id: [u8; 32]) -> Bytes {
    channel_status_data_with_flags(channel_id, false, false)
}

pub fn channel_status_data_with_flags(
    channel_id: [u8; 32],
    disputed: bool,
    is_final: bool,
) -> Bytes {
    let base = ChannelStatus::default();
    let state = base
        .state()
        .as_builder()
        .channel_id(Byte32::from_slice(&channel_id).expect("channel id"))
        .is_final(Bool::from_bool(is_final))
        .build();
    let status = base
        .as_builder()
        .state(state)
        .disputed(Bool::from_bool(disputed))
        .build();
    status.as_bytes()
}
