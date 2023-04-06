use crate::perun;
use crate::Loader;
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};

// Env contains all chain information required for running Perun
// tests.
pub struct Env {
    // Perun contracts.
    pub pcls_out_point: OutPoint,
    pub pcts_out_point: OutPoint,
    pub pfls_out_point: OutPoint,
    // Auxiliary contracts.
    pub always_success_out_point: OutPoint,
    // Perun scripts.
    pub pcls_script: Script,
    pub pcts_script: Script,
    pub pfls_script: Script,
    pub pcls_script_dep: CellDep,
    pub pcts_script_dep: CellDep,
    pub pfls_script_dep: CellDep,
    // Auxiliary scripts.
    pub always_success_script: Script,
    pub always_success_script_dep: CellDep,
}

// prepare_env prepares the given context to be used for running Perun
// tests.
pub fn prepare_env(context: &mut Context) -> Result<Env, perun::error::Error> {
    // Perun contracts.
    let pcls: Bytes = Loader::default().load_binary("perun-channel-lockscript");
    let pcts: Bytes = Loader::default().load_binary("perun-channel-typescript");
    let pfls: Bytes = Loader::default().load_binary("perun-funds-lockscript");
    // Deploying the contracts returns the cell they are deployed in.
    let pcls_out_point = context.deploy_cell(pcls);
    let pcts_out_point = context.deploy_cell(pcts);
    let pfls_out_point = context.deploy_cell(pfls);
    // Auxiliary contracts.
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // Prepare scripts.
    // Perun scripts.
    let pcls_script = context
        .build_script(&pcls_out_point, Default::default())
        .ok_or("perun-channel-lockscript")?;
    let pcts_script = context
        .build_script(&pcts_out_point, Default::default())
        .ok_or("perun-channel-typescript")?;
    let pfls_script = context
        .build_script(&pfls_out_point, Default::default())
        .ok_or("perun-funds-lockscript")?;
    let pcls_script_dep = CellDep::new_builder()
        .out_point(pcls_out_point.clone())
        .build();
    let pcts_script_dep = CellDep::new_builder()
        .out_point(pcts_out_point.clone())
        .build();
    let pfls_script_dep = CellDep::new_builder()
        .out_point(pfls_out_point.clone())
        .build();
    // Auxiliary scripts.
    let always_success_script = context
        .build_script(&always_success_out_point, Default::default())
        .expect("always_success");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    Ok(Env {
        pcls_out_point,
        pcts_out_point,
        pfls_out_point,
        always_success_out_point,
        pcls_script,
        pcts_script,
        pfls_script,
        pcls_script_dep,
        pcts_script_dep,
        pfls_script_dep,
        always_success_script,
        always_success_script_dep,
    })
}
