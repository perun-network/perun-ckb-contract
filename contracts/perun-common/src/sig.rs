use k256::ecdsa::{VerifyingKey, Signature, signature::{hazmat::PrehashVerifier}};

use crate::{error::Error, helpers::blake2b256};

pub fn verify_signature(msg: &[u8], sig: &[u8], key: &[u8]) -> Result<(), Error> {
    let msg_hash = blake2b256(msg);
    let signature = Signature::from_der(sig)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(key)?;
    verifying_key.verify_prehash(&msg_hash, &signature)?;
    Ok(())
}
