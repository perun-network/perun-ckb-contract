use k256::ecdsa::{recoverable, signature::Signature};

use crate::error::Error;

// TODO: This is just a draft!
pub fn recover_signer(msg: &[u8; 32], sig: &[u8; 65]) -> Result<[u8; 33], Error> {
    let sig = recoverable::Signature::from_bytes(sig)
        .expect("Can't fail because size is known at compile time");
    let verifying_key = sig
        .recover_verifying_key_from_digest_bytes(msg.into())
        .expect("signature verification failed");

    Ok(verifying_key.to_bytes().into())
}
