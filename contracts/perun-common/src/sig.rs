use k256::ecdsa::{recoverable, signature::Signature};

use crate::{error::Error, helpers::blake2b256};

// TODO: This is just a draft!
pub fn recover_signer(msg: &[u8], sig: &[u8]) -> Result<[u8; 33], Error> {
    let msg_hash = blake2b256(msg);
    if sig.len() != 65 {
        return Err(Error::InvalidSignature);
    }
    let sig = recoverable::Signature::from_bytes(sig)
        .expect("Can't fail because size is known at compile time");
    let verifying_key = sig
        .recover_verifying_key_from_digest_bytes(&msg_hash.into())
        .expect("signature verification failed");

    Ok(verifying_key.to_bytes().into())
}
