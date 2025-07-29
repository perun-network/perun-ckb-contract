use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    elliptic_curve::sec1::EncodedPoint,
    Secp256k1,
};
use sha3::{Digest, Keccak256};

use crate::error::Error;

pub fn verify_signature(msg_hash: &[u8; 32], sig: &[u8], key: &[u8]) -> Result<(), Error> {
    let signature = Signature::from_der(sig)?;
    let e = EncodedPoint::<Secp256k1>::from_bytes(key).expect("unable to decode public key");
    let verifying_key = VerifyingKey::from_encoded_point(&e)?;
    verifying_key.verify_prehash(msg_hash, &signature)?;
    Ok(())
}

/// Replaces `blake2b256(data)` — hashes with Ethereum message prefix
pub fn ethereum_message_hash(data: &[u8]) -> [u8; 32] {
    // First keccak256 hash of the message
    let msg_hash = Keccak256::digest(data);

    // Ethereum message prefix: "\x19Ethereum Signed Message:\n32"
    let mut prefix = b"\x19Ethereum Signed Message:\n32".to_vec();
    prefix.extend_from_slice(&msg_hash);

    // Second keccak256 hash of the prefixed data
    let final_hash = Keccak256::digest(&prefix);

    final_hash
        .as_slice()
        .try_into()
        .expect("Ethereum message hash must be 32 bytes")
}