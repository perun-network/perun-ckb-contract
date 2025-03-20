use k256::{ecdsa::{VerifyingKey, Signature, signature::{hazmat::PrehashVerifier}}, elliptic_curve::sec1::EncodedPoint, Secp256k1};

use crate::error::Error;

pub fn verify_signature(msg_hash: &[u8; 32], sig: &[u8], key: &[u8]) -> Result<(), Error> {
    let signature = Signature::from_der(sig)?;
    let e = EncodedPoint::<Secp256k1>::from_bytes(key).expect("unable to decode public key");
    let verifying_key = VerifyingKey::from_encoded_point(&e)?;
    verifying_key.verify_prehash(msg_hash, &signature)?;
    Ok(())
}
