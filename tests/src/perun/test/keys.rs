use k256::{ecdsa::VerifyingKey, elliptic_curve::sec1::ToEncodedPoint};

pub fn verifying_key_to_byte_array(vk: &VerifyingKey) -> [u8; 33] {
    vk.to_encoded_point(true)
        .as_bytes()
        .iter()
        .map(|x| *x)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("public-key length 33")
}
