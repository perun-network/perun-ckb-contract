use ckb_types::packed::Byte as PackedByte;
use k256::ecdsa::VerifyingKey;

pub fn verifying_key_to_packed_byte_array(vk: &VerifyingKey) -> [PackedByte; 65] {
    vk.to_bytes()
        .iter()
        .map(|x| PackedByte::new(*x))
        .collect::<Vec<PackedByte>>()
        .try_into()
        .expect("public-key length 65")
}

pub fn verifying_key_to_byte_array(vk: &VerifyingKey) -> [u8; 65] {
    vk.to_bytes()
        .iter()
        .map(|x| *x)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("public-key length 65")
}
