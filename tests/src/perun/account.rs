use k256::{ecdsa::SigningKey, PublicKey};
use rand_core::OsRng;
use sha3::{Digest, Keccak256};
use std::fmt::Debug;

pub trait Account: Debug + Clone {
    fn public_key(&self) -> PublicKey;
    fn name(&self) -> String;
    fn eth_pub_key(&self) -> Vec<u8>;
}

#[derive(Clone, Debug)]
pub struct TestAccount {
    pub sk: SigningKey,
    pub name: String,
    pub eth_pubkey: Vec<u8>,
}

impl TestAccount {
    pub fn _new(sk: SigningKey, name: String, eth_pubkey: Vec<u8>) -> Self {
        Self {
            sk,
            name,
            eth_pubkey,
        }
    }

    pub fn new_with_random_key(name: String) -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let pubkey_bytes: Vec<u8> = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let eth_pubkey = pubkey_bytes[1..].to_vec();

        Self {
            sk,
            name,
            eth_pubkey,
        }
    }

    pub fn _id(&self) -> &str {
        &self.name
    }

    pub fn eth_address(&self) -> String {
        let hash = Keccak256::digest(&self.eth_pub_key());
        let addr = &hash[12..];
        format!("0x{}", hex::encode(addr))
    }
}

impl Account for TestAccount {
    fn public_key(&self) -> PublicKey {
        PublicKey::from(self.sk.verifying_key())
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn eth_pub_key(&self) -> Vec<u8> {
        let encoded_point = self.sk.verifying_key().to_encoded_point(false);
        let pk_bytes = encoded_point.as_bytes();
        pk_bytes[1..].to_vec()
    }
}
