use k256::{ecdsa::SigningKey, PublicKey};
use rand_core::OsRng;
use std::fmt::Debug;

pub trait Account: Debug + Clone {
    fn public_key(&self) -> PublicKey;
    fn name(&self) -> String;
}

#[derive(Clone, Debug)]
pub struct TestAccount {
    pub sk: SigningKey,
    pub name: String,
}

impl TestAccount {
    pub fn new(sk: SigningKey, name: String) -> Self {
        Self { sk, name }
    }

    pub fn new_with_random_key(name: String) -> Self {
        Self {
            sk: SigningKey::random(&mut OsRng),
            name,
        }
    }

    pub fn id(&self) -> &str {
        &self.name
    }
}

impl Account for TestAccount {
    fn public_key(&self) -> PublicKey {
        PublicKey::from(self.sk.verifying_key())
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
