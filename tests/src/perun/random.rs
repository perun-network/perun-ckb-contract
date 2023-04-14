use rand::Rng;

use super::TestAccount;

pub fn nonce() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let nonce: [u8; 32] = rng.gen();
    nonce
}

pub fn account(name: &str) -> TestAccount {
    TestAccount::new_with_random_key(name.to_string())
}
