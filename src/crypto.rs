use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit,
};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Crypto { cipher }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce_arr = GenericArray::from_slice(&nonce);

        let mut ciphertext = self
            .cipher
            .encrypt(nonce_arr, plaintext)
            .expect("Encryption failed");
        let mut result = nonce.to_vec();
        result.append(&mut ciphertext);

        result
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let (nonce, data) = ciphertext.split_at(12);
        let nonce_arr = GenericArray::from_slice(nonce);
        self.cipher
            .decrypt(nonce_arr, data)
            .expect("Decryption failed")
    }
}

pub fn generate_keys() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn derive_shared_key(secret: EphemeralSecret, peer_public: &PublicKey) -> [u8; 32] {
    let shared_secret = secret.diffie_hellman(peer_public);
    let bytes = shared_secret.as_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    key
}
