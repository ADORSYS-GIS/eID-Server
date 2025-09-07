use crate::crypto::SecureBytes;
use crate::crypto::errors::{CryptoResult, Error};
use crate::crypto::utils::{iso_7816_pad, iso_7816_unpad};
use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, Mac};
use openssl::symm::{Cipher as OpenSslCipher, Crypter, Mode};

const AES_BLOCK_SIZE: usize = 16;

type CmacAes128 = Cmac<Aes128>;
type CmacAes192 = Cmac<Aes192>;
type CmacAes256 = Cmac<Aes256>;

/// Represents a symmetric cipher algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-128-CBC cipher
    Aes128Cbc,
    /// AES-192-CBC cipher
    Aes192Cbc,
    /// AES-256-CBC cipher
    Aes256Cbc,
}

impl Cipher {
    /// Get the key size of the cipher in bytes
    pub const fn key_size(self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes192Cbc => 24,
            Self::Aes256Cbc => 32,
        }
    }

    /// Get the block size of the cipher in bytes.
    pub const fn block_size(self) -> usize {
        // AES always has a block size of 16 bytes.
        AES_BLOCK_SIZE
    }

    /// Convert the cipher to an OpenSSL cipher
    pub fn to_openssl_cipher(self) -> OpenSslCipher {
        match self {
            Self::Aes128Cbc => OpenSslCipher::aes_128_cbc(),
            Self::Aes192Cbc => OpenSslCipher::aes_192_cbc(),
            Self::Aes256Cbc => OpenSslCipher::aes_256_cbc(),
        }
    }
}

/// An AES encryptor used for encrypting and decrypting data
#[derive(Debug, Clone)]
pub struct AesEncryptor {
    cipher: Cipher,
}

impl AesEncryptor {
    /// Create a new AES encryptor.
    ///
    /// Uses AES-128-CBC by default. Could be overridden using [`with_cipher`].
    pub const fn new() -> Self {
        Self {
            cipher: Cipher::Aes128Cbc,
        }
    }

    /// Override the cipher used by this encryptor
    pub fn with_cipher(mut self, cipher: Cipher) -> Self {
        self.cipher = cipher;
        self
    }

    /// Encrypt the data using AES-CBC with the given key and IV
    pub fn encrypt(
        &self,
        kenc: &SecureBytes,
        iv: impl AsRef<[u8]>,
        plaintext: impl AsRef<[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        let plaintext_bytes = plaintext.as_ref();
        if plaintext_bytes.is_empty() {
            return Ok(Vec::new());
        }

        // Pad data to AES block size
        let padded_data = iso_7816_pad(plaintext_bytes, self.cipher.block_size());

        let mut encrypter = Crypter::new(
            self.cipher.to_openssl_cipher(),
            Mode::Encrypt,
            kenc.expose_secret(),
            Some(iv.as_ref()),
        )?;
        encrypter.pad(false);

        let mut ciphertext = vec![0u8; padded_data.len() + self.cipher.block_size()];
        let mut count = encrypter.update(&padded_data, &mut ciphertext)?;
        count += encrypter.finalize(&mut ciphertext[count..])?;
        ciphertext.truncate(count);

        Ok(ciphertext)
    }

    /// Decrypt the data using AES-CBC with the given key and IV
    pub fn decrypt(
        &self,
        kdec: &SecureBytes,
        iv: impl AsRef<[u8]>,
        ciphertext: impl AsRef<[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        let ciphertext_bytes = ciphertext.as_ref();
        if ciphertext_bytes.is_empty() {
            return Ok(Vec::new());
        }

        let mut decrypter = Crypter::new(
            self.cipher.to_openssl_cipher(),
            Mode::Decrypt,
            kdec.expose_secret(),
            Some(iv.as_ref()),
        )?;
        decrypter.pad(false);

        let mut plaintext = vec![0u8; ciphertext_bytes.len() + self.cipher.block_size()];
        let mut count = decrypter.update(ciphertext_bytes, &mut plaintext)?;
        count += decrypter.finalize(&mut plaintext[count..])?;
        plaintext.truncate(count);

        Ok(iso_7816_unpad(&plaintext))
    }

    /// Calculate CMAC authentication code for the given data
    pub fn calculate_mac(
        &self,
        kmac: &SecureBytes,
        data: impl AsRef<[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        let key_bytes = kmac.expose_secret();

        let mac_result = match self.cipher {
            Cipher::Aes128Cbc => {
                let mut mac = CmacAes128::new_from_slice(key_bytes)
                    .map_err(|_| Error::Invalid("Wrong key size for AES-128".to_string()))?;
                mac.update(data.as_ref());
                mac.finalize().into_bytes()
            }
            Cipher::Aes192Cbc => {
                let mut mac = CmacAes192::new_from_slice(key_bytes)
                    .map_err(|_| Error::Invalid("Wrong key size for AES-192".to_string()))?;
                mac.update(data.as_ref());
                mac.finalize().into_bytes()
            }
            Cipher::Aes256Cbc => {
                let mut mac = CmacAes256::new_from_slice(key_bytes)
                    .map_err(|_| Error::Invalid("Wrong key size for AES-256".to_string()))?;
                mac.update(data.as_ref());
                mac.finalize().into_bytes()
            }
        };

        Ok(mac_result.to_vec())
    }
}

impl Default for AesEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecureBytes;

    // Test vectors for AES-128-CBC
    const AES128_KEY: &[u8] = &[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    const AES192_KEY: &[u8] = &[
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79,
        0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
    ];

    const AES256_KEY: &[u8] = &[
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ];

    const TEST_IV: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    const TEST_PLAINTEXT: &[u8] = b"Test message for AES encryption.";

    #[test]
    fn test_cipher_key_sizes() {
        assert_eq!(Cipher::Aes128Cbc.key_size(), 16);
        assert_eq!(Cipher::Aes192Cbc.key_size(), 24);
        assert_eq!(Cipher::Aes256Cbc.key_size(), 32);
    }

    #[test]
    fn test_cipher_block_size() {
        assert_eq!(Cipher::Aes128Cbc.block_size(), 16);
        assert_eq!(Cipher::Aes192Cbc.block_size(), 16);
        assert_eq!(Cipher::Aes256Cbc.block_size(), 16);
    }

    #[test]
    fn test_aes_encryptor_new() {
        let encryptor = AesEncryptor::new();
        assert_eq!(encryptor.cipher, Cipher::Aes128Cbc);
    }

    #[test]
    fn test_aes_encryptor_with_cipher() {
        let encryptor = AesEncryptor::new().with_cipher(Cipher::Aes256Cbc);
        assert_eq!(encryptor.cipher, Cipher::Aes256Cbc);
    }

    #[test]
    fn test_aes128_encrypt_decrypt() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new().with_cipher(Cipher::Aes128Cbc);
        let key = SecureBytes::new(AES128_KEY.to_vec());

        let ciphertext = encryptor.encrypt(&key, TEST_IV, TEST_PLAINTEXT)?;
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, TEST_PLAINTEXT);

        let decrypted = encryptor.decrypt(&key, TEST_IV, &ciphertext)?;
        assert_eq!(decrypted, TEST_PLAINTEXT);

        Ok(())
    }

    #[test]
    fn test_aes192_encrypt_decrypt() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new().with_cipher(Cipher::Aes192Cbc);
        let key = SecureBytes::new(AES192_KEY.to_vec());

        let ciphertext = encryptor.encrypt(&key, TEST_IV, TEST_PLAINTEXT)?;
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, TEST_PLAINTEXT);

        let decrypted = encryptor.decrypt(&key, TEST_IV, &ciphertext)?;
        assert_eq!(decrypted, TEST_PLAINTEXT);

        Ok(())
    }

    #[test]
    fn test_aes256_encrypt_decrypt() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new().with_cipher(Cipher::Aes256Cbc);
        let key = SecureBytes::new(AES256_KEY.to_vec());

        let ciphertext = encryptor.encrypt(&key, TEST_IV, TEST_PLAINTEXT)?;
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, TEST_PLAINTEXT);

        let decrypted = encryptor.decrypt(&key, TEST_IV, &ciphertext)?;
        assert_eq!(decrypted, TEST_PLAINTEXT);

        Ok(())
    }

    #[test]
    fn test_encrypt_empty_data() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new();
        let key = SecureBytes::new(AES128_KEY.to_vec());

        let ciphertext = encryptor.encrypt(&key, TEST_IV, &[])?;
        assert!(ciphertext.is_empty());

        Ok(())
    }

    #[test]
    fn test_decrypt_empty_data() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new();
        let key = SecureBytes::new(AES128_KEY.to_vec());

        let plaintext = encryptor.decrypt(&key, TEST_IV, &[])?;
        assert!(plaintext.is_empty());

        Ok(())
    }

    #[test]
    fn test_encrypt_single_byte() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new();
        let key = SecureBytes::new(AES128_KEY.to_vec());
        let single_byte = [0x42];

        let ciphertext = encryptor.encrypt(&key, TEST_IV, &single_byte)?;
        let decrypted = encryptor.decrypt(&key, TEST_IV, &ciphertext)?;

        assert_eq!(decrypted, single_byte);
        Ok(())
    }

    #[test]
    fn test_different_ivs_produce_different_ciphertexts() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new();
        let key = SecureBytes::new(AES128_KEY.to_vec());
        let iv1 = TEST_IV;
        let iv2 = [0xff; 16];

        let ciphertext1 = encryptor.encrypt(&key, iv1, TEST_PLAINTEXT)?;
        let ciphertext2 = encryptor.encrypt(&key, iv2, TEST_PLAINTEXT)?;

        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt to the same plaintext
        let decrypted1 = encryptor.decrypt(&key, iv1, &ciphertext1)?;
        let decrypted2 = encryptor.decrypt(&key, iv2, &ciphertext2)?;

        assert_eq!(decrypted1, TEST_PLAINTEXT);
        assert_eq!(decrypted2, TEST_PLAINTEXT);

        Ok(())
    }

    #[test]
    fn test_calculate_mac_aes128() -> CryptoResult<()> {
        let data = b"test data for MAC calculation";

        let mut encryptor = AesEncryptor::new().with_cipher(Cipher::Aes128Cbc);
        let key_aes128 = SecureBytes::new(AES128_KEY.to_vec());
        let mac_aes128 = encryptor.calculate_mac(&key_aes128, data)?;

        encryptor = encryptor.with_cipher(Cipher::Aes192Cbc);
        let key_aes192 = SecureBytes::new(AES192_KEY.to_vec());
        let mac_aes192 = encryptor.calculate_mac(&key_aes192, data)?;

        encryptor = encryptor.with_cipher(Cipher::Aes256Cbc);
        let key_aes256 = SecureBytes::new(AES256_KEY.to_vec());
        let mac_aes256 = encryptor.calculate_mac(&key_aes256, data)?;

        // Mac output lenght is always 16 bytes for AES
        assert_eq!(mac_aes128.len(), 16);
        assert!(!mac_aes128.is_empty());
        assert_eq!(mac_aes192.len(), 16);
        assert!(!mac_aes192.is_empty());
        assert_eq!(mac_aes256.len(), 16);
        assert!(!mac_aes256.is_empty());

        Ok(())
    }

    #[test]
    fn test_calculate_mac_deterministic() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new();
        let key = SecureBytes::new(AES128_KEY.to_vec());
        let data = b"consistent test data";

        let mac1 = encryptor.calculate_mac(&key, data)?;
        let mac2 = encryptor.calculate_mac(&key, data)?;

        assert_eq!(mac1, mac2);

        Ok(())
    }

    #[test]
    fn test_calculate_mac_different_data() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new();
        let key = SecureBytes::new(AES128_KEY.to_vec());
        let data1 = b"first test data";
        let data2 = b"second test data";

        let mac1 = encryptor.calculate_mac(&key, data1)?;
        let mac2 = encryptor.calculate_mac(&key, data2)?;

        assert_ne!(mac1, mac2);

        Ok(())
    }

    #[test]
    fn test_wrong_key_size_for_cipher() {
        let encryptor = AesEncryptor::new().with_cipher(Cipher::Aes256Cbc);
        // 128-bit key for 256-bit cipher
        let wrong_key = SecureBytes::new(AES128_KEY.to_vec());

        let result = encryptor.encrypt(&wrong_key, TEST_IV, TEST_PLAINTEXT);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic]
    fn test_wrong_iv_size() {
        let encryptor = AesEncryptor::new();
        let key = SecureBytes::new(AES128_KEY.to_vec());
        let wrong_iv = [0u8; 8]; // Wrong IV size (should be 16)

        // OpenSSL panics when the IV size is wrong so we expect a panic
        let _ = encryptor.encrypt(&key, &wrong_iv, TEST_PLAINTEXT);
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new();
        let key = SecureBytes::new(AES128_KEY.to_vec());

        let mut ciphertext = encryptor.encrypt(&key, TEST_IV, TEST_PLAINTEXT)?;

        // Corrupt the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let decrypted = encryptor.decrypt(&key, TEST_IV, &ciphertext)?;

        // Decryption should succeed but produce different plaintext
        assert_ne!(decrypted, TEST_PLAINTEXT);

        Ok(())
    }

    #[test]
    fn test_roundtrip_with_various_data_sizes() -> CryptoResult<()> {
        let encryptor = AesEncryptor::new();
        let key = SecureBytes::new(AES128_KEY.to_vec());

        // Test various data sizes
        let test_sizes = [1, 15, 16, 17, 31, 32, 33, 64, 100];

        for size in test_sizes {
            let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

            let ciphertext = encryptor.encrypt(&key, TEST_IV, &test_data)?;
            let decrypted = encryptor.decrypt(&key, TEST_IV, &ciphertext)?;

            assert_eq!(decrypted, test_data, "Failed for data size: {}", size);
        }

        Ok(())
    }
}
