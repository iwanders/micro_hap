pub const CHACHA20_POLY1305_KEY_BYTES: usize = 32;
use chacha20poly1305::aead::generic_array::typenum::Unsigned;
use chacha20poly1305::{
    AeadInPlace, ChaCha20Poly1305, Nonce,
    aead::{AeadCore, KeyInit},
};

// TODO: I think 'key' should be sized instead of a slice.

pub fn decrypt<'a>(
    buffer: &'a mut [u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<&'a [u8], chacha20poly1305::Error> {
    type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
    // Unwrap is safe because the key has a constant length and is correctly sized.
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| chacha20poly1305::Error)?;

    // Create the nonce
    let mut nonce_bytes: [u8; NonceSize::USIZE] = Default::default();
    // Non conformant nonce, put the value at the right instead.
    nonce_bytes[NonceSize::USIZE - nonce.len()..].copy_from_slice(nonce);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt.
    let associated_data = &[];
    let mut buffer = BufferSlice::whole(buffer);
    cipher.decrypt_in_place(&nonce, associated_data, &mut buffer)?;
    Ok(buffer.into_buffer_ref())
}

pub fn encrypt<'a>(
    buffer: &'a mut [u8],
    payload_length: usize,
    key: &[u8],
    nonce: &[u8],
) -> Result<&'a [u8], chacha20poly1305::Error> {
    type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;

    let tag = encrypt_aad(&mut buffer[0..payload_length], &[], key, nonce)?;
    if buffer.len() < (payload_length + NonceSize::USIZE) {
        Err(chacha20poly1305::Error)
    } else {
        buffer[payload_length..(payload_length + tag.len())].copy_from_slice(tag.as_slice());
        Ok(&buffer[0..(payload_length + tag.len())])
    }
}

pub fn encrypt_aad<'a>(
    buffer: &'a mut [u8],
    associated_data: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<chacha20poly1305::Tag, chacha20poly1305::Error> {
    type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
    // Unwrap is safe because the key has a constant length and is correctly sized.
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| chacha20poly1305::Error)?;

    // Create the nonce
    let mut nonce_bytes: [u8; NonceSize::USIZE] = Default::default();
    // Non conformant nonce, put the value at the right instead.
    nonce_bytes[NonceSize::USIZE - nonce.len()..].copy_from_slice(nonce);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt.
    let tag = cipher.encrypt_in_place_detached(&nonce, associated_data, buffer)?;
    Ok(tag)
}

//  HAPSessionChannelState
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Copy, Clone, Debug, Default)]
pub struct ControlChannel {
    pub key: [u8; CHACHA20_POLY1305_KEY_BYTES],
    pub nonce: u64,
}
impl ControlChannel {
    pub fn decrypt<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], chacha20poly1305::Error> {
        // Create the nonce
        type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
        let mut nonce_bytes: [u8; NonceSize::USIZE] = Default::default();
        nonce_bytes[4..].copy_from_slice(&self.nonce.to_le_bytes());

        let r = decrypt(buffer, &self.key, &nonce_bytes)?;

        // Increment the nonce.
        self.nonce += 1;

        // Convert the buffer back into the ref.
        Ok(r)
    }
    pub fn encrypt<'a>(
        &mut self,
        buffer: &'a mut [u8],
        payload_length: usize,
    ) -> Result<&'a [u8], chacha20poly1305::Error> {
        // Create the nonce
        type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
        let mut nonce_bytes: [u8; NonceSize::USIZE] = Default::default();
        nonce_bytes[4..].copy_from_slice(&self.nonce.to_le_bytes());

        let r = encrypt(buffer, payload_length, &self.key, &nonce_bytes)?;

        // Increment the nonce.
        self.nonce += 1;
        // Convert the buffer back into the ref.
        Ok(r)
    }
}

pub struct BufferSlice<'a> {
    buffer: &'a mut [u8],
    end: usize,
}
impl<'a> BufferSlice<'a> {
    pub fn whole(buffer: &'a mut [u8]) -> Self {
        let len = buffer.len();
        Self { buffer, end: len }
    }
    pub fn partial(buffer: &'a mut [u8], length: usize) -> Self {
        Self {
            buffer,
            end: length,
        }
    }
    fn into_buffer_ref(self) -> &'a [u8] {
        &self.buffer[0..self.end]
    }
}
impl<'a> chacha20poly1305::aead::Buffer for BufferSlice<'a> {
    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        if (self.end + other.len()) < self.buffer.len() {
            self.buffer[self.end..self.end + other.len()].copy_from_slice(other);
            self.end += other.len();
        } else {
            return Err(chacha20poly1305::aead::Error);
        }
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.end = len;
    }
}
impl<'a> core::convert::AsRef<[u8]> for BufferSlice<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[0..self.end]
    }
}
impl<'a> core::convert::AsMut<[u8]> for BufferSlice<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[0..self.end]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_aead_first_incoming_payload() {
        crate::test::init();
        use chacha20poly1305::aead::generic_array::typenum::Unsigned;
        use chacha20poly1305::{
            AeadInPlace, ChaCha20Poly1305, Nonce,
            aead::{AeadCore, KeyInit},
        };

        // c_to_a key: [66, 52, 2f, e8, f4, 98, dd, fa, d2, 54, 93, d8, 6a, ef, e7, ad, 50, e5, 80, fc, 39, 52, 4e, 12, ca, ea, c3, be, 5d, 36, b1, 30]
        // Raw write data [82, 25, d1, a4, 1f, a, d5, e0, ef, e8, b2, 48, 32, a2, 7c, b6, 62, 39, 74, b6, 31]
        let key = [
            0x66, 0x52, 0x2f, 0xe8, 0xf4, 0x98, 0xdd, 0xfa, 0xd2, 0x54, 0x93, 0xd8, 0x6a, 0xef,
            0xe7, 0xad, 0x50, 0xe5, 0x80, 0xfc, 0x39, 0x52, 0x4e, 0x12, 0xca, 0xea, 0xc3, 0xbe,
            0x5d, 0x36, 0xb1, 0x30,
        ];
        let mut ciphertext: [u8; _] = [
            0x82, 0x25, 0xd1, 0xa4, 0x1f, 0x0a, 0xd5, 0xe0, 0xef, 0xe8, 0xb2, 0x48, 0x32, 0xa2,
            0x7c, 0xb6, 0x62, 0x39, 0x74, 0xb6, 0x31,
        ];
        let orig_ciphertext = ciphertext;

        type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("key should work");
        // let nonce_integer: u64 = 0;
        let nonce_bytes: [u8; NonceSize::USIZE] = Default::default();
        // nonce_bytes[0] = 1;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let associated_data = &[];
        let mut buffer = BufferSlice::whole(&mut ciphertext);
        cipher
            .decrypt_in_place(&nonce, associated_data, &mut buffer)
            .expect("decryption should work");

        assert_eq!(&buffer.as_ref(), &[0x00u8, 0x12, 0x03, 0x11, 0x00]);
        // info!("ciphertext now: {:02?}", buffer.as_ref());
        // info!("ciphertext now: {:02?}", ciphertext);

        let mut decrypted_data_buffer = [0u8; 1024];
        decrypted_data_buffer[0..orig_ciphertext.len()].copy_from_slice(&orig_ciphertext);
        let decrypted_data = decrypt(
            &mut decrypted_data_buffer[0..orig_ciphertext.len()],
            &key,
            &nonce_bytes,
        )
        .unwrap();
        assert_eq!(&decrypted_data, &[0x00u8, 0x12, 0x03, 0x11, 0x00]);

        // And encrypt it back.
        let encrypted_data = encrypt(&mut decrypted_data_buffer, 5, &key, &nonce_bytes).unwrap();
        assert_eq!(&encrypted_data, &orig_ciphertext);
    }

    #[test]
    fn test_aead_control_channel() {
        let key = [
            0x66, 0x52, 0x2f, 0xe8, 0xf4, 0x98, 0xdd, 0xfa, 0xd2, 0x54, 0x93, 0xd8, 0x6a, 0xef,
            0xe7, 0xad, 0x50, 0xe5, 0x80, 0xfc, 0x39, 0x52, 0x4e, 0x12, 0xca, 0xea, 0xc3, 0xbe,
            0x5d, 0x36, 0xb1, 0x30,
        ];
        let ciphertext: [u8; _] = [
            0x82, 0x25, 0xd1, 0xa4, 0x1f, 0x0a, 0xd5, 0xe0, 0xef, 0xe8, 0xb2, 0x48, 0x32, 0xa2,
            0x7c, 0xb6, 0x62, 0x39, 0x74, 0xb6, 0x31,
        ];
        let mut channel = ControlChannel { key, nonce: 0 };

        let mut buffer = ciphertext;
        let v = channel.decrypt(&mut buffer).unwrap();
        assert_eq!(&v, &[0x00u8, 0x12, 0x03, 0x11, 0x00]);
        assert_eq!(channel.nonce, 1);

        let plaintext = [0x00u8, 0x12, 0x03, 0x11, 0x00];

        let mut buffer = [0u8; 32];

        let payload_len = 5;
        buffer[0..payload_len].copy_from_slice(&plaintext);

        let mut channel = ControlChannel { key, nonce: 0 };
        let encrypted = channel.encrypt(&mut buffer, payload_len).unwrap();
        assert_eq!(encrypted, &ciphertext);
    }
    #[test]
    fn test_aead_aad() {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Tests/HAPCryptoTest.c#L102
        //
        let key: [u8; _] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; _] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; _] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext: &[u8; _] =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_tag: [u8; _] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];
        let expected_ciphertext: [u8; _] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];

        let mut ciphertext = *plaintext;

        let tag = encrypt_aad(&mut ciphertext, &aad, &key, &nonce).unwrap();

        let tag_slice = tag.as_slice();
        assert_eq!(tag_slice, expected_tag);
        assert_eq!(ciphertext, expected_ciphertext);
    }
}
