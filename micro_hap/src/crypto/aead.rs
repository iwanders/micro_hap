#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_first_incoming_payload() {
        crate::test::init();
        use chacha20poly1305::aead::generic_array::typenum::Unsigned;
        use chacha20poly1305::{
            AeadInPlace, ChaCha20Poly1305, Nonce,
            aead::{AeadCore, KeyInit},
        };

        struct BufferSlice<'a> {
            buffer: &'a mut [u8],
            end: usize,
        }
        impl<'a> BufferSlice<'a> {
            pub fn new(buffer: &'a mut [u8]) -> Self {
                let len = buffer.len();
                Self { buffer, end: len }
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
        type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("key should work");
        // let nonce_integer: u64 = 0;
        let nonce_bytes: [u8; NonceSize::USIZE] = Default::default();
        // nonce_bytes[0] = 1;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let associated_data = &[];
        let mut buffer = BufferSlice::new(&mut ciphertext);
        cipher
            .decrypt_in_place(&nonce, associated_data, &mut buffer)
            .expect("decryption should work");

        assert_eq!(&buffer.as_ref(), &[0x00u8, 0x12, 0x03, 0x11, 0x00]);
        info!("ciphertext now: {:0>2x?}", buffer.as_ref());
        info!("ciphertext now: {:0>2x?}", ciphertext);
    }
}
