// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairing.h#L56
//
//
//
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairing.h#L122
//
// use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};
//

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c

// Okay, this is some six step process...
// The reference effectively uses two methods as entry points:
// HAPPairingPairSetupHandleWrite at:
//   https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L1209
// and
// HAPPairingPairSetupHandleRead at:
//   https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L1377C10-L1377C39
//
// It's probably a good idea to follow that structure such that we can easily follow the code and if need be introspect
// the data in intermediate stages in the reference.

use uuid;

pub const CHACHA20_POLY1305_KEY_BYTES: usize = 32;
pub const X25519_SCALAR_BYTES: usize = 32;
pub const X25519_BYTES: usize = 32;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct PairingId(pub uuid::Uuid);

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct PairingPublicKey(pub [u8; 32]);

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct Pairing {
    pub id: PairingId,
    // NONCOMPLIANCE; Why do we have a numIdentifierBytes here??
    pub public_key: PairingPublicKey,
    pub permissions: u8,
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPSession.h#L116
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct PairSetup {
    pub state: PairState,
    pub method: u8,
    pub error: u8,
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPSession.h#L127
pub struct PairVerify {
    pub setup: PairSetup,
    pub session_key: [u8; CHACHA20_POLY1305_KEY_BYTES],
    pub cv_pk: [u8; X25519_BYTES],
    pub cv_sk: [u8; X25519_SCALAR_BYTES],
    pub cv_key: [u8; X25519_BYTES],
    pub pairing_id: usize,
    pub controller_cv_pk: [u8; X25519_BYTES],
}

#[repr(u8)]
pub enum PairingMethod {
    /// Pair Setup.
    PairSetup = 0x00,

    /// Pair Setup with Auth.
    PairSetupWithAuth = 0x01,

    /// Pair Verify.
    PairVerify = 0x02,

    /// Add Pairing.
    AddPairing = 0x03,

    /// Remove Pairing.
    RemovePairing = 0x04,

    /// List Pairings.
    ListPairings = 0x05,

    ///Pair Resume.
    //@see HomeKit Accessory Protocol Specification R14 Table 7-38 Defines Description
    PairResume = 0x06,
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairing.h#L122
#[repr(u8)]
pub enum TLVType {
    /**
     * Method to use for pairing.
     * integer.
     */
    Method = 0x00,

    /**
     * Identifier for authentication.
     * UTF-8.
     */
    Identifier = 0x01,

    /**
     * 16+ bytes of random salt.
     * bytes.
     */
    Salt = 0x02,

    /**
     * Curve25519, SRP public key, or signed Ed25519 key.
     * bytes.
     */
    PublicKey = 0x03,

    /**
     * Ed25519 or SRP proof.
     * bytes.
     */
    Proof = 0x04,

    /**
     * Encrypted data with auth tag at end.
     * bytes.
     */
    EncryptedData = 0x05,

    /**
     * State of the pairing process. 1=M1, 2=M2, etc.
     * integer.
     */
    State = 0x06,

    /**
     * Error code. Must only be present if error code is not 0.
     * integer.
     */
    Error = 0x07,

    /**
     * Seconds to delay until retrying a setup code.
     * integer.
     *
     * @remark Obsolete since R3.
     */
    RetryDelay = 0x08,

    /**
     * X.509 Certificate.
     * bytes.
     */
    Certificate = 0x09,

    /**
     * Ed25519 or Apple Authentication Coprocessor signature.
     * bytes.
     */
    Signature = 0x0A,

    /**
     * Bit value describing permissions of the controller being added.
     * None (0x00): Regular user
     * Bit 1 (0x01): Admin that is able to add and remove pairings against the
     * accessory. integer.
     */
    Permissions = 0x0B,

    /**
     * Non-last fragment of data. If length is 0, it's an ACK.
     * bytes.
     *
     * @remark Obsolete since R7.
     *
     * @see HomeKit Accessory Protocol Specification R6
     *      Section 3.8 Fragmentation and Reassembly
     */
    FragmentData = 0x0C,

    /**
     * Last fragment of data.
     * bytes.
     *
     * @remark Obsolete since R7.
     *
     * @see HomeKit Accessory Protocol Specification R6
     *      Section 3.8 Fragmentation and Reassembly
     */
    FragmentLast = 0x0D,

    /**
     * Identifier to resume a session.
     *
     * @see HomeKit Accessory Protocol Specification R14
     *      Table 7-38 Defines Description
     */
    SessionID = 0x0E,

    /**
     * Pairing Type Flags (32 bit unsigned integer).
     * integer.
     */
    Flags = 0x13,

    /**
     * Zero-length TLV that separates different TLVs in a list.
     * null.
     */
    Separator = 0xFF,
}
impl Into<u8> for TLVType {
    fn into(self) -> u8 {
        self as u8
    }
}

pub struct TLVMethod<'a>(TLV<'a>);
impl<'a> TLVMethod<'a> {
    pub fn tied(data: &'a [u8]) -> Self {
        Self(TLV::tied(data, TLVType::Method))
    }
}
impl<'a> core::ops::Deref for TLVMethod<'a> {
    type Target = TLV<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<'a> core::ops::DerefMut for TLVMethod<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Default, PartialEq, Eq, Debug, Copy, Clone)]
#[repr(u8)]
pub enum PairState {
    #[default]
    NotStarted = 0,
    //ReceivedM1 = 1,
}

use crate::tlv::{TLV, TLVReader};
// HAPPairingPairSetupHandleWrite
pub fn pair_setup_handle_incoming(setup: &mut PairSetup, data: &[u8]) -> Result<(), ()> {
    let _ = data;
    match setup.state {
        PairState::NotStarted => {
            let mut a = TLVMethod::tied(&data);
            let mut b = TLV::tied(&data, 0x06);

            let collected = TLVReader::new(&data).read_into(&mut [&mut a, &mut b]);
        }
    }
    Ok(())
}

// HAPPairingPairSetupHandleRead
pub fn pair_setup_handle_outgoing(setup: &mut PairSetup, data: &mut [u8]) -> Result<usize, ()> {
    let _ = data;
    let _ = setup;
    Ok(0)
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L48
pub fn pair_setup_process_m1() {}

#[cfg(test)]
mod test {
    use super::*;

    fn init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::max())
            .try_init();
    }

    #[test]
    fn test_pairing_tlv_parse() -> Result<(), crate::tlv::TLVError> {
        init();

        let tlv_payload = [
            0x00, 0x01, 0x00, 0x06, 0x01, 0x01, 0x13, 0x04, 0x10, 0x80, 0x00, 0x01, 0x09, 0x01,
            0x01,
        ];

        let mut a = TLV::tied(&tlv_payload, 0x00);
        let mut b = TLV::tied(&tlv_payload, 0x06);

        let collected = TLVReader::new(&tlv_payload).read_into(&mut [&mut a, &mut b]);
        assert_eq!(collected.is_ok(), true);
        assert_eq!(a.type_id, 0x00);
        assert_eq!(a.length, 0x01);
        assert_eq!(a.data, &[0x00]);
        assert_eq!(b.type_id, 0x06);
        assert_eq!(b.length, 0x01);
        assert_eq!(b.data, &[0x01]);
        Ok(())
    }
}
