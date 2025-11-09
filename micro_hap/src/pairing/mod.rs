// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairing.h#L56
//
//
//
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairing.h#L122
//
use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};
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

use crate::tlv::TLVError;
use uuid;

use crate::crypto::{aead::CHACHA20_POLY1305_KEY_BYTES, homekit_srp_client};
pub(crate) mod pair_pairing;
pub(crate) mod pair_setup;
pub(crate) mod pair_verify;
pub(crate) mod session_cache;
use crate::{AccessoryContext, InterfaceError};
use pair_pairing::Pairings;
use session_cache::BleSessionCache;
use thiserror::Error;

pub const TRANSPORT_BLE: bool = true;
/// Errors associated to pairing, and configuration / initialisation of the pairing properties.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum PairingError {
    #[error("tlv error occured")]
    TLVError(#[from] TLVError),
    #[error("incorrect methods combined")]
    IncorrectMethodCombination,
    #[error("incorrect state for this method")]
    IncorrectState,
    #[error("incorrect length encountered")]
    IncorrectLength,
    #[error("bad public key detected")]
    BadPublicKey,
    #[error("bad proof provided")]
    BadProof,
    #[error("aed decryption failed")]
    BadDecryption,
    #[error("bad signature encountered")]
    BadSignature,
    #[error("failed to interpret uuid")]
    UuidError,
    #[error("unknown pairing id")]
    UnknownPairing,
    #[error("an error happend on the platform interface")]
    InterfaceError(#[from] InterfaceError),
    #[error("invalid data was provided")]
    InvalidData,
    #[error("not enough authentication was provided")]
    AuthenticationError,
}

impl From<hkdf::InvalidLength> for PairingError {
    fn from(_e: hkdf::InvalidLength) -> PairingError {
        PairingError::IncorrectLength
    }
}
impl From<chacha20poly1305::Error> for PairingError {
    fn from(_e: chacha20poly1305::Error) -> PairingError {
        PairingError::BadDecryption
    }
}
impl From<ed25519_dalek::SignatureError> for PairingError {
    fn from(_e: ed25519_dalek::SignatureError) -> PairingError {
        PairingError::BadSignature
    }
}

// Constants
pub const X25519_SCALAR_BYTES: usize = 32;
pub const X25519_BYTES: usize = 32;

pub const ED25519_BYTES: usize = 64;

pub const ED25519_LTSK: usize = 32;
pub const ED25519_LTPK: usize = 32;

pub const SRP_PUBLIC_KEY_BYTES: usize = 384;
pub const SRP_PREMASTER_SECRET_BYTES: usize = 384;
pub const SRP_SECRET_KEY_BYTES: usize = 32;
pub const SRP_SESSION_KEY_BYTES: usize = 64;
pub const SRP_PROOF_BYTES: usize = 64;
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessorySetupInfo.c#L324C45-L324C59
// Zero byte at the end is not added.
pub const SRP_USERNAME: &'static str = "Pair-Setup";

const _: [(); 0] = [(); crate::crypto::srp::SRP_PRIVATE_SECRET_BYTES - SRP_SECRET_KEY_BYTES];

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Default)]
#[repr(transparent)]
pub struct PairingId(pub uuid::Uuid);
impl PairingId {
    pub fn parse_str(input_bytes: &[u8]) -> Result<PairingId, PairingError> {
        Ok(PairingId(
            uuid::Uuid::try_parse_ascii(input_bytes).map_err(|_| PairingError::UuidError)?,
        ))
    }
    pub fn from_tlv(identifier: &TLVIdentifier) -> Result<PairingId, PairingError> {
        Ok(PairingId(
            uuid::Uuid::try_parse_ascii(
                identifier
                    .data_slices()
                    .get(0)
                    .ok_or(PairingError::UuidError)?,
            )
            .map_err(|_| PairingError::UuidError)?,
        ))
    }

    /// Checks if the pairing is none.
    pub fn is_none(&self) -> bool {
        self == &Default::default()
    }
    /// Returns a none pairing id.
    pub fn none() -> Self {
        Default::default()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PairingId {
    fn format(&self, f: defmt::Formatter) {
        // format the bitfields of the register as struct fields
        defmt::write!(f, "PairingId {{ {} }}", self.0.as_bytes(),)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Default)]
pub struct PairingPublicKey(pub [u8; 32]);
impl PairingPublicKey {
    pub fn from(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut r = Self::default();
        if bytes.len() != r.0.len() {
            return Err(PairingError::IncorrectLength);
        }
        r.0.copy_from_slice(bytes);
        Ok(r)
    }
    pub fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Default,
    TryFromBytes,
    IntoBytes,
    Immutable,
    KnownLayout,
)]
#[repr(transparent)]
pub struct SessionId(pub [u8; 8]);
impl SessionId {
    pub fn from(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut r = Self::default();
        if bytes.len() != r.0.len() {
            return Err(PairingError::IncorrectLength);
        }
        r.0.copy_from_slice(bytes);
        Ok(r)
    }
    pub fn as_ref(&self) -> &[u8; 8] {
        &self.0
    }
    pub fn from_tlv(identifier: &TLVSessionId) -> Result<SessionId, PairingError> {
        Ok(*SessionId::try_ref_from_bytes(
            identifier
                .short_data()
                .map_err(|_| PairingError::InvalidData)?,
        )
        .map_err(|_| PairingError::InvalidData)?)
    }
}

/// Represents the 8 digit pairing code the user is prompted for during the pairing procedure.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PairCode([u8; 8 + 2]);
impl PairCode {
    /// Create the pairing code from an array of digits, for example \[1,1,1,2,2,3,3,3\].
    pub const fn from_digits(v: [u8; 8]) -> Result<Self, ()> {
        // all values must be within 0-9
        let mut i = 0;
        while i < v.len() {
            if v[i] > 9 {
                return Err(());
            }
            i += 1;
        }
        // digits are all 0..9, calculate the offset for '0' in ascii
        let offset = '0' as u8;
        Ok(Self([
            offset + v[0],
            offset + v[1],
            offset + v[2],
            '-' as u8, // first three digits and hyphen
            offset + v[3],
            offset + v[4], // middle two digits.
            '-' as u8,
            offset + v[5],
            offset + v[6],
            offset + v[7],
        ]))
    }
    /// Create a pairing code from a string, including the hyphens: `111-22-333`.
    pub fn from_str(v: &'static str) -> Result<Self, ()> {
        let mut r = [0u8; 10];
        for (i, x) in v.chars().enumerate() {
            let correct_char = if i == 3 || i == 6 {
                x == '-'
            } else {
                x.is_ascii_digit()
            };
            if !correct_char {
                return Err(());
            }
            r[i] = x as u8;
        }

        Ok(Self(r))
    }

    /// Returns a slice of bytes including the hyphens, this is used for the verifier calculation.
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Calculate the verifier using the provided salt. This is usually done during the comissioning procedure.
    pub fn calculate_verifier(
        &self,
        salt: &[u8; 16],
        verifier: &mut [u8; crate::crypto::srp::SRP_VERIFIER_SIZE],
    ) {
        let our_client = homekit_srp_client();
        let username = SRP_USERNAME.as_bytes();
        let password = self.as_bytes();
        // unwrap is safe because all the preconditions & sizes are met.
        our_client
            .compute_verifier(username, password, salt, verifier)
            .unwrap();
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct Pairing {
    pub id: PairingId,
    // NONCOMPLIANCE; Why do we have a numIdentifierBytes here if it is constant?
    pub public_key: PairingPublicKey,
    pub permissions: u8,
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairing.h#L247
/// Flags for pairing
#[bitfield(u32)]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PairingFlags {
    #[bits(4)]
    _1: u8,

    /// Transient Pair Setup. Pair Setup M1 - M4 without exchanging public keys.
    // kHAPPairingFlag_Transient = 1U << 4U,
    #[bits(1)]
    transient: bool,

    #[bits(19)]
    _2: u32,

    /// Split Pair Setup.
    /// When set with kHAPPairingFlag_Transient save the SRP verifier used in this session,
    ///  and when only kHAPPairingFlag_Split is set, use the saved SRP verifier from previous session.
    // kHAPPairingFlag_Split = 1U << 24U,
    #[bits(1)]
    split: bool,
    #[bits(7)]
    _3: u8,
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPSession.h#L116
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct PairSetup {
    pub state: PairState,
    pub method: PairingMethod,
    pub error: u8,
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessoryServer%2BInternal.h#L128
/// Container struct for all the pairing temporary values.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct ServerPairSetup {
    // In the reference, this triple of flags lives in the 'state' struct, while the rest of this struct lives in the
    // internal struct.
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPSession.h#L117-L124
    /// State, method and error for the pair setup.
    pub setup: PairSetup,

    /// Ephemeral public key
    pub A: [u8; SRP_PUBLIC_KEY_BYTES],

    /// Private secret
    pub b: [u8; SRP_SECRET_KEY_BYTES],

    /// Ephemeral public key
    pub B: [u8; SRP_PUBLIC_KEY_BYTES],

    /// SRP session key
    pub K: [u8; SRP_SESSION_KEY_BYTES],

    /// Session key for pair setup procecure
    pub session_key: [u8; CHACHA20_POLY1305_KEY_BYTES],

    pub m1: [u8; SRP_PROOF_BYTES],
    pub m2: [u8; SRP_PROOF_BYTES],

    pub flags: PairingFlags,
}
impl Default for ServerPairSetup {
    fn default() -> Self {
        Self {
            A: [0u8; SRP_PUBLIC_KEY_BYTES],
            b: [0u8; SRP_SECRET_KEY_BYTES],
            B: [0u8; SRP_PUBLIC_KEY_BYTES],
            K: [0u8; SRP_SESSION_KEY_BYTES],
            session_key: [0u8; CHACHA20_POLY1305_KEY_BYTES],
            m1: [0u8; SRP_PROOF_BYTES],
            m2: [0u8; SRP_PROOF_BYTES],
            flags: Default::default(),
            setup: Default::default(),
        }
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct PairServer {
    pub pair_setup: ServerPairSetup,
    pub pair_verify: PairVerify,
    pub pairings: Pairings,
    pub ble_session_cache: BleSessionCache,
}
impl PairServer {
    pub fn disconnect(&mut self) {
        self.pair_setup = Default::default();
        self.pair_verify = Default::default();
        self.pairings = Default::default();
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPSession.h#L127
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct PairVerify {
    pub setup: PairSetup,
    pub session_key: [u8; CHACHA20_POLY1305_KEY_BYTES],
    pub cv_pk: [u8; X25519_BYTES],
    pub cv_sk: [u8; X25519_SCALAR_BYTES],
    pub cv_key: [u8; X25519_BYTES],
    pub pairing_id: Option<PairingId>,
    pub controller_cv_pk: [u8; X25519_BYTES],
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(
    PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone, Default,
)]
#[repr(u8)]
pub enum PairingMethod {
    #[default]
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
    /// HomeKit Accessory Protocol Specification R14 Table 7-38 Defines Description
    PairResume = 0x06,
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairing.h#L122
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
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

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/PAL/HAPBase.h#L178-L182
// #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
/// Setup information created during device commissioning.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
pub struct SetupInfo {
    /// Salt used to create the verifier.
    pub salt: [u8; 16],
    /// Verifier created for the pairing code and salt. See `PairingCode` for how to create this.
    pub verifier: [u8; 384],
}

impl SetupInfo {
    pub fn assign_from(&mut self, salt: [u8; 16], pair_code: PairCode) {
        self.salt = salt;
        pair_code.calculate_verifier(&self.salt, &mut self.verifier);
    }
}

impl Default for SetupInfo {
    fn default() -> Self {
        Self {
            salt: [0u8; 16],
            verifier: [0u8; 384],
        }
    }
}

pub mod tlv {
    use super::*;
    use crate::typed_tlv;
    // And then make the concrete TLV types.
    typed_tlv!(TLVMethod, TLVType::Method);
    typed_tlv!(TLVIdentifier, TLVType::Identifier);
    typed_tlv!(TLVPublicKey, TLVType::PublicKey);
    typed_tlv!(TLVProof, TLVType::Proof);
    typed_tlv!(TLVState, TLVType::State);
    typed_tlv!(TLVFlags, TLVType::Flags);
    typed_tlv!(TLVEncryptedData, TLVType::EncryptedData);
    typed_tlv!(TLVSignature, TLVType::Signature);
    typed_tlv!(TLVSessionId, TLVType::SessionID);
    typed_tlv!(TLVPermissions, TLVType::Permissions);
}
use tlv::*;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(
    PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone, Default,
)]
#[repr(u8)]
pub enum PairState {
    #[default]
    NotStarted = 0,
    ReceivedM1 = 1,
    SentM2 = 2,
    ReceivedM3 = 3,
    SentM4 = 4,
    ReceivedM5 = 5,
    SentM6 = 6,
}
impl PairState {
    pub fn from_tlv(identifier: &TLVState) -> Result<PairState, PairingError> {
        Ok(*PairState::try_ref_from_bytes(
            identifier
                .short_data()
                .map_err(|_| PairingError::InvalidData)?,
        )
        .map_err(|_| PairingError::InvalidData)?)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::PlatformSupport;
    use crate::ble::broadcast::BleBroadcastParameters;
    #[derive(Debug, Clone)]
    pub struct TestPairSupport {
        pub ed_ltsk: [u8; ED25519_LTSK],
        pub random: std::collections::VecDeque<u8>,
        pub pairings: std::collections::HashMap<PairingId, Pairing>,
        pub global_state_number: u16,
        pub config_number: u8,
        pub ble_broadcast_parameters: BleBroadcastParameters,
    }
    impl Default for TestPairSupport {
        fn default() -> Self {
            Self {
                ed_ltsk: Default::default(),
                random: Default::default(),
                pairings: Default::default(),
                global_state_number: 1,
                config_number: 1,
                ble_broadcast_parameters: Default::default(),
            }
        }
    }

    impl TestPairSupport {
        pub fn add_random(&mut self, v: &[u8]) {
            self.random.extend(v.iter())
        }
    }
    impl PlatformSupport for TestPairSupport {
        /// Return the time of this platform
        fn get_time(&self) -> embassy_time::Instant {
            let dt = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap();
            let micros = dt.as_micros();
            embassy_time::Instant::from_micros(micros as u64)
        }

        async fn get_ltsk(&self) -> [u8; ED25519_LTSK] {
            self.ed_ltsk
        }

        async fn fill_random(&mut self, buffer: &mut [u8]) -> () {
            buffer.fill_with(|| {
                self.random
                    .pop_front()
                    .expect("test pair support ran out of random")
            })
        }

        async fn store_pairing(&mut self, pairing: &Pairing) -> Result<(), InterfaceError> {
            self.pairings.insert(pairing.id, *pairing);
            error!("Writing pairing for {:?}", pairing.id);
            Ok(())
        }

        async fn get_pairing(&mut self, id: &PairingId) -> Result<Option<Pairing>, InterfaceError> {
            Ok(self.pairings.get(id).copied())
        }

        async fn remove_pairing(&mut self, id: &PairingId) -> Result<(), InterfaceError> {
            let _ = self.pairings.remove(&id);
            Ok(())
        }

        async fn is_paired(&mut self) -> Result<bool, InterfaceError> {
            Ok(!self.pairings.is_empty())
        }

        async fn get_global_state_number(&self) -> Result<u16, InterfaceError> {
            Ok(self.global_state_number)
        }
        /// Set the global state number, this is used by the BLE transport.
        async fn set_global_state_number(&mut self, value: u16) -> Result<(), InterfaceError> {
            self.global_state_number = value;
            Ok(())
        }

        async fn get_config_number(&self) -> Result<u8, InterfaceError> {
            Ok(self.config_number)
        }
        async fn set_config_number(&mut self, value: u8) -> Result<(), InterfaceError> {
            self.config_number = value;
            Ok(())
        }

        async fn get_ble_broadcast_parameters(
            &self,
        ) -> Result<BleBroadcastParameters, InterfaceError> {
            Ok(self.ble_broadcast_parameters)
        }
        async fn set_ble_broadcast_parameters(
            &mut self,
            params: &BleBroadcastParameters,
        ) -> Result<(), InterfaceError> {
            self.ble_broadcast_parameters = *params;
            Ok(())
        }
    }

    #[test]
    fn test_pairing_flags() {
        crate::test::init();
        let transient = 1u32 << 4;
        let from_flag = PairingFlags::new().with_transient(true);
        assert_eq!(transient, from_flag.0);
        let split = 1u32 << 24;
        let from_flag = PairingFlags::new().with_split(true);
        assert_eq!(split, from_flag.0);
    }

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
        info!("ciphertext now: {:02?}", buffer.as_ref());
        info!("ciphertext now: {:02?}", ciphertext);
    }

    #[test]
    fn test_pairingcode_srp_verifier() {
        let salt = [
            0xb3, 0x5b, 0x84, 0xc4, 0x04, 0x8b, 0x2d, 0x91, 0x35, 0xc4, 0xaf, 0xa3, 0x6d, 0xf6,
            0x2b, 0x29,
        ];
        let expected_verifier = [
            0x84, 0x3e, 0x54, 0xd4, 0x61, 0xd8, 0xbd, 0xee, 0x78, 0xcf, 0x96, 0xb3, 0x30, 0x85,
            0x4c, 0xba, 0x90, 0x89, 0xb6, 0x8a, 0x10, 0x7c, 0x51, 0xd6, 0xde, 0x2f, 0xc3, 0xe2,
            0x9e, 0xdb, 0x55, 0xd0, 0xe1, 0xa3, 0xc3, 0x80, 0x6a, 0x1c, 0xae, 0xa3, 0x4d, 0x8b,
            0xbe, 0xae, 0x91, 0x51, 0xe1, 0x78, 0xf6, 0x48, 0x9e, 0xa5, 0x09, 0x73, 0x91, 0xcd,
            0xc4, 0xae, 0x12, 0xad, 0x09, 0x04, 0xdf, 0x44, 0x6d, 0xbe, 0x10, 0x15, 0x58, 0x02,
            0xb2, 0x1e, 0x9e, 0xff, 0xfe, 0xa4, 0x91, 0xf4, 0xb7, 0xa6, 0xb5, 0x12, 0xaa, 0x04,
            0xbc, 0xff, 0xe1, 0x86, 0xeb, 0x27, 0x6a, 0xef, 0xe5, 0xc3, 0x9f, 0x18, 0x6f, 0xe3,
            0x53, 0xc7, 0x56, 0x2b, 0x58, 0x4a, 0xa9, 0x16, 0x12, 0x79, 0x04, 0x81, 0x22, 0x2f,
            0xb8, 0xf1, 0xce, 0xb0, 0xb9, 0xda, 0x6b, 0x0e, 0x39, 0x24, 0xcc, 0xf2, 0x1d, 0xf3,
            0xfc, 0x47, 0x58, 0xce, 0x16, 0xd4, 0x08, 0xfe, 0x9d, 0x77, 0x20, 0xa3, 0x43, 0x3a,
            0x45, 0xb0, 0xd4, 0xfb, 0xab, 0x3b, 0xad, 0x36, 0x13, 0xe0, 0xb3, 0xc2, 0x2a, 0x6a,
            0x22, 0x5a, 0xc3, 0xd6, 0xdc, 0x49, 0x41, 0x0c, 0xd6, 0x48, 0x26, 0x8d, 0x07, 0xe8,
            0x57, 0x84, 0xa9, 0xda, 0xb0, 0xe0, 0x54, 0xed, 0x59, 0xe9, 0xcf, 0x03, 0x26, 0x1f,
            0x46, 0x3a, 0x41, 0x01, 0xa9, 0xf8, 0x44, 0x60, 0xc3, 0x5d, 0x9c, 0xb4, 0x66, 0x42,
            0xe7, 0x9f, 0x98, 0x7c, 0xbb, 0x0f, 0x08, 0x7e, 0x36, 0x04, 0x12, 0xcc, 0x7b, 0x4f,
            0x05, 0x44, 0x3b, 0xdd, 0x35, 0x3d, 0x44, 0x2a, 0x47, 0x1d, 0xe0, 0x3e, 0x03, 0xe2,
            0x51, 0xeb, 0x12, 0x96, 0xad, 0x08, 0x46, 0x07, 0xfd, 0xc4, 0x94, 0x9f, 0xc2, 0x59,
            0x9d, 0x0f, 0x79, 0x93, 0x51, 0x0b, 0xb5, 0xe8, 0xfd, 0xbc, 0xd4, 0x5a, 0xcf, 0xf0,
            0x08, 0xf7, 0xd6, 0x44, 0x6a, 0x63, 0x86, 0x88, 0x56, 0x13, 0xcf, 0x5c, 0x51, 0x68,
            0xfb, 0xa9, 0xb7, 0x63, 0x6a, 0xce, 0x64, 0xe1, 0xe1, 0x5a, 0x55, 0xea, 0xb1, 0x0c,
            0x0a, 0x82, 0xe9, 0x23, 0x61, 0x2f, 0x0d, 0xa9, 0x09, 0xb3, 0x48, 0xd4, 0xcf, 0x19,
            0x53, 0x81, 0x38, 0x5d, 0x74, 0x4d, 0xf8, 0x9d, 0x66, 0xaf, 0x52, 0xaf, 0xab, 0xef,
            0x22, 0xce, 0x6f, 0xbe, 0xbe, 0xa1, 0x40, 0x44, 0xd0, 0x01, 0xef, 0x9e, 0x8e, 0xed,
            0xd7, 0x99, 0xa0, 0x1f, 0x6f, 0x89, 0x48, 0x98, 0xa7, 0x61, 0x01, 0x18, 0x77, 0x58,
            0x82, 0xfe, 0x5f, 0x8f, 0x5e, 0xf6, 0xf3, 0x25, 0xb0, 0xda, 0xd2, 0xbf, 0xb0, 0x9e,
            0x08, 0x3b, 0x6b, 0x07, 0xff, 0x54, 0x0d, 0xc7, 0x45, 0xcf, 0x75, 0x51, 0x16, 0x5d,
            0x08, 0xe0, 0xea, 0x98, 0xc8, 0xd7, 0xab, 0x21, 0x4a, 0x08, 0x17, 0xd0, 0x97, 0x13,
            0x49, 0xd7, 0xe7, 0xbe, 0xf1, 0x8f,
        ];
        // let pass = "111-22-333";

        let p = PairCode::from_digits([1, 1, 1, 2, 2, 3, 3, 3]).unwrap();
        let mut verifier = [0u8; 384];
        p.calculate_verifier(&salt, &mut verifier);
        assert_eq!(&verifier, &expected_verifier);
        // From a string.
        verifier.fill(0);
        let p = PairCode::from_str("111-22-333").unwrap();
        p.calculate_verifier(&salt, &mut verifier);
        assert_eq!(&verifier, &expected_verifier);
        // check some badness.
        assert!(PairCode::from_str("11a-22-333").is_err());
        assert!(PairCode::from_str("11-22-333").is_err());
        assert!(PairCode::from_str("11-122-333").is_err());
        assert!(PairCode::from_digits([1, 1, 1, 2, 2, 3, 33, 3]).is_err());
    }
}
