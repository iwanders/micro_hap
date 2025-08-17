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

use crate::tlv::{TLV, TLVError, TLVReader};
use uuid;

#[derive(Debug, Copy, Clone)]
pub enum PairingError {
    TLVError(TLVError),
    IncorrectCombination,
}

impl From<TLVError> for PairingError {
    fn from(e: TLVError) -> PairingError {
        PairingError::TLVError(e)
    }
}

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

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairing.h#L247
/// Flags for pairing
#[bitfield(u32)]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
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
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct PairSetup {
    pub state: PairState,
    pub method: PairingMethod,
    pub error: u8,
}

#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct PairServer {
    pub flags: PairingFlags,
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPSession.h#L127
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct PairVerify {
    pub setup: PairSetup,
    pub session_key: [u8; CHACHA20_POLY1305_KEY_BYTES],
    pub cv_pk: [u8; X25519_BYTES],
    pub cv_sk: [u8; X25519_SCALAR_BYTES],
    pub cv_key: [u8; X25519_BYTES],
    pub pairing_id: usize,
    pub controller_cv_pk: [u8; X25519_BYTES],
}

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

/// Helper macro to make typed newtype wrappers around TLV
macro_rules! typed_tlv {
    ( $name:ident, $tlv_type:expr  ) => {
        #[derive(PartialEq, Eq, Debug, Copy, Clone)]
        pub struct $name<'a>(TLV<'a>);
        impl<'a> $name<'a> {
            pub fn tied(data: &'a [u8]) -> Self {
                Self(TLV::tied(data, $tlv_type))
            }
            pub fn tlv_type(&self) -> TLVType {
                $tlv_type
            }
        }
        impl<'a> core::ops::Deref for $name<'a> {
            type Target = TLV<'a>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl<'a> core::ops::DerefMut for $name<'a> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

// And then make the concrete TLV types.
typed_tlv!(TLVMethod, TLVType::Method);
typed_tlv!(TLVState, TLVType::State);
typed_tlv!(TLVFlags, TLVType::Flags);

#[derive(
    PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone, Default,
)]
#[repr(u8)]
pub enum PairState {
    #[default]
    NotStarted = 0,
    ReceivedM1 = 1,
    SentM2 = 2,
}

// HAPPairingPairSetupHandleWrite
pub fn pair_setup_handle_incoming(
    server: &mut PairServer,
    setup: &mut PairSetup,
    data: &[u8],
) -> Result<(), PairingError> {
    match setup.state {
        PairState::NotStarted => {
            let mut method = TLVMethod::tied(&data);
            let mut state = TLVState::tied(&data);
            let mut flags = TLVFlags::tied(&data);
            TLVReader::new(&data).require_into(&mut [&mut method, &mut state, &mut flags])?;
            pair_setup_process_m1(server, setup, method, state, flags)
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L1406
// HAPPairingPairSetupHandleRead
pub fn pair_setup_handle_outgoing(
    server: &mut PairServer,
    setup: &mut PairSetup,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    match setup.state {
        PairState::ReceivedM1 => {
            // Advance the state, and write M2.
            setup.state = PairState::SentM2;
            pair_setup_process_get_m2(server, setup, data)
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L48
pub fn pair_setup_process_m1(
    server: &mut PairServer,
    setup: &mut PairSetup,
    method: TLVMethod,
    state: TLVState,
    flags: TLVFlags,
) -> Result<(), PairingError> {
    let method = method.try_from::<PairingMethod>()?;
    // info!("method: {:?}", method);
    // info!("state: {:?}", state);
    // info!("flags: {:?}", flags);

    setup.method = *method;
    server.flags = PairingFlags::from_bits(flags.to_u32()?);
    setup.state = *state.try_from::<PairState>()?;

    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L158
pub fn pair_setup_process_get_m2(
    server: &mut PairServer,
    setup: &mut PairSetup,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    info!("Pair Setup M2: SRP Start Response.");
    // NONCOMPLIANCE: Check if accessory is already paired.
    // NONCOMPLIANCE: Check if accessory has received more than 100 unsuccesful attempts
    // NONCOMPLIANCE: Keep invalid authentication counter.
    let mut is_transient: bool = false;
    let mut is_split: bool = false;
    if server.flags.transient() {
        if setup.method == PairingMethod::PairSetupWithAuth {
            // What does this mean!?
            warn!("pair setup M2; ignoring because pair setup with auth was requested");
        } else {
            if (setup.method != PairingMethod::PairSetup) {
                error!("method should be pair setup");
                return Err(PairingError::IncorrectCombination);
            }
            is_transient = true;
        }
    }
    if server.flags.split() {
        if setup.method == PairingMethod::PairSetupWithAuth {
            // What does this mean!?
            warn!("pair setup M2; ignoring because pair setup with auth was requested");
        } else {
            if (setup.method != PairingMethod::PairSetup) {
                error!("method should be pair setup");
                return Err(PairingError::IncorrectCombination);
            }
            is_split = true;
        }
    }

    let restore = !is_transient && is_split;

    // In the recording we see both flags being false.

    // Stuff with setup info salts?
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessorySetupInfo.c#L298
    // In the AppleHomekitADK, that is data that seems to have been made in the commissioning procedure?

    todo!()
}

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
    fn test_pairing_flags() {
        let transient = 1u32 << 4;
        let from_flag = PairingFlags::new().with_transient(true);
        assert_eq!(transient, from_flag.0);
        let split = 1u32 << 24;
        let from_flag = PairingFlags::new().with_split(true);
        assert_eq!(split, from_flag.0);
    }
    #[test]
    fn test_pairing_handle_setup() -> Result<(), PairingError> {
        init();

        let incoming_0 = [
            0x00, 0x01, 0x00, 0x06, 0x01, 0x01, 0x13, 0x04, 0x10, 0x80, 0x00, 0x01, 0x09, 0x01,
            0x01,
        ];
        let mut setup = PairSetup::default();
        let mut server = PairServer::default();
        pair_setup_handle_incoming(&mut server, &mut setup, &incoming_0)?;

        let mut buffer = [0u8; 1024];

        pair_setup_handle_outgoing(&mut server, &mut setup, &mut buffer)?;

        Ok(())
    }
}
