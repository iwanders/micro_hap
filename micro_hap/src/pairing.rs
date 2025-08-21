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

pub const SRP_PUBLIC_KEY_BYTES: usize = 384;
pub const SRP_SECRET_KEY_BYTES: usize = 32;
pub const SRP_SESSION_KEY_BYTES: usize = 64;
pub const SRP_PROOF_BYTES: usize = 64;

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessorySetupInfo.c#L324C45-L324C59
// Zero byte at the end is not added.
pub const SRP_USERNAME: &'static str = "Pair-Setup";

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

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessoryServer%2BInternal.h#L128
/// Container struct for all the pairing temporary values.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct ServerPairSetup {
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
        }
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct PairServer {
    pub flags: PairingFlags,
    pub pair_setup: ServerPairSetup,
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

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/PAL/HAPBase.h#L178-L182
/// Setup information created during device commissioning.
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct SetupInfo {
    salt: [u8; 16],
    verifier: [u8; 384],
}

/// Setup code string, with zero byte; XXX-XX-XXX
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct SetupCode(pub [u8; 11]);

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

pub struct PairContext<'server, 'setup, 'setupinfo, 'random> {
    pub server: &'server mut PairServer,
    pub setup: &'setup mut PairSetup,
    pub info: &'setupinfo SetupInfo,
    pub random_bytes: &'random [u8],
}
impl<'server, 'setup, 'setupinfo, 'random> PairContext<'server, 'setup, 'setupinfo, 'random> {
    pub fn new(
        server: &'server mut PairServer,
        setup: &'setup mut PairSetup,
        info: &'setupinfo SetupInfo,
        random_bytes: &'random [u8],
    ) -> Self {
        Self {
            server,
            setup,
            info,
            random_bytes,
        }
    }
}

// HAPPairingPairSetupHandleWrite
pub fn pair_setup_handle_incoming(ctx: &mut PairContext, data: &[u8]) -> Result<(), PairingError> {
    match ctx.setup.state {
        PairState::NotStarted => {
            let mut method = TLVMethod::tied(&data);
            let mut state = TLVState::tied(&data);
            let mut flags = TLVFlags::tied(&data);
            TLVReader::new(&data).require_into(&mut [&mut method, &mut state, &mut flags])?;
            pair_setup_process_m1(ctx, method, state, flags)
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L1406
// HAPPairingPairSetupHandleRead
pub fn pair_setup_handle_outgoing(
    ctx: &mut PairContext,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    match ctx.setup.state {
        PairState::ReceivedM1 => {
            // Advance the state, and write M2.
            ctx.setup.state = PairState::SentM2;
            pair_setup_process_get_m2(ctx, data)
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L48
pub fn pair_setup_process_m1(
    ctx: &mut PairContext,
    method: TLVMethod,
    state: TLVState,
    flags: TLVFlags,
) -> Result<(), PairingError> {
    let method = method.try_from::<PairingMethod>()?;
    // info!("method: {:?}", method);
    // info!("state: {:?}", state);
    // info!("flags: {:?}", flags);

    ctx.setup.method = *method;
    ctx.server.flags = PairingFlags::from_bits(flags.to_u32()?);
    ctx.setup.state = *state.try_from::<PairState>()?;

    Ok(())
}

pub type HomekitSrp<'a> = crate::srp::SrpServer<'a, sha2::Sha512>;
pub fn homekit_srp() -> crate::srp::SrpServer<'static, sha2::Sha512> {
    HomekitSrp::new(&crate::srp::groups::GROUP_3072)
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L158
pub fn pair_setup_process_get_m2(
    ctx: &mut PairContext,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    info!("Pair Setup M2: SRP Start Response.");
    // NONCOMPLIANCE: Check if accessory is already paired.
    // NONCOMPLIANCE: Check if accessory has received more than 100 unsuccesful attempts
    // NONCOMPLIANCE: Keep invalid authentication counter.
    let mut is_transient: bool = false;
    let mut is_split: bool = false;
    if ctx.server.flags.transient() {
        if ctx.setup.method == PairingMethod::PairSetupWithAuth {
            // What does this mean!?
            warn!("pair setup M2; ignoring because pair setup with auth was requested");
        } else {
            if ctx.setup.method != PairingMethod::PairSetup {
                error!("method should be pair setup");
                return Err(PairingError::IncorrectCombination);
            }
            is_transient = true;
        }
    }
    if ctx.server.flags.split() {
        if ctx.setup.method == PairingMethod::PairSetupWithAuth {
            // What does this mean!?
            warn!("pair setup M2; ignoring because pair setup with auth was requested");
        } else {
            if ctx.setup.method != PairingMethod::PairSetup {
                error!("method should be pair setup");
                return Err(PairingError::IncorrectCombination);
            }
            is_split = true;
        }
    }

    let _restore = !is_transient && is_split;

    // NONCOMPLIANCE do something with _restore, probably need this after we do the initial pair?

    // In the recording we see both flags being false.

    // Stuff with setup info salts?
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessorySetupInfo.c#L298
    // In the AppleHomekitADK, that is data that seems to have been made in the commissioning procedure?

    // Do SRP things...
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L256

    // fill b with random;
    //
    let len = ctx.server.pair_setup.b.len();
    ctx.server
        .pair_setup
        .b
        .copy_from_slice(&ctx.random_bytes[0..len]);

    // Then, we derive the public key B.

    let v = SRP_SECRET_KEY_BYTES;

    let server = homekit_srp();

    // Calculate the public ephemeral data.
    server.compute_public_ephemeral(
        &ctx.server.pair_setup.b,
        &ctx.info.verifier,
        &mut ctx.server.pair_setup.B,
    );
    //todo!("need to write public ephemeral into B");
    //
    // Now we need a TLV writer; https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L264

    Ok(0)
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
        let recorded = recorded_info();

        let mut ctx = PairContext::new(
            &mut server,
            &mut setup,
            &recorded.setup_info,
            &recorded.random_b,
        );
        pair_setup_handle_incoming(&mut ctx, &incoming_0)?;

        let mut buffer = [0u8; 1024];

        pair_setup_handle_outgoing(&mut ctx, &mut buffer)?;

        info!("recorded.public_B: {:x?}", recorded.public_B);
        info!("srvr.pair_setup.B: {:x?}", ctx.server.pair_setup.B);

        // Afer this, the public ephemeral should match.
        // Gah, we don't have the private b in the recording... so nothing matches.

        Ok(())
    }

    // Lets keep values for the unit tests below this line, such that I don't have to scroll too much :)

    #[allow(non_snake_case)]
    struct RecordedInfo {
        setup_info: SetupInfo,
        random_b: Vec<u8>,
        public_B: Vec<u8>,
    }

    fn recorded_info() -> RecordedInfo {
        let salt = [
            0xF3, 0xB3, 0x3D, 0xAF, 0xA6, 0xF7, 0x32, 0x03, 0x28, 0x61, 0x6A, 0x58, 0x28, 0x29,
            0x63, 0x36,
        ];
        let verifier = [
            0xD0, 0x1E, 0xEE, 0xCB, 0x1F, 0xA9, 0x88, 0x95, 0xD2, 0x8B, 0x3A, 0x25, 0x10, 0x09,
            0x10, 0x96, 0x06, 0xF9, 0xB0, 0x9A, 0x67, 0x75, 0x51, 0xA8, 0xB5, 0xF5, 0xDF, 0x65,
            0x9E, 0x19, 0xA7, 0x5C, 0x9A, 0xAF, 0x58, 0xFA, 0x0D, 0xA2, 0x33, 0xC9, 0xB4, 0x76,
            0x7A, 0x43, 0xEB, 0x6C, 0xBE, 0x5B, 0x24, 0xFB, 0xEB, 0xCD, 0x92, 0xB3, 0xB2, 0x3A,
            0xBA, 0xF6, 0x89, 0x41, 0x57, 0x3C, 0x9D, 0x9F, 0xBC, 0xB3, 0x76, 0x82, 0x73, 0x0A,
            0x12, 0x60, 0x8A, 0xDC, 0x35, 0xB6, 0x69, 0xA5, 0xDC, 0x78, 0x72, 0xC7, 0x77, 0xD0,
            0x5F, 0x92, 0xD4, 0x9E, 0x53, 0xC6, 0xD1, 0x46, 0x1F, 0x00, 0x78, 0x4E, 0x87, 0x41,
            0x8B, 0x04, 0xA4, 0x29, 0x5F, 0x57, 0x69, 0x06, 0x60, 0x09, 0x65, 0x9F, 0x94, 0xF0,
            0xC0, 0x36, 0x10, 0x96, 0xA8, 0x4C, 0xE2, 0x8F, 0x06, 0x7E, 0x2C, 0xB0, 0x30, 0xCE,
            0x97, 0x7F, 0xC6, 0x6F, 0x18, 0x76, 0xD7, 0xFC, 0x9B, 0x05, 0x0A, 0x15, 0x3B, 0x69,
            0x13, 0x10, 0x77, 0xA8, 0xE8, 0x36, 0x84, 0xDB, 0x16, 0xAB, 0x41, 0x65, 0x80, 0xE4,
            0x0B, 0x0C, 0xD8, 0x0E, 0x88, 0x33, 0xD3, 0x3C, 0x6D, 0x7A, 0x17, 0x48, 0x77, 0x0C,
            0x1D, 0x26, 0x0B, 0x9F, 0x0D, 0xC9, 0x5B, 0x1C, 0x2E, 0x8C, 0x00, 0x99, 0x2C, 0x17,
            0xD7, 0xB7, 0xA9, 0x90, 0x42, 0x2C, 0x74, 0xE4, 0x30, 0xFD, 0xD9, 0xB3, 0x20, 0xA1,
            0xC2, 0xBD, 0xE5, 0xEE, 0x2F, 0x55, 0x71, 0x98, 0x47, 0x9D, 0xCB, 0xD8, 0x05, 0x1A,
            0x8A, 0x69, 0xBD, 0x5A, 0x2C, 0x5B, 0x91, 0x12, 0x0D, 0x10, 0x34, 0x20, 0x47, 0xC5,
            0x3A, 0x0C, 0xB8, 0xDA, 0x6C, 0xBE, 0x38, 0x4B, 0xA8, 0xFC, 0x08, 0x38, 0xFC, 0x38,
            0x95, 0x12, 0xD4, 0xB1, 0x22, 0x00, 0xD5, 0xBA, 0x81, 0xB4, 0xBB, 0x87, 0x6A, 0x4B,
            0x25, 0x7F, 0x54, 0x69, 0x96, 0x3A, 0xBA, 0x8D, 0xA8, 0x67, 0xF5, 0x7F, 0x86, 0x42,
            0xF2, 0x94, 0xAD, 0xCC, 0x0B, 0xF9, 0xF3, 0x4B, 0x6F, 0x6F, 0xCB, 0x66, 0xD7, 0x2F,
            0x3A, 0x58, 0xF6, 0x69, 0x10, 0xD6, 0x90, 0x11, 0x58, 0x4F, 0x79, 0xC7, 0xFE, 0x50,
            0x72, 0x9A, 0x92, 0x3D, 0xA0, 0x7A, 0x70, 0x13, 0xC0, 0x7B, 0x2F, 0xCC, 0xD8, 0x03,
            0xD6, 0xB3, 0xDC, 0x6B, 0x40, 0xBC, 0x41, 0xB2, 0xDC, 0x75, 0x13, 0x94, 0x8B, 0x41,
            0x94, 0x21, 0xD0, 0xA9, 0x13, 0x70, 0xBA, 0x83, 0xBF, 0xC5, 0xA1, 0x27, 0xE3, 0xB7,
            0xB7, 0x97, 0x18, 0x5B, 0x19, 0x25, 0xD6, 0x50, 0xB2, 0x83, 0xE9, 0xCB, 0xE5, 0x2E,
            0x25, 0x90, 0x3C, 0xC4, 0x85, 0x36, 0x53, 0x74, 0x90, 0xE4, 0xCD, 0x03, 0xED, 0xEC,
            0xC5, 0x28, 0x72, 0xF7, 0x73, 0x48, 0x98, 0xAE, 0xAA, 0xFB, 0x6B, 0x50, 0x3F, 0xCA,
            0x4A, 0x27, 0xCB, 0x92, 0x17, 0x31,
        ];

        let random_b = vec![0; 32];

        let public_B = vec![
            0xfd, 0x83, 0xea, 0x82, 0x4d, 0x6c, 0xbf, 0xab, 0x7f, 0xa5, 0x03, 0x4b, 0x60, 0x75,
            0x29, 0xab, 0x85, 0x19, 0x7f, 0xba, 0x14, 0x7b, 0x65, 0x29, 0xf5, 0x95, 0x04, 0x37,
            0x95, 0x12, 0x55, 0xf6, 0xbb, 0xe1, 0x60, 0x5c, 0xa3, 0xc1, 0xbc, 0x04, 0x80, 0xc7,
            0x0f, 0x99, 0x3a, 0xd3, 0xe5, 0xf5, 0xae, 0x82, 0xdc, 0x9b, 0xbb, 0xf9, 0xc3, 0x44,
            0x07, 0xd9, 0x75, 0x12, 0xab, 0x2e, 0x2d, 0x2c, 0xa8, 0x1d, 0x6b, 0x9b, 0xcc, 0x7f,
            0x5f, 0xeb, 0x42, 0xb0, 0xad, 0x1e, 0x18, 0xb2, 0x67, 0x33, 0xb0, 0x45, 0x47, 0x67,
            0x11, 0x35, 0x58, 0x4a, 0x07, 0xf1, 0xba, 0x32, 0xb3, 0x96, 0x31, 0x17, 0x5f, 0x2b,
            0x16, 0x7f, 0x0d, 0xcd, 0x2a, 0x83, 0x1a, 0x62, 0xe7, 0xb5, 0x6c, 0x5e, 0x7f, 0xfc,
            0xc9, 0x1a, 0xd3, 0xc6, 0xfc, 0x67, 0xc4, 0x20, 0xf2, 0x99, 0x62, 0x53, 0x03, 0xfe,
            0x5f, 0x7a, 0x0f, 0x7c, 0xe7, 0x85, 0xa3, 0x75, 0x66, 0xb9, 0x24, 0x39, 0x3d, 0x7b,
            0x5c, 0xc8, 0x37, 0x90, 0x1d, 0x62, 0x7d, 0x07, 0x4f, 0x63, 0x3b, 0xcc, 0xaa, 0xdd,
            0x60, 0x75, 0x4c, 0x7c, 0x9a, 0x72, 0x15, 0xa3, 0xbc, 0x8a, 0x32, 0x94, 0xfc, 0x98,
            0xfe, 0x1b, 0x9d, 0x79, 0xc4, 0x8d, 0xba, 0x1f, 0x34, 0xc4, 0x1c, 0xe3, 0x72, 0x8c,
            0xb7, 0x6b, 0x17, 0xb4, 0xa0, 0xd7, 0x54, 0xc3, 0xc1, 0x1c, 0x2d, 0x03, 0x17, 0x5b,
            0x47, 0xe8, 0xe6, 0xdd, 0x56, 0x73, 0x9f, 0xa7, 0xa1, 0x26, 0xa3, 0x20, 0x9d, 0x78,
            0xea, 0xc8, 0xfb, 0x92, 0xde, 0x7d, 0xe4, 0x4a, 0x82, 0xb5, 0x60, 0xbb, 0x28, 0x11,
            0xa8, 0xa6, 0x26, 0xb0, 0x04, 0xce, 0xe4, 0x93, 0x13, 0x91, 0xbb, 0x87, 0x2b, 0x09,
            0x63, 0xb2, 0x69, 0x07, 0x32, 0x0b, 0x7e, 0x39, 0x36, 0x72, 0xba, 0xbe, 0xa9, 0xbd,
            0xbb, 0x31, 0x90, 0xd0, 0x91, 0x2e, 0x83, 0x31, 0x1e, 0x6a, 0x35, 0xa3, 0xe1, 0x3b,
            0xd1, 0xce, 0x7a, 0x97, 0xa2, 0x8c, 0xbc, 0xf2, 0x53, 0xe0, 0xb7, 0x7b, 0x47, 0x8d,
            0x4b, 0xae, 0xa8, 0x94, 0x76, 0xec, 0x12, 0x7b, 0x99, 0x2a, 0xdc, 0xf4, 0x1f, 0xe0,
            0xc6, 0x4d, 0xab, 0x98, 0xd5, 0x98, 0x37, 0xfd, 0x08, 0xd1, 0x05, 0x0e, 0x79, 0x38,
            0xd1, 0x45, 0x98, 0x8e, 0x20, 0x66, 0x81, 0x21, 0x9b, 0xc0, 0xe4, 0x76, 0x81, 0x60,
            0x66, 0x15, 0x9d, 0x00, 0xc4, 0xe6, 0x1f, 0xbb, 0x4f, 0xc8, 0xb5, 0x39, 0x95, 0xba,
            0x16, 0x9a, 0x9e, 0x1b, 0x9f, 0x88, 0x6d, 0x35, 0x07, 0xc1, 0xdc, 0x25, 0xff, 0x07,
            0xc0, 0x6a, 0x9a, 0x29, 0xb7, 0x9c, 0x73, 0xea, 0x3e, 0xfe, 0xed, 0xdb, 0xee, 0x87,
            0x25, 0x1a, 0x30, 0xd4, 0xbb, 0xca, 0xc0, 0x92, 0xdc, 0xaa, 0x11, 0x00, 0xf8, 0x58,
            0xdf, 0x2d, 0xe9, 0x2b, 0x91, 0x76,
        ];

        RecordedInfo {
            setup_info: SetupInfo { salt, verifier },
            random_b,
            public_B,
        }
    }
}
