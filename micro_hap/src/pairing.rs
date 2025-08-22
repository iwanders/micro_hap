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

use crate::tlv::{TLV, TLVError, TLVReader, TLVWriter};
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
    pub salt: [u8; 16],
    pub verifier: [u8; 384],
}
impl Default for SetupInfo {
    fn default() -> Self {
        Self {
            salt: [0u8; 16],
            verifier: [0u8; 384],
        }
    }
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

pub struct PairContext {
    pub server: PairServer,
    pub setup: PairSetup,
    pub info: SetupInfo,
}
impl Default for PairContext {
    fn default() -> Self {
        Self {
            server: Default::default(),
            setup: Default::default(),
            info: Default::default(),
        }
    }
}

/// Function signature for the random generator. It's not FnMut for convenience in case we need to add more to the
/// support, use interior mutability if necessary.
type RandomFunction<'a> = &'a dyn Fn() -> u8;

/// Helper support for the pairing situations.
pub struct PairSupport<'a> {
    pub rng: RandomFunction<'a>,
}

// HAPPairingPairSetupHandleWrite
pub fn pair_setup_handle_incoming(
    ctx: &mut PairContext,
    support: &PairSupport,
    data: &[u8],
) -> Result<(), PairingError> {
    let _ = support;
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
    support: &PairSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    match ctx.setup.state {
        PairState::ReceivedM1 => {
            // Advance the state, and write M2.
            ctx.setup.state = PairState::SentM2;
            pair_setup_process_get_m2(ctx, support, data)
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
    info!("hit setup process m1");
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
    support: &PairSupport,
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
    ctx.server.pair_setup.b.fill_with(|| (support.rng)());
    // Then, we derive the public key B.

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

    let mut writer = TLVWriter::new(data);

    writer = writer.add_entry(TLVType::State, &ctx.setup.state)?;

    // NONCOMPLIANCE: They skip leading zeros, do we need that? Sounds like a minor improvement?
    writer = writer.add_slice(TLVType::PublicKey, &ctx.server.pair_setup.B)?;

    writer = writer.add_slice(TLVType::Salt, &ctx.info.salt)?;

    // Make flags
    let flags = PairingFlags::new()
        .with_split(is_split)
        .with_transient(is_transient);

    writer = writer.add_entry(TLVType::Flags, &flags)?;

    Ok(writer.end())
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

        let mut ctx = PairContext::default();
        ctx.info = recorded.setup_info;
        let mut counter = core::cell::RefCell::new(0);

        let random_buffer = recorded.random_b.clone();

        let rng = move || {
            let mut c = counter.borrow_mut();
            let v = random_buffer[*c];
            *c += 1;
            v
        };

        let support = PairSupport { rng: &rng };

        pair_setup_handle_incoming(&mut ctx, &support, &incoming_0)?;

        let mut buffer = [0u8; 1024];

        pair_setup_handle_outgoing(&mut ctx, &support, &mut buffer)?;

        info!("recorded.public_B: {:x?}", recorded.public_B);
        info!("srvr.pair_setup.B: {:x?}", ctx.server.pair_setup.B);

        // Afer this, the public ephemeral should match.
        assert_eq!(recorded.public_B, ctx.server.pair_setup.B);

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
            0xb3, 0x5b, 0x84, 0xc4, 0x04, 0x8b, 0x2d, 0x91, 0x35, 0xc4, 0xaf, 0xa3, 0x6d, 0xf6,
            0x2b, 0x29,
        ];
        let verifier = [
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

        let random_b = vec![
            0xab, 0xf6, 0x31, 0xc2, 0x84, 0x80, 0xee, 0x9f, 0x55, 0x27, 0x91, 0xb8, 0xdc, 0x47,
            0x5e, 0x6e, 0x04, 0x0f, 0x84, 0xde, 0xfc, 0xbd, 0xc3, 0x15, 0x4b, 0xed, 0x5b, 0xe1,
            0x89, 0xf2, 0x7f, 0x56,
        ];

        #[allow(non_snake_case)]
        let public_B = vec![
            0x96, 0xf3, 0x8a, 0x1b, 0x27, 0x01, 0x74, 0x7c, 0xef, 0xcb, 0xa1, 0xdb, 0xdb, 0x88,
            0x37, 0xa6, 0x87, 0x94, 0xa9, 0x6f, 0x89, 0xf4, 0x2a, 0x66, 0x0c, 0xe7, 0xa9, 0xa1,
            0xd1, 0xe4, 0x6c, 0x9a, 0x30, 0x5b, 0xe8, 0xee, 0x75, 0x56, 0xa3, 0x5c, 0x7f, 0xb4,
            0x09, 0x63, 0x25, 0x4b, 0x91, 0x96, 0x2b, 0xda, 0x87, 0x70, 0x23, 0xb8, 0xfd, 0xd2,
            0xcc, 0x4c, 0x94, 0x18, 0xa8, 0x36, 0xa5, 0x65, 0x5c, 0xb3, 0xdc, 0x33, 0x60, 0xe0,
            0xfe, 0xbe, 0xea, 0xb1, 0x4c, 0x2c, 0x5d, 0xfd, 0x12, 0x07, 0xe0, 0xf1, 0xbf, 0xc0,
            0x88, 0x9e, 0x81, 0x72, 0x48, 0x89, 0x7a, 0x27, 0x36, 0x66, 0x00, 0x53, 0x2a, 0xb9,
            0x87, 0x54, 0xd3, 0xee, 0x6c, 0x12, 0x2b, 0x3e, 0xab, 0x0b, 0x03, 0x89, 0x03, 0x96,
            0xed, 0xbf, 0xa2, 0x76, 0xde, 0x4f, 0x29, 0xf5, 0x0b, 0x61, 0xb1, 0x49, 0xa2, 0xd0,
            0x91, 0xe5, 0xe7, 0x60, 0xf2, 0x9c, 0x72, 0xec, 0x26, 0xde, 0x5e, 0xd4, 0xd0, 0x2d,
            0x97, 0x72, 0x0f, 0x4d, 0x9a, 0xe3, 0x07, 0x13, 0x61, 0x69, 0xad, 0xb3, 0xcf, 0xc3,
            0x60, 0xec, 0x8a, 0x54, 0x45, 0x9c, 0x99, 0xdc, 0x7a, 0xcc, 0xb0, 0x79, 0x78, 0x52,
            0x87, 0x9f, 0x20, 0x6d, 0xa1, 0x44, 0xbe, 0x49, 0x2c, 0x6d, 0x27, 0x51, 0x2f, 0x64,
            0xa6, 0xec, 0xd5, 0x97, 0xea, 0x33, 0xf9, 0xc4, 0xf7, 0x77, 0xc0, 0x29, 0x4c, 0xed,
            0x6f, 0x09, 0x9d, 0xbb, 0xa0, 0xe6, 0xd9, 0xf1, 0xaf, 0x8b, 0xf7, 0x56, 0xe5, 0xcc,
            0xad, 0x21, 0x1a, 0x1b, 0x0e, 0x66, 0xdb, 0x6a, 0x33, 0xa0, 0xd8, 0xc8, 0x54, 0xad,
            0x20, 0x3e, 0x77, 0x3b, 0x1a, 0x90, 0x21, 0xec, 0x51, 0x35, 0xfd, 0xa5, 0x2d, 0x57,
            0xf8, 0xcd, 0xdc, 0xc5, 0xa3, 0x7f, 0xfb, 0x3a, 0x68, 0x63, 0xa6, 0x91, 0x21, 0x33,
            0x84, 0xfb, 0x89, 0xcb, 0xa3, 0xbf, 0xa4, 0x52, 0x09, 0x70, 0x1d, 0x05, 0x60, 0x63,
            0xb6, 0x67, 0x20, 0xc6, 0x2d, 0x9b, 0x2b, 0x02, 0xef, 0x70, 0xbd, 0xcd, 0x8c, 0x5f,
            0x45, 0xd1, 0xb7, 0x9b, 0xb8, 0x1d, 0x7b, 0x65, 0x00, 0x9b, 0x4f, 0x28, 0xef, 0x0e,
            0x14, 0x77, 0x28, 0x14, 0x58, 0x79, 0xb5, 0x9a, 0xf4, 0xdf, 0xe8, 0x68, 0xb2, 0x37,
            0xf7, 0xea, 0x9f, 0x52, 0x3a, 0x36, 0x5e, 0xa6, 0xbd, 0x81, 0xf8, 0x20, 0xb8, 0xff,
            0xdd, 0x75, 0x93, 0xd7, 0xe6, 0xfb, 0x11, 0x3d, 0xf7, 0xfc, 0x07, 0x59, 0x9f, 0xcb,
            0xf6, 0xa6, 0x61, 0x3a, 0xb8, 0xdc, 0x98, 0xf9, 0xdf, 0x06, 0xb1, 0x4b, 0x79, 0x21,
            0xf8, 0x73, 0x84, 0x85, 0x4e, 0xef, 0xac, 0x93, 0x49, 0x33, 0x6e, 0x6d, 0x14, 0x80,
            0x5d, 0x30, 0xb0, 0x78, 0x28, 0xe9, 0x77, 0x0f, 0xa1, 0x16, 0x93, 0x5c, 0x5c, 0xcc,
            0x0b, 0xae, 0xb3, 0x49, 0xf1, 0xfb,
        ];

        RecordedInfo {
            setup_info: SetupInfo { salt, verifier },
            random_b,
            public_B,
        }
    }
}
