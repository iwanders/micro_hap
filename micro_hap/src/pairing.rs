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

use crate::crypto::{aead, aead::CHACHA20_POLY1305_KEY_BYTES, hkdf_sha512, homekit_srp};

#[derive(Debug, Copy, Clone)]
pub enum PairingError {
    TLVError(TLVError),
    IncorrectCombination,
    IncorrectState,
    IncorrectLength,
    BadPublicKey,
    BadProof,
    BadDecryption,
}

impl From<TLVError> for PairingError {
    fn from(e: TLVError) -> PairingError {
        PairingError::TLVError(e)
    }
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

pub const X25519_SCALAR_BYTES: usize = 32;
pub const X25519_BYTES: usize = 32;

pub const SRP_PUBLIC_KEY_BYTES: usize = 384;
pub const SRP_PREMASTER_SECRET_BYTES: usize = 384;
pub const SRP_SECRET_KEY_BYTES: usize = 32;
pub const SRP_SESSION_KEY_BYTES: usize = 64;
pub const SRP_PROOF_BYTES: usize = 64;

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessorySetupInfo.c#L324C45-L324C59
// Zero byte at the end is not added.
pub const SRP_USERNAME: &'static str = "Pair-Setup";

// Salt and info for the session key.
pub const PAIR_SETUP_ENCRYPT_SALT: &'static str = "Pair-Setup-Encrypt-Salt";
pub const PAIR_SETUP_ENCRYPT_INFO: &'static str = "Pair-Setup-Encrypt-Info";

// Salt and info for the control channel.
pub const CONTROL_CHANNEL_SALT: &'static str = "SplitSetupSalt";
pub const CONTROL_CHANNEL_ACCESSORY: &'static str = "AccessoryEncrypt-Control";
pub const CONTROL_CHANNEL_CONTROLLER: &'static str = "ControllerEncrypt-Control";

// Message stage specific nonces
pub const PAIR_SETUP_M5_NONCE: &'static str = "PS-Msg05";

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
        #[derive(PartialEq, Eq, Debug, Clone)]
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
typed_tlv!(TLVProof, TLVType::Proof);
typed_tlv!(TLVPublicKey, TLVType::PublicKey);
typed_tlv!(TLVEncryptedData, TLVType::EncryptedData);

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
}

pub struct PairContext {
    pub server: PairServer,
    pub setup: PairSetup,
    pub info: SetupInfo,
    pub session: crate::Session,
    pub accessory: crate::AccessoryInformationStatic,
}
impl Default for PairContext {
    fn default() -> Self {
        Self {
            server: Default::default(),
            setup: Default::default(),
            info: Default::default(),
            session: Default::default(),
            accessory: Default::default(),
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
            info!("not started, so m1");
            let mut method = TLVMethod::tied(&data);
            let mut state = TLVState::tied(&data);
            //let mut flags = TLVFlags::tied(&data);
            info!("before read into, data: {:0>2x?}", data);
            TLVReader::new(&data).require_into(&mut [&mut method, &mut state])?;

            info!("pair_setup_process_m1 next");
            pair_setup_process_m1(ctx, method, state)
        }
        PairState::SentM2 => {
            info!("Stage M3 begin");
            let mut state = TLVState::tied(&data);
            let mut public_key = TLVPublicKey::tied(&data);
            let mut proof = TLVProof::tied(&data);
            TLVReader::new(&data).require_into(&mut [&mut state, &mut public_key, &mut proof])?;
            ctx.setup.state = PairState::ReceivedM3;
            pair_setup_process_m3(ctx, state, public_key, proof)
        }
        PairState::SentM4 => {
            info!("HAPPairingPairSetupProcessM5 & pair_setup_process_m5");
            let mut state = TLVState::tied(&data);

            let mut encrypted_data = TLVEncryptedData::tied(&data);
            TLVReader::new(&data).require_into(&mut [&mut state, &mut encrypted_data])?;
            ctx.setup.state = PairState::ReceivedM5;
            pair_setup_process_m5(ctx, state, encrypted_data)
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
        PairState::ReceivedM3 => {
            // Advance the state, and write M2.
            ctx.setup.state = PairState::SentM4;
            pair_setup_process_get_m4(ctx, support, data)
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L48
// HAPPairingPairSetupProcessM1
pub fn pair_setup_process_m1(
    ctx: &mut PairContext,
    method: TLVMethod,
    state: TLVState,
) -> Result<(), PairingError> {
    let method = method.try_from::<PairingMethod>()?;
    info!("hit setup process m1");
    // info!("method: {:?}", method);
    // info!("state: {:?}", state);
    // info!("flags: {:?}", flags);

    ctx.setup.method = *method;
    // NONCOMPLIANCE: flags present is not set to false.
    //ctx.server.flags = PairingFlags::from_bits(flags.to_u32()?);
    ctx.setup.state = *state.try_from::<PairState>()?;

    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L342
// HAPPairingPairSetupProcessM3
pub fn pair_setup_process_m3(
    ctx: &mut PairContext,
    state: TLVState,
    public_key: TLVPublicKey,
    proof: TLVProof,
) -> Result<(), PairingError> {
    info!("hit setup process m3");

    let state = *state.try_from::<PairState>()?;
    if state != PairState::ReceivedM3 {
        return Err(PairingError::IncorrectState);
    }

    let public_key_len = public_key.len();
    let a_len = ctx.server.pair_setup.A.len();
    if public_key_len > a_len {
        return Err(PairingError::IncorrectLength);
    }

    // Zero extend big endian....
    let right = &mut ctx.server.pair_setup.A[a_len - public_key_len..];
    public_key.copy_body(right)?;

    // Copy the proof, whatever that means.
    proof.copy_body(&mut ctx.server.pair_setup.m1)?;

    // And update the state.
    ctx.setup.state = state;
    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L833
// HAPPairingPairSetupProcessM5
pub fn pair_setup_process_m5(
    ctx: &mut PairContext,
    state: TLVState,
    encrypted_data: TLVEncryptedData,
) -> Result<(), PairingError> {
    info!("Pair Setup M5: Exchange Request.");

    let state = *state.try_from::<PairState>()?;
    if state != PairState::ReceivedM5 {
        return Err(PairingError::IncorrectState);
    }
    info!("encrypted_data: {:?}", encrypted_data);

    // Write the data to the buffer first to ensure contiguous data

    // NONCOMPLIANCE: Bad use of ephemeral B, but we don't need that anymore and its available memory.
    encrypted_data.copy_body(&mut ctx.server.pair_setup.B)?;
    let key = &ctx.server.pair_setup.session_key;
    let data = &mut ctx.server.pair_setup.B[0..encrypted_data.len()];
    let decrypted = aead::decrypt(data, key, &PAIR_SETUP_M5_NONCE.as_bytes())?;
    info!("decrypted: {:0>2x?}", decrypted);

    //
    // let data = aead::decrypt(buffer, key, nonce_bytes);
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.
    // Decrypt the encrypted data.

    ctx.setup.state = state;
    Ok(())
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
    /*
    let flags = PairingFlags::new()
        .with_split(is_split)
        .with_transient(is_transient);

    writer = writer.add_entry(TLVType::Flags, &flags)?;
    */

    Ok(writer.end())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L430
pub fn pair_setup_process_get_m4(
    ctx: &mut PairContext,
    support: &PairSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    let _ = support;

    info!("Pair Setup M4: SRP Verify Response.");
    let server = homekit_srp();

    // NONCOMPLIANCE: ignoring the whole restorePrevious again.
    let public_b = &ctx.server.pair_setup.B;
    let b = &ctx.server.pair_setup.b;
    let v = &ctx.info.verifier;
    let public_a = &ctx.server.pair_setup.A;
    // premaster is also called S.
    let mut premaster = [0u8; SRP_PREMASTER_SECRET_BYTES];
    server
        .compute_shared_secret(public_b, b, v, public_a, &mut premaster)
        .map_err(|_| PairingError::BadPublicKey)?;

    info!("premaster: {:0>2x?}", &premaster);

    server.session_key(&premaster, &mut ctx.server.pair_setup.K);

    // What's the difference between K and S? First 64 bytes of S seems to be K?
    info!("Calculated K: {:0>2x?}", ctx.server.pair_setup.K);

    // we also have to check m1 :(
    let mut calculated_m1 = [0u8; SRP_PROOF_BYTES];
    let salt = &ctx.info.salt;
    let session_key = &ctx.server.pair_setup.K;
    server.compute_m1(
        SRP_USERNAME,
        salt,
        public_a,
        public_b,
        session_key,
        &mut calculated_m1,
    );

    info!("got_m1: {:0>2x?}", ctx.server.pair_setup.m1);
    info!("calculated_m1: {:0>2x?}", calculated_m1);
    if &ctx.server.pair_setup.m1 != &calculated_m1 {
        // NONCOMPLIANCE: Do something with counters to keep track of unsuccessful attempts.
        return Err(PairingError::BadProof);
    }
    // Cool, m1 matches, which means we advance to generating the accessory proof.
    let client_proof_m1 = &ctx.server.pair_setup.m1;
    server.compute_m2(
        public_a,
        session_key,
        client_proof_m1,
        &mut ctx.server.pair_setup.m2,
    );
    info!("calculated_m2: {:0>2x?}", ctx.server.pair_setup.m2);

    // oh, now we need something with hkdf_sha512...

    hkdf_sha512(
        &ctx.server.pair_setup.K,
        PAIR_SETUP_ENCRYPT_SALT.as_bytes(),
        PAIR_SETUP_ENCRYPT_INFO.as_bytes(),
        &mut ctx.server.pair_setup.session_key,
    )?;
    info!(
        "ctx.server.pair_setup.session_key: {:0>2x?}",
        ctx.server.pair_setup.session_key
    );

    // That concludes the session key... next we can start writing the response.

    let mut writer = TLVWriter::new(data);

    writer = writer.add_entry(TLVType::State, &ctx.setup.state)?;

    writer = writer.add_entry(TLVType::Proof, &ctx.server.pair_setup.m2)?;

    if ctx.setup.method == PairingMethod::PairSetupWithAuth {
        todo!();
    }

    if ctx.setup.method == PairingMethod::PairSetup && ctx.server.flags.transient() {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L740
        // Make a sesion... and a control channel, whatever that means.
        // Clear the current session.
        ctx.session = Default::default();

        hkdf_sha512(
            &ctx.server.pair_setup.K,
            CONTROL_CHANNEL_SALT.as_bytes(),
            CONTROL_CHANNEL_ACCESSORY.as_bytes(),
            &mut ctx.session.a_to_c.key,
        )?;
        info!("a_to_c key: {:0>2x?}", ctx.session.a_to_c.key);
        hkdf_sha512(
            &ctx.server.pair_setup.K,
            CONTROL_CHANNEL_SALT.as_bytes(),
            CONTROL_CHANNEL_CONTROLLER.as_bytes(),
            &mut ctx.session.c_to_a.key,
        )?;
        info!("c_to_a key: {:0>2x?}", ctx.session.c_to_a.key);

        ctx.session.security_active = true;
        ctx.session.transient = true;

        // NONCOMPLIANCE: not clearing setup procedure data.
        // NONCOMPLIANCE: not handling keepSetupInfo
    }

    // NONCOMPLIANCE: Not informing the application the pairing procedure succeeded.
    // NONCOMPLIANCE: Not telling the ble transport the session is accepted.
    //                https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEPeripheralManager.c#L1666

    Ok(writer.end())
}

#[cfg(test)]
mod test {
    use super::*;

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
    fn test_pairing_handle_setup() -> Result<(), PairingError> {
        crate::test::init();

        let recorded = recorded_info();

        let mut ctx = PairContext::default();
        ctx.info = recorded.setup_info;

        let counter = core::cell::RefCell::new(0);
        let random_buffer = recorded.random_b.clone();
        let rng = move || {
            let mut c = counter.borrow_mut();
            let v = random_buffer[*c];
            *c += 1;
            v
        };

        let support = PairSupport { rng: &rng };

        pair_setup_handle_incoming(&mut ctx, &support, &recorded.incoming_0)?;

        let mut buffer = [0u8; 1024];

        pair_setup_handle_outgoing(&mut ctx, &support, &mut buffer)?;

        info!("recorded.public_B: {:x?}", recorded.public_B);
        info!("srvr.pair_setup.B: {:x?}", ctx.server.pair_setup.B);

        // Afer this, the public ephemeral should match.
        assert_eq!(recorded.public_B, ctx.server.pair_setup.B);

        // This is M3: SRP Verify Request.
        pair_setup_handle_incoming(&mut ctx, &support, &recorded.incoming_1)?;
        let mut buffer = [0u8; 1024];

        // This is M4: SRP verify response.
        let l = pair_setup_handle_outgoing(&mut ctx, &support, &mut buffer)?;
        let response = &buffer[0..l];
        info!("m4 response: {:0>2x?}", &response);
        let expected_response = [
            0x06, 0x01, 0x04, 0x04, 0x40, 0x64, 0xe8, 0xca, 0xfc, 0x4e, 0xba, 0x56, 0x65, 0x06,
            0xc4, 0x9a, 0xf8, 0x4a, 0x47, 0x82, 0x56, 0x2a, 0x41, 0xa9, 0xa6, 0x7d, 0xec, 0xcc,
            0xaa, 0xea, 0xda, 0xe9, 0x73, 0x9e, 0xbd, 0x1f, 0x0c, 0x05, 0x85, 0xf4, 0x71, 0x05,
            0x24, 0x33, 0x2c, 0xb0, 0x6d, 0xfe, 0x41, 0x04, 0x37, 0x27, 0xd1, 0x28, 0xf0, 0x95,
            0x93, 0x39, 0xc7, 0x14, 0x36, 0x40, 0xc1, 0xa5, 0xa9, 0x07, 0x1f, 0x80, 0x0e,
        ];
        assert_eq!(response, &expected_response);

        Ok(())
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
        info!("ciphertext now: {:0>2x?}", buffer.as_ref());
        info!("ciphertext now: {:0>2x?}", ciphertext);
    }

    // Lets keep values for the unit tests below this line, such that I don't have to scroll too much :)

    #[allow(non_snake_case)]
    struct RecordedInfo {
        incoming_0: Vec<u8>,
        setup_info: SetupInfo,
        random_b: Vec<u8>,
        public_B: Vec<u8>,
        incoming_1: Vec<u8>,
    }

    fn recorded_info() -> RecordedInfo {
        let incoming_0 = vec![
            0x00, 0x01, 0x00, 0x06, 0x01, 0x01, 0x13, 0x04, 0x10, 0x80, 0x00, 0x01, 0x09, 0x01,
            0x01,
        ];
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

        // Remember this needs to be reassembled at the ble PDU layer.
        let incoming_1 = vec![
            0x06, 0x01, 0x03, 0x03, 0xff, 0xcd, 0xc2, 0x25, 0x41, 0x60, 0x7f, 0x3f, 0x5c, 0xa7,
            0x22, 0x40, 0x09, 0x97, 0x30, 0x70, 0xd1, 0xb9, 0xc2, 0x69, 0x17, 0xdd, 0x10, 0x8d,
            0xa9, 0x51, 0xe2, 0x31, 0x9e, 0x71, 0x09, 0xab, 0xcb, 0x0d, 0x13, 0x68, 0x19, 0xfe,
            0xbc, 0xd4, 0x09, 0x1e, 0x54, 0x45, 0xf1, 0xac, 0x19, 0xd9, 0x77, 0x79, 0xdb, 0xd8,
            0xbf, 0xa8, 0x61, 0x7b, 0xc9, 0xd5, 0x66, 0x9e, 0x53, 0xc7, 0xf3, 0xfc, 0x80, 0xd9,
            0x8a, 0x75, 0x85, 0xbb, 0xfc, 0x50, 0x46, 0x67, 0x62, 0xa1, 0x59, 0xd1, 0x2f, 0x38,
            0x9f, 0x36, 0xdc, 0x24, 0xdb, 0x69, 0xe6, 0xa0, 0x5f, 0x93, 0xe7, 0x9a, 0x4e, 0x9a,
            0xb1, 0x2f, 0xbd, 0x56, 0x19, 0x9e, 0x56, 0xb2, 0xed, 0xa6, 0x5e, 0x13, 0xe3, 0x24,
            0x42, 0x36, 0x89, 0x1b, 0xdf, 0x0a, 0xd5, 0x81, 0x0f, 0x0a, 0xbc, 0x54, 0x0e, 0x1a,
            0x6c, 0x2f, 0xad, 0x37, 0xf3, 0x9f, 0x22, 0x32, 0xfe, 0x59, 0xc7, 0xc3, 0x40, 0x5b,
            0x63, 0xa6, 0xb1, 0x89, 0x83, 0x3f, 0x41, 0xf7, 0x02, 0x1e, 0x40, 0x9f, 0x4c, 0xe8,
            0x33, 0x24, 0xb3, 0xc9, 0x92, 0xcc, 0xd8, 0x94, 0x47, 0x61, 0x20, 0x7f, 0x77, 0xf9,
            0x85, 0x91, 0x4e, 0x04, 0x59, 0x10, 0xf7, 0x49, 0xfc, 0x91, 0x4a, 0x25, 0x89, 0xdf,
            0x73, 0x62, 0xc2, 0x11, 0x4a, 0x12, 0xe4, 0x2a, 0x61, 0x1b, 0xf9, 0xf5, 0x0e, 0xa6,
            0x5a, 0xc5, 0x4f, 0x08, 0x18, 0x90, 0xc3, 0x5f, 0x34, 0x1a, 0xfc, 0x8e, 0xc7, 0x47,
            0x17, 0x4c, 0x30, 0x8f, 0x7e, 0x4d, 0x5c, 0x61, 0xc9, 0xf6, 0x72, 0xe9, 0x3d, 0xd3,
            0xd9, 0xbe, 0x35, 0xb6, 0x77, 0x1c, 0x09, 0x78, 0x3c, 0xd2, 0x45, 0xca, 0x1e, 0x99,
            0xfc, 0x27, 0xbb, 0x42, 0x3a, 0x64, 0x89, 0x30, 0x41, 0x40, 0x68, 0xe8, 0xf0, 0x16,
            0xb7, 0x07, 0x03, 0x38, 0xa2, 0xf4, 0xbf, 0xb2, 0x03, 0x81, 0x75, 0xb3, 0xe1, 0xe8,
            0xda, 0x70, 0x2c, 0x77, 0xe3, 0x6a, 0xb1, 0xf3, 0x7f, 0x77, 0x96, 0x3e, 0xeb, 0xe8,
            0xdc, 0x43, 0xa5, 0xf1, 0x7a, 0xdd, 0xd4, 0xfd, 0x4c, 0x28, 0x82, 0xfe, 0xba, 0x2e,
            0x64, 0x05, 0x63, 0x21, 0x0b, 0x00, 0x0f, 0xf2, 0xbb, 0x57, 0x76, 0x30, 0x92, 0x55,
            0x93, 0x9c, 0x28, 0xeb, 0x51, 0xe9, 0x96, 0xfd, 0x3f, 0x19, 0xf6, 0x23, 0xad, 0x12,
            0xcb, 0xfb, 0x9b, 0x74, 0x95, 0x3a, 0x0b, 0x92, 0x70, 0xbc, 0x19, 0x43, 0x28, 0x10,
            0xf2, 0x5b, 0xbb, 0xa7, 0xed, 0x63, 0x83, 0x26, 0xe7, 0xc1, 0x97, 0xe8, 0x3f, 0x16,
            0x43, 0x0a, 0xa3, 0x95, 0xaa, 0x11, 0xfd, 0x7c, 0x22, 0x99, 0x97, 0xd0, 0xc2, 0x0e,
            0x43, 0xb9, 0x4c, 0xf1, 0xe6, 0x7f, 0x5c, 0xaf, 0xe6, 0x80, 0x12, 0xf8, 0x77, 0xf3,
            0xb3, 0x91, 0xde, 0xed, 0xc2, 0xd3, 0x32, 0xf2, 0x97, 0xf4, 0xe6, 0xc9, 0xae, 0x04,
            0x40, 0xbb, 0x1c, 0x98, 0xdf, 0x60, 0x0b, 0xb2, 0x78, 0x1c, 0xb0, 0xc1, 0x05, 0xbb,
            0x40, 0x71, 0x72, 0xbe, 0xb3, 0x67, 0xb2, 0x96, 0x88, 0x89, 0x62, 0x15, 0xb8, 0x53,
            0xf7, 0xec, 0x54, 0xb8, 0x5f, 0xed, 0xdb, 0xb7, 0xc4, 0xc7, 0x30, 0xde, 0x02, 0xb8,
            0x89, 0xa6, 0xbf, 0xb6, 0xb1, 0x86, 0x6d, 0x49, 0x90, 0xb1, 0x3f, 0x79, 0xa2, 0xec,
            0x78, 0x4e, 0x44, 0x3e, 0x4d, 0x03, 0x5c, 0xa8, 0xae,
        ];
        RecordedInfo {
            incoming_0,
            setup_info: SetupInfo { salt, verifier },
            random_b,
            public_B,
            incoming_1,
        }
    }
}
