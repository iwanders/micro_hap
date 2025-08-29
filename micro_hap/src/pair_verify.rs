// use bitfield_struct::bitfield;
use zerocopy::IntoBytes;

use crate::crypto::{aead, ed25519::ed25519_sign, hkdf_sha512};
use crate::pairing::{
    ED25519_BYTES, PairContext, PairState, PairSupport, PairingError, PairingMethod, TLVType,
    X25519_BYTES, tlv::*,
};
use crate::tlv::{TLV, TLVError, TLVReader, TLVWriter};
use uuid;

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L972

// constants used in the pair verify process
const PAIR_VERIFY_M2_SALT: &'static str = "Pair-Verify-Encrypt-Salt";
const PAIR_VERIFY_M2_INFO: &'static str = "Pair-Verify-Encrypt-Info";
const PAIR_VERIFY_M2_NONCE: &'static str = "PV-Msg02";
const PAIR_VERIFY_M3_NONCE: &'static str = "PV-Msg03";

// HAPPairingPairVerifyHandleWrite
pub fn handle_incoming(
    ctx: &mut PairContext,
    support: &mut impl PairSupport,
    data: &[u8],
) -> Result<(), PairingError> {
    let _ = support;
    match ctx.server.pair_verify.setup.state {
        PairState::NotStarted => {
            info!("not started, so m1");
            let mut method = TLVMethod::tied(&data);
            let mut state = TLVState::tied(&data);
            let mut public_key = TLVPublicKey::tied(&data);
            let mut session_id = TLVSessionId::tied(&data);
            let mut encrypted_data = TLVEncryptedData::tied(&data);
            info!("before read into, data: {:0>2x?}", data);
            for v in TLVReader::new(&data) {
                info!("v: {:?}", v);
            }
            // Only got 6 & 3??? state & public key? Only those are required, the rest are optional.
            TLVReader::new(&data)
                .require_into(&mut [&mut state, &mut public_key])
                .map_err(|e| {
                    error!("missing {:?}", e);
                    e
                })?;

            TLVReader::new(&data).read_into(&mut [
                &mut method,
                &mut session_id,
                &mut encrypted_data,
            ])?;

            info!("pair_verify_process_m1 next");
            pair_verify_process_m1(ctx, method, state, public_key, session_id, encrypted_data)
        }
        PairState::SentM2 => {
            for v in TLVReader::new(&data) {
                info!("v: {:?}", v);
            }
            let mut state = TLVState::tied(&data);
            let mut encrypted_data = TLVEncryptedData::tied(&data);
            TLVReader::new(&data).read_into(&mut [&mut state, &mut encrypted_data])?;
            pair_verify_process_m3(ctx, state, encrypted_data)
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L1105C10-L1105C40
// HAPPairingPairVerifyHandleRead
pub fn handle_outgoing(
    ctx: &mut PairContext,
    support: &mut impl PairSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    match ctx.server.pair_verify.setup.state {
        PairState::ReceivedM1 => {
            ctx.server.pair_verify.setup.state = PairState::SentM2;
            // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L1136
            // Advance the state, and write M2.
            if ctx.server.pair_verify.setup.method == PairingMethod::PairResume {
                todo!();
            } else {
                pair_verify_process_get_m2(ctx, support, data)
            }
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L135
// HAPPairingPairVerifyProcessM1
pub fn pair_verify_process_m1(
    ctx: &mut PairContext,
    method: TLVMethod,
    state: TLVState,
    public_key: TLVPublicKey,
    session_id: TLVSessionId,
    encrypted_data: TLVEncryptedData,
) -> Result<(), PairingError> {
    info!("Pair Verify M1: Verify Start Request");

    let state = *state.try_from::<PairState>()?;
    if state != PairState::ReceivedM1 {
        return Err(PairingError::IncorrectState);
    }
    ctx.server.pair_verify.setup.state = PairState::ReceivedM1;

    let mut use_method = PairingMethod::PairVerify;
    if method.is_some() {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L185
        todo!();
    }

    if public_key.len() != X25519_BYTES {
        return Err(PairingError::IncorrectLength);
    }

    ctx.server.pair_verify.setup.method = use_method;
    public_key.copy_body(&mut ctx.server.pair_verify.controller_cv_pk)?;

    if ctx.server.pair_verify.setup.method == PairingMethod::PairResume {
        //https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L256
        todo!();
        // Seems the fallback of this is just doing a pair verify? Perhaps we can just do that and skip implementing this?
    }

    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L352
// HAPPairingPairVerifyGetM2
pub fn pair_verify_process_get_m2(
    ctx: &mut PairContext,
    support: &mut impl PairSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    info!("Pair Verify M2: Verify Start Response.");
    // NONCOMPLIANCE: not checking if an error is set, or if the session is already active.

    // Populate cv_SK from random.
    ctx.server
        .pair_verify
        .cv_sk
        .fill_with(|| support.get_random());

    // What is HAP_X25519_scalarmult_base(session->state.pairVerify.cv_PK, session->state.pairVerify.cv_SK); ? :/
    // That makes the Public key from our private secret!
    info!(" pair_verify.cv_sk: {:0>2x?}", ctx.server.pair_verify.cv_sk);
    let secret = x25519_dalek::StaticSecret::from(ctx.server.pair_verify.cv_sk);
    let our_public = x25519_dalek::PublicKey::from(&secret);

    ctx.server
        .pair_verify
        .cv_pk
        .copy_from_slice(our_public.as_bytes());
    // info!("verify.cv_pk: {:0>2x?}", ctx.server.pair_verify.cv_pk);

    // Shared secret
    let controller_public = x25519_dalek::PublicKey::from(ctx.server.pair_verify.controller_cv_pk);
    let common_secret = secret.diffie_hellman(&controller_public);
    ctx.server
        .pair_verify
        .cv_key
        .copy_from_slice(common_secret.as_bytes());
    // info!("verify.cv_key: {:0>2x?}", ctx.server.pair_verify.cv_key);

    let mut writer = TLVWriter::new(data);

    writer = writer.add_entry(TLVType::State, &ctx.server.pair_verify.setup.state)?;
    writer = writer.add_slice(TLVType::PublicKey, &ctx.server.pair_verify.cv_pk)?;

    // Next up, the whole subwriter dance again.

    // Next, create the aspects to sign.
    const X_LENGTH: usize = 32;
    // Concatenation of: accessory public, pairing id, ios device public key.

    let device_id_str = ctx.accessory.device_id.to_device_id_string();

    let identifier = device_id_str.0.as_bytes();

    let accessory_cvpk_idx = 0..X25519_BYTES;
    let pairing_id_idx = accessory_cvpk_idx.end..accessory_cvpk_idx.end + identifier.len();
    let ios_cvpk_idx = pairing_id_idx.end..pairing_id_idx.end + X25519_BYTES;
    let signature_idx = ios_cvpk_idx.end..ios_cvpk_idx.end + ED25519_BYTES;

    // Copy all the data.

    // NONCOMPLIANCE: Again (ab) using the B buffer.
    let scratch = &mut ctx.server.pair_setup.B;

    scratch[accessory_cvpk_idx.clone()].copy_from_slice(&ctx.server.pair_verify.cv_pk);
    scratch[pairing_id_idx].copy_from_slice(&identifier);

    // This controller_cv_pk is filled with zeros... what should it be??
    scratch[ios_cvpk_idx.clone()].copy_from_slice(&ctx.server.pair_verify.controller_cv_pk);

    // Next we sign what we got up to here.
    {
        let (to_sign, mut area_for_signature) = scratch.split_at_mut(ios_cvpk_idx.end);
        ed25519_sign(
            support.get_ltsk(),
            &to_sign,
            &mut area_for_signature[0..ED25519_BYTES],
        )
        .map_err(|_| PairingError::IncorrectLength)?;
    }
    let (original_data, mut subwriter_scratch) = scratch.split_at_mut(signature_idx.end);

    let mut subwriter = TLVWriter::new(subwriter_scratch);
    subwriter = subwriter.add_slice(TLVType::Identifier, identifier)?;
    subwriter = subwriter.add_slice(TLVType::Signature, &original_data[signature_idx])?;
    let subwriter_length = subwriter.end();

    // Next, derive the symmetric session encryption key.
    hkdf_sha512(
        &ctx.server.pair_verify.cv_key,
        PAIR_VERIFY_M2_SALT.as_bytes(),
        PAIR_VERIFY_M2_INFO.as_bytes(),
        &mut ctx.server.pair_verify.session_key,
    )?;

    // Now we need to encrypt the data in the subwriter.
    let key = &ctx.server.pair_verify.session_key;
    info!("verify.session_key: {:0>2x?}", key);
    let encrypted_sub = aead::encrypt(
        subwriter_scratch,
        subwriter_length,
        key,
        &PAIR_VERIFY_M2_NONCE.as_bytes(),
    )?;

    writer = writer.add_slice(TLVType::EncryptedData, &encrypted_sub)?;
    // info!("plain: {:0>2x?}", &subwriter_scratch[0..subwriter_length]);

    Ok(writer.end())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L708
// HAPPairingPairVerifyProcessM3
pub fn pair_verify_process_m3(
    ctx: &mut PairContext,
    state: TLVState,
    encrypted_data: TLVEncryptedData,
) -> Result<(), PairingError> {
    info!("Pair Verify M3: Verify Start Request");

    let state = *state.try_from::<PairState>()?;
    if state != PairState::ReceivedM3 {
        return Err(PairingError::IncorrectState);
    }
    ctx.server.pair_verify.setup.state = PairState::ReceivedM3;

    // Write the data to the buffer first to ensure contiguous data

    // NONCOMPLIANCE: use of ephemeral B, but we don't need that anymore at this point and it's available memory.
    // left holds the encrypted & decrypted data, with leaves right as a scratchpad. Encrypted data is 154 bytes, the
    // B size is 384, so that leaves 230 for the right side.
    let (left, right) = ctx.server.pair_setup.B.split_at_mut(encrypted_data.len());
    encrypted_data.copy_body(left)?;
    let key = &ctx.server.pair_verify.session_key;
    let data = left;
    let decrypted = aead::decrypt(data, key, &PAIR_VERIFY_M3_NONCE.as_bytes())?;
    info!("decrypted: {:0>2x?}", decrypted);

    let mut identifier = TLVIdentifier::tied(&decrypted);
    let mut signature = TLVSignature::tied(&decrypted);
    TLVReader::new(&decrypted).require_into(&mut [&mut identifier, &mut signature])?;

    // need to retrieve pairing that we created during the setup now.

    Ok(())
}
