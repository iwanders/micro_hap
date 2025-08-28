// use bitfield_struct::bitfield;
use zerocopy::IntoBytes;

use crate::crypto::ed25519::ed25519_sign;
use crate::pairing::{
    ED25519_BYTES, PairContext, PairState, PairSupport, PairingError, PairingMethod, TLVType,
    X25519_BYTES, tlv::*,
};
use crate::tlv::{TLV, TLVError, TLVReader, TLVWriter};
use uuid;

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L972

// HAPPairingPairVerifyHandleWrite
pub fn handle_incoming(
    ctx: &mut PairContext,
    support: &PairSupport,
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
            ctx.server.pair_verify.setup.state = PairState::ReceivedM1;
            pair_verify_process_m1(ctx, method, state, public_key, session_id, encrypted_data)
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
    support: &PairSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    match ctx.server.pair_verify.setup.state {
        PairState::ReceivedM1 => {
            ctx.setup.state = PairState::SentM2;
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

    let mut use_method = PairingMethod::PairVerify;
    if method.is_some() {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L185
        todo!();
    }

    if public_key.len() != X25519_BYTES {
        return Err(PairingError::IncorrectLength);
    }

    ctx.server.pair_verify.setup.method = use_method;
    public_key.copy_body(&mut ctx.server.pair_verify.cv_pk)?;

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
    support: &PairSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    info!("Pair Verify M2: Verify Start Response.");
    // NONCOMPLIANCE: not checking if an error is set, or if the session is already active.

    // Populate cv_SK from random.
    ctx.server.pair_verify.cv_sk.fill_with(|| (support.rng)());

    // What is HAP_X25519_scalarmult_base(session->state.pairVerify.cv_PK, session->state.pairVerify.cv_SK); ? :/
    // That makse the Public key from our private secret!
    let secret = x25519_dalek::StaticSecret::from(ctx.server.pair_verify.cv_sk);
    let public = x25519_dalek::PublicKey::from(&secret);

    ctx.server
        .pair_verify
        .cv_pk
        .copy_from_slice(public.as_bytes());

    // Shared secret
    //
    let common_secret = secret.diffie_hellman(&public);

    let mut writer = TLVWriter::new(data);

    writer = writer.add_entry(TLVType::State, &ctx.setup.state)?;
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

    scratch[accessory_cvpk_idx].copy_from_slice(&ctx.server.pair_verify.cv_pk);
    scratch[pairing_id_idx].copy_from_slice(&identifier);
    scratch[ios_cvpk_idx.clone()].copy_from_slice(&ctx.server.pair_verify.controller_cv_pk);

    // Next we sign what we got up to here.
    {
        let (to_sign, mut area_for_signature) = scratch.split_at_mut(ios_cvpk_idx.end);
        ed25519_sign(
            &todo!("what is identity.ed_LTSK"),
            &to_sign,
            &mut area_for_signature,
        )
        .map_err(|_| PairingError::IncorrectLength)?;
    }

    /*
    let hash_start = 0;
    let hash_end = X_LENGTH;
    let identifier_start = X_LENGTH;
    let identifier_end = X_LENGTH + identifier.len();
    let public_key_start = identifier_start + identifier.len();
    let public_key_end = public_key_start + public_key.len();
    let sig_start = public_key_end;
    let sig_end = public_key_end + ED25519_BYTES;

    // Write the hash, first section.
    let key = &ctx.server.pair_setup.K;
    let salt = &PAIR_SETUP_M6_SIGN_SALT.as_bytes();
    let info = &PAIR_SETUP_M6_SIGN_INFO.as_bytes();
    hkdf_sha512(key, salt, info, &mut scratch[hash_start..hash_end])?;

    // Write the device id as a string.
    scratch[identifier_start..identifier_end].copy_from_slice(identifier);

    // Write the long term pairing key.
    scratch[public_key_start..public_key_end].copy_from_slice(&public_key);

    // Sign it all
    {
        let secret_key = &support.ed_ltsk;
        let (data, signature) = scratch.split_at_mut(sig_start);
        ed25519_sign(secret_key, data, &mut signature[0..ED25519_BYTES])
            .map_err(|_| PairingError::IncorrectLength)?;
    }

    let (pre_calc, subwriter_scratch) = scratch.split_at_mut(sig_end);

    let mut subwriter = TLVWriter::new(subwriter_scratch);
    subwriter = subwriter.add_slice(TLVType::Identifier, device_id_str.as_bytes())?;
    subwriter = subwriter.add_slice(TLVType::PublicKey, &public_key)?;
    subwriter = subwriter.add_slice(TLVType::Signature, &pre_calc[sig_start..sig_end])?;
    let subwriter_length = subwriter.end();
    // Should be:
    // [01, 11, 35, 37, 3a, 33, 42, 3a, 32, 30, 3a, 41, 37, 3a, 45, 37, 3a, 43, 34, 03, 20, a1, 83, 6d, b8, c5, f8, b1, 27, 1c, bc, e2, df, 72, eb, 78, 9b, 55, 48, 6e, 53, 6c, 11, e1, 5b, b3, 9c, 65, c9, 26, 79, 16, 5a, 0a, 40, 56, 55, d7, 95, ca, 96, 8a, 30, 92, 64, e0, 0e, 6f, d8, 61, e4, fe, 96, d3, f5, e4, e5, 7b, e4, 22, 72, 38, f1, 36, 01, ef, 38, 04, 63, e5, db, 9b, 88, d3, af, 05, e5, d7, 52, 84, 1d, dd, ad, dd, d4, 37, d1, 92, 3e, 48, 06, 23, 5b, 97, d2, 6c, 7e, ef, 09]
    // Currently is:
    // [01, 11, 30, 31, 3a, 30, 32, 3a, 30, 33, 3a, 30, 34, 3a, 30, 35, 3a, 30, 36, 03, 20, a1, 83, 6d, b8, c5, f8, b1, 27, 1c, bc, e2, df, 72, eb, 78, 9b, 55, 48, 6e, 53, 6c, 11, e1, 5b, b3, 9c, 65, c9, 26, 79, 16, 5a, 0a, 40, e6, e8, 0d, 5b, 7c, 7e, 76, 05, 34, e8, 19, b8, 51, ad, 76, cf, 7a, 5a, ae, c8, ca, 48, 8e, ff, d5, 18, cc, 97, 92, 23, cd, 7d, dd, 04, 8d, 43, a8, 9a, ea, 8f, 65, f7, b2, fc, c3, 92, 66, 31, 48, 74, 2c, f7, 32, d6, 0c, da, 1c, ba, 36, c0, 74, 42, 44, 09]

    // let mut copied_plaintext = [0u8; 1024];
    // let mut plain_slice = &mut copied_plaintext[0..subwriter_length];
    // plain_slice.copy_from_slice(&subwriter_scratch[0..subwriter_length]);
    // info!("plain: {:0>2x?}", plain_slice);

    // Now we need to encrypt the data in the subwriter.
    let key = &ctx.server.pair_setup.session_key;
    info!("key: {key:?}");
    let encrypted_sub = aead::encrypt(
        subwriter_scratch,
        subwriter_length,
        key,
        &PAIR_SETUP_M6_NONCE.as_bytes(),
    )?;

    writer = writer.add_slice(TLVType::EncryptedData, &encrypted_sub)?;

    Ok(writer.end())
    */
    todo!()
}
