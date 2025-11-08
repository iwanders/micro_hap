// use bitfield_struct::bitfield;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::PlatformSupport;
use crate::crypto::{
    aead::{self, CHACHA20_POLY1305_KEY_BYTES},
    ed25519::{ed25519_sign, ed25519_verify},
    hkdf_sha512,
};
use crate::pairing::{
    AccessoryContext, ED25519_BYTES, PairState, PairingError, PairingId, PairingMethod, TLVType,
    X25519_BYTES, tlv::*,
};
use crate::tlv::{TLVReader, TLVWriter};

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L972

// constants used in the pair verify process

const PAIR_VERIFY_M1_RESUME_INFO: &'static str = "Pair-Resume-Request-Info";
const PAIR_VERIFY_M1_RESUME_NONCE: &'static str = "PR-Msg01";
const PAIR_VERIFY_M2_RESUME_INFO: &'static str = "Pair-Resume-Response-Info";
const PAIR_VERIFY_M2_RESUME_SHARED_SECRET_INFO: &'static str = "Pair-Resume-Shared-Secret-Info";
const PAIR_VERIFY_M2_RESUME_NONCE: &'static str = "PR-Msg02";

const PAIR_VERIFY_M2_SALT: &'static str = "Pair-Verify-Encrypt-Salt";
const PAIR_VERIFY_M2_INFO: &'static str = "Pair-Verify-Encrypt-Info";
const PAIR_VERIFY_M2_NONCE: &'static str = "PV-Msg02";
const PAIR_VERIFY_M3_NONCE: &'static str = "PV-Msg03";

// Salt and info for the control channel.
pub const CONTROL_CHANNEL_SALT: &'static str = "Control-Salt";
pub const CONTROL_CHANNEL_READ_KEY: &'static str = "Control-Read-Encryption-Key";
pub const CONTROL_CHANNEL_WRITE_KEY: &'static str = "Control-Write-Encryption-Key";

// HAPPairingPairVerifyHandleWrite
pub async fn handle_incoming(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &[u8],
) -> Result<(), PairingError> {
    let _ = support;
    let r = match ctx.server.pair_verify.setup.state {
        PairState::NotStarted => {
            info!("not started, so m1");
            let mut method = TLVMethod::tied(&data);
            let mut state = TLVState::tied(&data);
            let mut public_key = TLVPublicKey::tied(&data);
            let mut session_id = TLVSessionId::tied(&data);
            let mut encrypted_data = TLVEncryptedData::tied(&data);
            info!("before read into, data: {:02?}", data);
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
            pair_verify_process_m3(ctx, support, state, encrypted_data).await
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    };

    if r.is_err() {
        ctx.server.pair_verify = Default::default();
    }
    r
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L1105C10-L1105C40
// HAPPairingPairVerifyHandleRead
pub async fn handle_outgoing(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    let r = match ctx.server.pair_verify.setup.state {
        PairState::ReceivedM1 => {
            ctx.server.pair_verify.setup.state = PairState::SentM2;
            // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L1136
            // Advance the state, and write M2.
            if ctx.server.pair_verify.setup.method == PairingMethod::PairResume {
                pair_verify_process_get_m2_ble(ctx, support, data).await
            } else {
                pair_verify_process_get_m2(ctx, support, data).await
            }
        }
        PairState::ReceivedM3 => {
            ctx.server.pair_verify.setup.state = PairState::SentM4;
            // Advance the state, and write M4.
            pair_verify_process_get_m4(ctx, support, data)
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    };

    if r.is_err() || ctx.server.pair_verify.setup.state == PairState::SentM4 {
        info!("Clearing pairing setup state.");
        ctx.server.pair_verify = Default::default();
    }
    r
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L135
// HAPPairingPairVerifyProcessM1
pub fn pair_verify_process_m1(
    ctx: &mut AccessoryContext,
    method: TLVMethod,
    state: TLVState,
    public_key: TLVPublicKey,
    session_id: TLVSessionId,
    encrypted_data: TLVEncryptedData,
) -> Result<(), PairingError> {
    info!("Pair Verify M1: Verify Start Request");
    // let _ = (session_id, encrypted_data);

    let state = *state.try_from::<PairState>()?;
    if state != PairState::ReceivedM1 {
        return Err(PairingError::IncorrectState);
    }
    ctx.server.pair_verify.setup.state = PairState::ReceivedM1;

    let mut use_method = PairingMethod::PairVerify;
    if method.is_some() {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L185
        info!("method: {:?}", method);
        use_method = PairingMethod::try_read_from_bytes(method.short_data()?)
            .map_err(|_| PairingError::IncorrectLength)?;
    }

    if public_key.len() != X25519_BYTES {
        return Err(PairingError::IncorrectLength);
    }

    ctx.server.pair_verify.setup.method = use_method;
    info!("using method: {:?}", use_method);
    public_key.copy_body(&mut ctx.server.pair_verify.controller_cv_pk)?;
    info!(
        "obtained public key: {:?}",
        ctx.server.pair_verify.controller_cv_pk
    );

    if ctx.server.pair_verify.setup.method == PairingMethod::PairResume {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L256
        info!("Pair Resume M1: Resume Request");
        // NONCOMPLIANCE; They have a session cache here... we don't have a session cache?

        let provided_session_id = session_id.short_data()?;
        info!(
            "Pair resume with {:02?}, {:02?} {:02?}",
            provided_session_id, public_key, encrypted_data
        );

        if ctx.session.pairing_id.is_none() {
            ctx.server.pair_verify.setup.method = PairingMethod::PairVerify;
            // NONCOMPLIANCE? do we ever use this method field?
            return Ok(());
        }

        let mut scratch = ctx.server.pair_setup.B;
        let request_key_idx = 0..CHACHA20_POLY1305_KEY_BYTES;
        let salt_idx = request_key_idx.end..request_key_idx.end + X25519_BYTES;
        let session_idx = salt_idx.end..salt_idx.end + provided_session_id.len();

        // Copy the data there.
        public_key.copy_body(&mut scratch[salt_idx.clone()])?;
        session_id.copy_body(&mut scratch[session_idx.clone()])?;

        let (first_section, right_scratch) = scratch.split_at_mut(session_idx.end);

        // Calculate the request key.
        let (result, remainder) = first_section.split_at_mut(request_key_idx.end);
        let shifted_salt_session_idx =
            (salt_idx.start - request_key_idx.end)..(session_idx.end - request_key_idx.end);
        let salt = &remainder[shifted_salt_session_idx];
        let key = &ctx.server.pair_verify.cv_key;
        let info = PAIR_VERIFY_M1_RESUME_INFO.as_bytes();
        hkdf_sha512(key, salt, info, result)?;

        info!("Pair Resume M1: RequestKey: {:02?}", result);

        // Next up is decrypting the data.
        let len = encrypted_data.copy_body(right_scratch)?;

        let decrypted = aead::decrypt(
            &mut right_scratch[0..len],
            result,
            PAIR_VERIFY_M1_RESUME_NONCE.as_bytes(),
        )?;
        // There is no actual data, we merely need to check the authentication tag?
        info!("Decrypted data: {:02?}", decrypted);
        // Seems the fallback of this is just doing a pair verify? Perhaps we can just do that and skip implementing this?
    }

    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L352
// HAPPairingPairVerifyGetM2
pub async fn pair_verify_process_get_m2(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    info!("Pair Verify M2: Verify Start Response.");
    // NONCOMPLIANCE: not checking if an error is set, or if the session is already active.

    // Populate cv_SK from random.
    support.fill_random(&mut ctx.server.pair_verify.cv_sk).await;

    // What is HAP_X25519_scalarmult_base(session->state.pairVerify.cv_PK, session->state.pairVerify.cv_SK); ? :/
    // That makes the Public key from our private secret!
    info!(" pair_verify.cv_sk: {:02?}", ctx.server.pair_verify.cv_sk);
    let secret = x25519_dalek::StaticSecret::from(ctx.server.pair_verify.cv_sk);
    let our_public = x25519_dalek::PublicKey::from(&secret);

    ctx.server
        .pair_verify
        .cv_pk
        .copy_from_slice(our_public.as_bytes());
    // info!("verify.cv_pk: {:02?}", ctx.server.pair_verify.cv_pk);

    // Shared secret
    let controller_public = x25519_dalek::PublicKey::from(ctx.server.pair_verify.controller_cv_pk);
    let common_secret = secret.diffie_hellman(&controller_public);
    ctx.server
        .pair_verify
        .cv_key
        .copy_from_slice(common_secret.as_bytes());
    // info!("verify.cv_key: {:02?}", ctx.server.pair_verify.cv_key);

    let mut writer = TLVWriter::new(data);

    writer = writer.add_entry(TLVType::State, &ctx.server.pair_verify.setup.state)?;
    writer = writer.add_slice(TLVType::PublicKey, &ctx.server.pair_verify.cv_pk)?;

    // Next up, the whole subwriter dance again.

    // Next, create the aspects to sign.
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
        let (to_sign, area_for_signature) = scratch.split_at_mut(ios_cvpk_idx.end);
        ed25519_sign(
            &support.get_ltsk().await,
            &to_sign,
            &mut area_for_signature[0..ED25519_BYTES],
        )
        .map_err(|_| PairingError::IncorrectLength)?;
    }
    let (original_data, subwriter_scratch) = scratch.split_at_mut(signature_idx.end);

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
    info!("verify.session_key: {:02?}", key);
    let encrypted_sub = aead::encrypt(
        subwriter_scratch,
        subwriter_length,
        key,
        &PAIR_VERIFY_M2_NONCE.as_bytes(),
    )?;

    writer = writer.add_slice(TLVType::EncryptedData, &encrypted_sub)?;
    // info!("plain: {:02?}", &subwriter_scratch[0..subwriter_length]);

    Ok(writer.end())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L553
// HAPPairingPairVerifyGetM2ForBLEPairResume
pub async fn pair_verify_process_get_m2_ble(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    info!("Pair Resume M2: Resume Response.");
    if ctx.server.pair_verify.setup.state != PairState::SentM2 {
        return Err(PairingError::IncorrectState);
    }

    // NONCOMPLIANCE This whole session_id seems to be proper and often used... where is it actually stored?

    const SESSION_ID_LENGTH: usize = 8;
    let mut scratch = ctx.server.pair_setup.B;
    let request_key_idx = 0..CHACHA20_POLY1305_KEY_BYTES;
    let salt_idx = request_key_idx.end..request_key_idx.end + X25519_BYTES;
    let session_idx = salt_idx.end..salt_idx.end + SESSION_ID_LENGTH;

    // Generated random session id.
    support.fill_random(&mut scratch[session_idx.clone()]).await;

    // Copy the cv key
    scratch[salt_idx.clone()].copy_from_slice(&ctx.server.pair_verify.controller_cv_pk);

    let (first_section, right_scratch) = scratch.split_at_mut(session_idx.end);

    // Calculate the request key.
    let (result_key, remainder) = first_section.split_at_mut(request_key_idx.end);
    let shifted_salt_session_idx =
        (salt_idx.start - request_key_idx.end)..(session_idx.end - request_key_idx.end);
    let salt = &remainder[shifted_salt_session_idx];
    info!("Pair Resume M2: salt.: {:02?}", salt);
    let key = &ctx.server.pair_verify.cv_key;
    let info = PAIR_VERIFY_M2_RESUME_INFO.as_bytes();
    hkdf_sha512(key, salt, info, result_key)?;
    info!("Pair Resume M2: ResponseKey.: {:02?}", result_key);
    let shifted_session_idx =
        (session_idx.start - request_key_idx.end)..(session_idx.end - request_key_idx.end);
    let session_id = &remainder[shifted_session_idx];
    info!("session_id: {:02?}", session_id);

    // with that key we encrypt some empty data.
    let encrypted_response = aead::encrypt(
        right_scratch,
        0,
        result_key,
        PAIR_VERIFY_M2_RESUME_NONCE.as_bytes(),
    )?;

    // Next up is creating the new shared secret.
    hkdf_sha512(
        key,
        salt,
        PAIR_VERIFY_M2_RESUME_SHARED_SECRET_INFO.as_bytes(),
        result_key,
    )?;
    // Huh, we just rotated the key here??
    ctx.server.pair_verify.cv_key.copy_from_slice(result_key);
    info!(
        "Pair Resume M2: cv_KEY.: {:02?}",
        ctx.server.pair_verify.cv_key
    );

    // NONCOMPLIANCE save session to cache.

    let mut writer = TLVWriter::new(data);
    writer = writer.add_slice(
        TLVType::State,
        ctx.server.pair_verify.setup.state.as_bytes(),
    )?;
    writer = writer.add_slice(
        TLVType::Method,
        ctx.server.pair_verify.setup.method.as_bytes(),
    )?;
    writer = writer.add_slice(TLVType::SessionID, session_id)?;
    writer = writer.add_slice(TLVType::EncryptedData, &encrypted_response)?;
    pair_verify_start_session(ctx, support)?;

    Ok(writer.end())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L708
// HAPPairingPairVerifyProcessM3
pub async fn pair_verify_process_m3(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    state: TLVState<'_>,
    encrypted_data: TLVEncryptedData<'_>,
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
    info!("decrypted: {:02?}", decrypted);

    let mut identifier = TLVIdentifier::tied(&decrypted);
    let mut signature = TLVSignature::tied(&decrypted);
    TLVReader::new(&decrypted).require_into(&mut [&mut identifier, &mut signature])?;
    info!("identifier: {:02?}", identifier);
    info!("signature {:02?}", signature);

    // need to retrieve pairing that we created during the setup now.
    let pairing_id = PairingId::from_tlv(&identifier)?;
    info!("pairing to retrieve: {:02?}", pairing_id);

    let pairing = support.get_pairing(&pairing_id).await?;
    info!("pairing retrieved: {:?}", pairing);

    let pairing = pairing.ok_or(PairingError::UnknownPairing)?;
    info!("found pairing: {:?}", pairing);

    // NONCOMPLIANCE reference stores session->state.pairVerify.pairingID = (int) key;, but we use the full pairing id?
    // do we need to track integers?
    ctx.session.pairing_id = pairing_id;

    // What's next, we collect: IOS public key, pairing id, accessory public key, check if signature matches that.
    // We use the 'right' slot in our scratch memory.

    let ios_device_pk_idx = 0..X25519_BYTES;
    let identifier_idx = ios_device_pk_idx.end..ios_device_pk_idx.end + identifier.len();
    let accessory_pk_idx = identifier_idx.end..identifier_idx.end + X25519_BYTES;
    let signature_idx = accessory_pk_idx.end..accessory_pk_idx.end + ED25519_BYTES;

    right[ios_device_pk_idx].copy_from_slice(&ctx.server.pair_verify.controller_cv_pk);
    identifier.copy_body(&mut right[identifier_idx])?;
    right[accessory_pk_idx].copy_from_slice(&ctx.server.pair_verify.cv_pk);
    signature.copy_body(&mut right[signature_idx.clone()])?;

    // Next, check if the signature matches.
    let public_key = pairing.public_key;
    let data = &right[0..X25519_BYTES + identifier.len() + X25519_BYTES];

    ed25519_verify(public_key.as_ref(), data, &right[signature_idx])?;
    info!("pairing checks out!");
    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L899
// HAPPairingPairVerifyGetM4
pub fn pair_verify_process_get_m4(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    info!("Pair Verify M4: Verify Finish Response.");

    // NONCOMPLIANCE: BLE Igorning pair resume

    let mut writer = TLVWriter::new(data);
    writer = writer.add_entry(TLVType::State, &ctx.server.pair_verify.setup.state)?;

    // Actually start the secure session.
    pair_verify_start_session(ctx, support)?;

    Ok(writer.end())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L25
// HAPPairingPairVerifyStartSession
pub fn pair_verify_start_session(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
) -> Result<(), PairingError> {
    let _ = support;
    ctx.server.pair_verify.setup.state = Default::default();
    // Do not wipe the session here, we already stored the pairing id into it.
    //ctx.session = Default::default();
    ctx.session.a_to_c.nonce = 0;
    ctx.session.c_to_a.nonce = 0;
    hkdf_sha512(
        &ctx.server.pair_verify.cv_key,
        CONTROL_CHANNEL_SALT.as_bytes(),
        CONTROL_CHANNEL_READ_KEY.as_bytes(),
        &mut ctx.session.a_to_c.key,
    )?;
    info!("a_to_c key: {:02?}", ctx.session.a_to_c.key);
    hkdf_sha512(
        &ctx.server.pair_verify.cv_key,
        CONTROL_CHANNEL_SALT.as_bytes(),
        CONTROL_CHANNEL_WRITE_KEY.as_bytes(),
        &mut ctx.session.c_to_a.key,
    )?;
    info!("c_to_a key: {:02?}", ctx.session.c_to_a.key);

    ctx.session.security_active = true;
    // Its now a non-transient session?
    ctx.session.transient = false;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_pair_verify_decode_verify_start() -> Result<(), PairingError> {
        let decrypted = [
            0x01, 0x24, 0x37, 0x37, 0x37, 0x35, 0x35, 0x44, 0x44, 0x35, 0x2d, 0x37, 0x32, 0x32,
            0x33, 0x2d, 0x34, 0x41, 0x33, 0x42, 0x2d, 0x38, 0x37, 0x44, 0x32, 0x2d, 0x43, 0x32,
            0x34, 0x41, 0x32, 0x34, 0x46, 0x34, 0x30, 0x36, 0x39, 0x35, 0x0a, 0x40, 0xd7, 0xe3,
            0xd6, 0x0a, 0xdf, 0x3b, 0x9d, 0xd9, 0x2d, 0x0a, 0x06, 0x80, 0x5f, 0x22, 0x7d, 0x29,
            0x23, 0xc1, 0xdf, 0x1d, 0x7a, 0x9d, 0x5e, 0x70, 0xca, 0x72, 0x78, 0x69, 0xb1, 0xc9,
            0x0e, 0xe0, 0x8d, 0x6f, 0x79, 0x4b, 0xfe, 0xd8, 0xae, 0x2a, 0x28, 0x23, 0x95, 0x8d,
            0x16, 0x5b, 0x98, 0x64, 0x5f, 0xbb, 0xf5, 0xf7, 0xaa, 0x33, 0xd4, 0x1e, 0x30, 0x67,
            0x82, 0x51, 0x1a, 0x00, 0xf1, 0x0a,
        ];
        let mut identifier = TLVIdentifier::tied(&decrypted);
        let mut signature = TLVSignature::tied(&decrypted);
        TLVReader::new(&decrypted).require_into(&mut [&mut identifier, &mut signature])?;
        let _pairing_id = PairingId::from_tlv(&identifier)?;
        Ok(())
    }
}
