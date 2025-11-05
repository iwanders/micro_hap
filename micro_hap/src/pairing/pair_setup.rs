use zerocopy::IntoBytes;
//
use crate::tlv::{TLVReader, TLVWriter};

use crate::crypto::{
    aead, ed25519::ed25519_create_public, ed25519::ed25519_sign, ed25519::ed25519_verify,
    hkdf_sha512, homekit_srp_server,
};
use crate::{AccessoryContext, PlatformSupport};

use super::tlv::*;
use super::{
    ED25519_BYTES, ED25519_LTPK, SRP_PREMASTER_SECRET_BYTES, SRP_PROOF_BYTES, SRP_USERNAME,
};
use super::{
    PairState, Pairing, PairingError, PairingId, PairingMethod, PairingPublicKey, TLVType,
};

// Salt and info for the session key.
pub const PAIR_SETUP_ENCRYPT_SALT: &'static str = "Pair-Setup-Encrypt-Salt";
pub const PAIR_SETUP_ENCRYPT_INFO: &'static str = "Pair-Setup-Encrypt-Info";

// Salt and info for the control channel.
pub const CONTROL_CHANNEL_SALT: &'static str = "SplitSetupSalt";
pub const CONTROL_CHANNEL_ACCESSORY: &'static str = "AccessoryEncrypt-Control";
pub const CONTROL_CHANNEL_CONTROLLER: &'static str = "ControllerEncrypt-Control";

// Message stage specific nonces
pub const PAIR_SETUP_M5_NONCE: &'static str = "PS-Msg05";
pub const PAIR_SETUP_M5_SIGN_SALT: &'static str = "Pair-Setup-Controller-Sign-Salt";
pub const PAIR_SETUP_M5_SIGN_INFO: &'static str = "Pair-Setup-Controller-Sign-Info";

pub const PAIR_SETUP_M6_NONCE: &'static str = "PS-Msg06";
pub const PAIR_SETUP_M6_SIGN_SALT: &'static str = "Pair-Setup-Accessory-Sign-Salt";
pub const PAIR_SETUP_M6_SIGN_INFO: &'static str = "Pair-Setup-Accessory-Sign-Info";

// HAPPairingPairSetupHandleWrite
pub async fn pair_setup_handle_incoming(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &[u8],
) -> Result<(), PairingError> {
    let _ = support;
    let r = match ctx.server.pair_setup.setup.state {
        PairState::NotStarted => {
            info!("not started, so m1");
            let mut method = TLVMethod::tied(&data);
            let mut state = TLVState::tied(&data);
            //let mut flags = TLVFlags::tied(&data);
            info!("before read into, data: {:02?}", data);
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
            ctx.server.pair_setup.setup.state = PairState::ReceivedM3;
            pair_setup_process_m3(ctx, state, public_key, proof)
        }
        PairState::SentM4 => {
            info!("HAPPairingPairSetupProcessM5 & pair_setup_process_m5");
            let mut state = TLVState::tied(&data);

            let mut encrypted_data = TLVEncryptedData::tied(&data);
            TLVReader::new(&data).require_into(&mut [&mut state, &mut encrypted_data])?;
            ctx.server.pair_setup.setup.state = PairState::ReceivedM5;
            pair_setup_process_m5(ctx, support, state, encrypted_data).await
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    };
    if r.is_err() {
        info!("An error occured, resetting the pairing setup state.");
        ctx.server.pair_setup = Default::default();
    };

    r
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L1406
// HAPPairingPairSetupHandleRead
pub async fn pair_setup_handle_outgoing(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    let r = match ctx.server.pair_setup.setup.state {
        PairState::ReceivedM1 => {
            // Advance the state, and write M2.
            ctx.server.pair_setup.setup.state = PairState::SentM2;
            pair_setup_process_get_m2(ctx, support, data).await
        }
        PairState::ReceivedM3 => {
            // Advance the state, and write M2.
            ctx.server.pair_setup.setup.state = PairState::SentM4;
            pair_setup_process_get_m4(ctx, support, data)
        }
        PairState::ReceivedM5 => {
            // Advance the state, and write M6.
            ctx.server.pair_setup.setup.state = PairState::SentM6;
            pair_setup_process_get_m6(ctx, support, data).await
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    };

    if r.is_err() || ctx.server.pair_setup.setup.state == PairState::SentM6 {
        info!("Clearing pairing setup state.");
        ctx.server.pair_setup = Default::default();
    }
    r
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L48
// HAPPairingPairSetupProcessM1
pub fn pair_setup_process_m1(
    ctx: &mut AccessoryContext,
    method: TLVMethod,
    state: TLVState,
) -> Result<(), PairingError> {
    let method = method.try_from::<PairingMethod>()?;
    info!("hit setup process m1");
    // info!("method: {:?}", method);
    // info!("state: {:?}", state);
    // info!("flags: {:?}", flags);

    ctx.server.pair_setup.setup.method = *method;
    // NONCOMPLIANCE: flags present is not set to false.
    //ctx.server.flags = PairingFlags::from_bits(flags.to_u32()?);
    ctx.server.pair_setup.setup.state = *state.try_from::<PairState>()?;

    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L342
// HAPPairingPairSetupProcessM3
pub fn pair_setup_process_m3(
    ctx: &mut AccessoryContext,
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
    ctx.server.pair_setup.setup.state = state;
    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L833
// HAPPairingPairSetupProcessM5
pub async fn pair_setup_process_m5(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    state: TLVState<'_>,
    encrypted_data: TLVEncryptedData<'_>,
) -> Result<(), PairingError> {
    info!("Pair Setup M5: Exchange Request.");

    let state = *state.try_from::<PairState>()?;
    if state != PairState::ReceivedM5 {
        return Err(PairingError::IncorrectState);
    }
    info!("encrypted_data: {:?}", encrypted_data);

    // Write the data to the buffer first to ensure contiguous data

    // NONCOMPLIANCE: use of ephemeral B, but we don't need that anymore at this point and it's available memory.
    // left holds the encrypted & decrypted data, with leaves right as a scratchpad. Encrypted data is 154 bytes, the
    // B size is 384, so that leaves 230 for the right side.
    let (left, right) = ctx.server.pair_setup.B.split_at_mut(encrypted_data.len());
    encrypted_data.copy_body(left)?;
    let key = &ctx.server.pair_setup.session_key;
    let data = left;
    let decrypted = aead::decrypt(data, key, &PAIR_SETUP_M5_NONCE.as_bytes())?;
    info!("decrypted: {:02?}", decrypted);

    let mut identifier = TLVIdentifier::tied(&decrypted);
    let mut public_key = TLVPublicKey::tied(&decrypted);
    let mut signature = TLVSignature::tied(&decrypted);
    TLVReader::new(&decrypted).require_into(&mut [
        &mut identifier,
        &mut public_key,
        &mut signature,
    ])?;
    info!("identifier: {:02?}", identifier);
    info!("public_key: {:02?}", public_key);
    info!("signature: {:02?}", signature);

    // NONCOMPLIANCE not checking the sizes of the above things.

    // Now we are here: https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L963
    // Are those alloc & alloc unaligned consecutive?
    // And we're all setup to do more more hashing of things.
    // ltpk  long term pairing key?
    const X_LENGTH: usize = 32;

    let key = &ctx.server.pair_setup.K;
    let salt = &PAIR_SETUP_M5_SIGN_SALT.as_bytes();
    let info = &PAIR_SETUP_M5_SIGN_INFO.as_bytes();
    hkdf_sha512(key, salt, info, &mut right[0..X_LENGTH])?;

    let identifier_start = X_LENGTH;
    let identifier_end = X_LENGTH + identifier.len();
    identifier.copy_body(&mut right[identifier_start..identifier_end])?;

    let public_key_start = identifier_start + identifier.len();
    let public_key_end = public_key_start + public_key.len();
    public_key.copy_body(&mut right[public_key_start..public_key_end])?;

    let sig_start = public_key_end;
    let sig_end = public_key_end + signature.len();
    signature.copy_body(&mut right[sig_start..sig_end])?;

    let iosdevice_info = &right[0..X_LENGTH + identifier.len() + public_key.len()];
    info!("iosdevice_info: {:02?}", iosdevice_info);

    // Now we need to verify that;
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L988-L991
    let public_key_buffer = &right[public_key_start..public_key_end];
    let signature_buffer = &right[sig_start..sig_end];
    ed25519_verify(public_key_buffer, iosdevice_info, signature_buffer)
        .map_err(|_| PairingError::BadSignature)?;

    // Next up is saving the pairing id and long term pairing key.
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L999

    //Pairing
    let identifier_buffer = &right[identifier_start..identifier_end];
    let id = PairingId::parse_str(identifier_buffer)?;
    info!("identifier: {:?}", id);
    let public_key = PairingPublicKey::from(public_key_buffer)?;

    let pairing = Pairing {
        id,
        public_key,
        permissions: 1,
    };
    support.store_pairing(&pairing).await?;

    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L158
pub async fn pair_setup_process_get_m2(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    info!("Pair Setup M2: SRP Start Response.");
    // NONCOMPLIANCE: Check if accessory is already paired.
    // NONCOMPLIANCE: Check if accessory has received more than 100 unsuccesful attempts
    // NONCOMPLIANCE: Keep invalid authentication counter.
    let mut is_transient: bool = false;
    let mut is_split: bool = false;
    if ctx.server.pair_setup.flags.transient() {
        if ctx.server.pair_setup.setup.method == PairingMethod::PairSetupWithAuth {
            // What does this mean!?
            warn!("pair setup M2; ignoring because pair setup with auth was requested");
        } else {
            if ctx.server.pair_setup.setup.method != PairingMethod::PairSetup {
                error!("method should be pair setup");
                return Err(PairingError::IncorrectMethodCombination);
            }
            is_transient = true;
        }
    }
    if ctx.server.pair_setup.flags.split() {
        if ctx.server.pair_setup.setup.method == PairingMethod::PairSetupWithAuth {
            // What does this mean!?
            warn!("pair setup M2; ignoring because pair setup with auth was requested");
        } else {
            if ctx.server.pair_setup.setup.method != PairingMethod::PairSetup {
                error!("method should be pair setup");
                return Err(PairingError::IncorrectMethodCombination);
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
    support.fill_random(&mut ctx.server.pair_setup.b).await;
    info!("random b: {:?}", &ctx.server.pair_setup.b);
    // Then, we derive the public key B.

    let server = homekit_srp_server();

    info!("Going into public ephemeral");
    // Calculate the public ephemeral data.
    server.compute_public_ephemeral(
        &ctx.server.pair_setup.b,
        &ctx.info.verifier,
        &mut ctx.server.pair_setup.B,
    );
    // info!("ephemeral B: {:?}", &ctx.server.pair_setup.B);
    //todo!("need to write public ephemeral into B");
    //
    // Now we need a TLV writer; https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L264

    let mut writer = TLVWriter::new(data);

    info!(
        "writing setup state: {:?}",
        &ctx.server.pair_setup.setup.state
    );
    writer = writer.add_entry(TLVType::State, &ctx.server.pair_setup.setup.state)?;

    // NONCOMPLIANCE: They skip leading zeros, do we need that? Sounds like a minor improvement?
    info!("writing B: ");
    writer = writer.add_slice(TLVType::PublicKey, &ctx.server.pair_setup.B)?;

    info!("writing salt: {:?}", &ctx.info.salt);
    writer = writer.add_slice(TLVType::Salt, &ctx.info.salt)?;

    // Make flags, we only needed this during the software authentication approach from the start.
    /*
    let flags = PairingFlags::new()
        .with_split(is_split)
        .with_transient(is_transient);

    writer = writer.add_entry(TLVType::Flags, &flags)?;
    */

    info!("returning");
    Ok(writer.end())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L430
pub fn pair_setup_process_get_m4(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    let _ = support;

    info!("Pair Setup M4: SRP Verify Response.");
    let server = homekit_srp_server();

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

    info!("premaster: {:02?}", &premaster);

    server.session_key(&premaster, &mut ctx.server.pair_setup.K);

    // What's the difference between K and S? First 64 bytes of S seems to be K?
    info!("Calculated K: {:02?}", ctx.server.pair_setup.K);

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

    info!("got_m1: {:02?}", ctx.server.pair_setup.m1);
    info!("calculated_m1: {:02?}", calculated_m1);
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
    info!("calculated_m2: {:02?}", ctx.server.pair_setup.m2);

    // oh, now we need something with hkdf_sha512...

    hkdf_sha512(
        &ctx.server.pair_setup.K,
        PAIR_SETUP_ENCRYPT_SALT.as_bytes(),
        PAIR_SETUP_ENCRYPT_INFO.as_bytes(),
        &mut ctx.server.pair_setup.session_key,
    )?;
    info!(
        "ctx.server.pair_setup.session_key: {:02?}",
        ctx.server.pair_setup.session_key
    );

    // That concludes the session key... next we can start writing the response.

    let mut writer = TLVWriter::new(data);

    writer = writer.add_entry(TLVType::State, &ctx.server.pair_setup.setup.state)?;

    writer = writer.add_entry(TLVType::Proof, &ctx.server.pair_setup.m2)?;

    if ctx.server.pair_setup.setup.method == PairingMethod::PairSetupWithAuth {
        todo!();
    }

    if ctx.server.pair_setup.setup.method == PairingMethod::PairSetup
        && ctx.server.pair_setup.flags.transient()
    {
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
        info!("a_to_c key: {:02?}", ctx.session.a_to_c.key);
        hkdf_sha512(
            &ctx.server.pair_setup.K,
            CONTROL_CHANNEL_SALT.as_bytes(),
            CONTROL_CHANNEL_CONTROLLER.as_bytes(),
            &mut ctx.session.c_to_a.key,
        )?;
        info!("c_to_a key: {:02?}", ctx.session.c_to_a.key);

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

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L1041
pub async fn pair_setup_process_get_m6(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    let _ = support;
    info!("Pair Setup M6: Exchange Response.");

    // We need a sub-TLV writer.
    // We need our own device id.
    // We need ed_LTSK, ed25519_Long_Term_Secret_Key?
    // We need the public key for that, which is what we send.
    // This is basically the counterpart to m5, but then just from our side.
    // We encrypt this sub-tlv parser.
    // Then we reset the pair setup data.

    // NONCOMPLIANCE, though this shouldn't matter, we get the ed_ltsk key from the support and it's not generated
    // if it doesn't exist, it's hardcoded.
    //
    // NONCOMPLIANCE: Again (ab) using the B buffer.
    let scratch = &mut ctx.server.pair_setup.B;

    let device_id_str = ctx.accessory.device_id.to_device_id_string();

    let mut writer = TLVWriter::new(data);
    writer = writer.add_entry(TLVType::State, &ctx.server.pair_setup.setup.state)?;

    // Make the public key and append that.
    let mut public_key = [0u8; ED25519_LTPK];
    ed25519_create_public(&support.get_ltsk().await, &mut public_key)
        .map_err(|_| PairingError::IncorrectLength)?;

    // Next, create the aspects to sign.
    //https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairSetup.c#L1123
    const X_LENGTH: usize = 32;
    // Concatenation of hash, pairing id, long term public key.

    let identifier = device_id_str.0.as_bytes();

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
        let secret_key = support.get_ltsk().await;
        let (data, signature) = scratch.split_at_mut(sig_start);
        ed25519_sign(&secret_key, data, &mut signature[0..ED25519_BYTES])
            .map_err(|_| PairingError::IncorrectLength)?;
    }

    let (pre_calc, subwriter_scratch) = scratch.split_at_mut(sig_end);

    let mut subwriter = TLVWriter::new(subwriter_scratch);
    subwriter = subwriter.add_slice(TLVType::Identifier, device_id_str.as_bytes())?;
    subwriter = subwriter.add_slice(TLVType::PublicKey, &public_key)?;
    subwriter = subwriter.add_slice(TLVType::Signature, &pre_calc[sig_start..sig_end])?;
    let subwriter_length = subwriter.end();

    // Now we need to encrypt the data in the subwriter.
    let key = &ctx.server.pair_setup.session_key;
    info!("key: {:?}", key);
    let encrypted_sub = aead::encrypt(
        subwriter_scratch,
        subwriter_length,
        key,
        &PAIR_SETUP_M6_NONCE.as_bytes(),
    )?;

    writer = writer.add_slice(TLVType::EncryptedData, &encrypted_sub)?;

    Ok(writer.end())
}

#[cfg(test)]
pub mod test {

    use super::*;
    use crate::pairing::{SetupInfo, test::TestPairSupport};

    #[tokio::test]
    async fn test_pairing_handle_setup() -> Result<(), PairingError> {
        crate::test::init();

        let recorded = recorded_info();

        let mut ctx = AccessoryContext::default();
        ctx.info = recorded.setup_info;

        let mut support = TestPairSupport::default();
        support.add_random(&recorded.random_b);

        pair_setup_handle_incoming(&mut ctx, &mut support, &recorded.incoming_0).await?;

        let mut buffer = [0u8; 1024];

        pair_setup_handle_outgoing(&mut ctx, &mut support, &mut buffer).await?;

        info!("recorded.public_B: {:x?}", recorded.public_B);
        info!("srvr.pair_setup.B: {:x?}", ctx.server.pair_setup.B);

        // Afer this, the public ephemeral should match.
        assert_eq!(recorded.public_B, ctx.server.pair_setup.B);

        // This is M3: SRP Verify Request.
        pair_setup_handle_incoming(&mut ctx, &mut support, &recorded.incoming_1).await?;
        let mut buffer = [0u8; 1024];

        // This is M4: SRP verify response.
        let l = pair_setup_handle_outgoing(&mut ctx, &mut support, &mut buffer).await?;
        let response = &buffer[0..l];
        info!("m4 response: {:02?}", &response);
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
    fn test_pairing_m6_decoded() {
        crate::test::init();
        // Not really a test, but I need to look into this payload, this is the easiest.
        let encrypted_data = [
            192, 45, 171, 153, 243, 156, 47, 235, 64, 180, 136, 231, 140, 158, 15, 122, 19, 226,
            74, 90, 215, 102, 201, 43, 69, 214, 114, 119, 129, 18, 172, 87, 21, 141, 177, 174, 98,
            122, 105, 12, 238, 248, 235, 49, 61, 57, 191, 107, 31, 200, 22, 87, 11, 6, 240, 86, 69,
            135, 250, 51, 146, 154, 105, 60, 235, 73, 200, 156, 6, 251, 190, 191, 236, 247, 96,
            186, 11, 235, 77, 138, 190, 98, 154, 231, 22, 220, 161, 97, 72, 61, 43, 120, 17, 117,
            239, 226, 176, 99, 254, 108, 58, 134, 140, 28, 34, 157, 207, 58, 184, 97, 56, 24, 51,
            9, 84, 232, 241, 185, 23, 163, 129, 254, 112, 80, 6, 122, 159, 209, 41, 133, 85, 119,
            99, 158, 4,
        ];
        let mut decryption_buffer = encrypted_data;
        let key = &[
            206, 14, 137, 60, 232, 100, 218, 42, 115, 83, 32, 92, 144, 95, 155, 29, 45, 243, 225,
            216, 68, 212, 247, 91, 8, 128, 116, 85, 71, 189, 114, 64,
        ];
        let decrypted =
            aead::decrypt(&mut decryption_buffer, key, &PAIR_SETUP_M6_NONCE.as_bytes()).unwrap();
        info!("decrypted: {:02?}", decrypted);
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
