// use bitfield_struct::bitfield;
// use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::pairing::{
    PairContext, PairState, PairSupport, PairingError, PairingMethod, X25519_BYTES, tlv::*,
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

    todo!();

    let mut writer = TLVWriter::new(data);

    Ok(writer.end())
}
