// use bitfield_struct::bitfield;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::PlatformSupport;
use crate::crypto::{
    aead::{self, CHACHA20_POLY1305_KEY_BYTES},
    ed25519::{ed25519_sign, ed25519_verify},
    hkdf_sha512,
};

use crate::pairing::{
    ED25519_BYTES, PairContext, PairState, PairingError, PairingId, PairingMethod, TLVType,
    X25519_BYTES, tlv::*,
};
use crate::tlv::{TLVReader, TLVWriter};

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPSession.h#L153
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub struct Pairings {
    pub state: PairState,
    pub method: PairingMethod,
    pub error: u8,
    pub removed_pairing_id: Option<PairingId>,
    // Had removed pairing length
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairings.c#L765

// HAPPairingPairingsHandleWrite
pub async fn pairing_pairing_handle_incoming(
    ctx: &mut PairContext,
    support: &mut impl PlatformSupport,
    data: &[u8],
) -> Result<(), PairingError> {
    let _ = support;
    match ctx.server.pairings.state {
        PairState::NotStarted => {
            info!("pairing_pairing_handle_incoming started, so m1");
            let mut method = TLVMethod::tied(&data);
            let mut state = TLVState::tied(&data);
            let mut public_key = TLVPublicKey::tied(&data);
            //let mut session_id = TLVSessionId::tied(&data);
            let mut identifier = TLVIdentifier::tied(&data);
            let mut permissions = TLVPermissions::tied(&data);
            info!("before read into, data: {:02?}", data);
            for v in TLVReader::new(&data) {
                info!("v: {:?}", v);
            }
            // Only got 6 & 3??? state & public key? Only those are required, the rest are optional.
            TLVReader::new(&data)
                .require_into(&mut [&mut method, &mut state, &mut identifier])
                .map_err(|e| {
                    error!("missing {:?}", e);
                    e
                })?;

            TLVReader::new(&data).read_into(&mut [&mut public_key, &mut permissions])?;

            let method = *(method.try_from::<PairingMethod>()?);
            if method != PairingMethod::AddPairing
                && method != PairingMethod::RemovePairing
                && method != PairingMethod::ListPairings
            {
                return Err(PairingError::InvalidData);
            }
            info!("hit setup process m1");
            // info!("method: {:?}", method);
            // info!("state: {:?}", state);
            // info!("flags: {:?}", flags);

            ctx.server.pairings.method = method;
            ctx.server.pairings.state = PairState::ReceivedM1;

            if !ctx.session.security_active {
                // Deny on authentication,   not enough authentication.
                return Err(PairingError::AuthenticationError);
            }

            /*
            let pairing = support
                .get_pairing(&id)
                .await?
                .ok_or(PairingError::UnknownPairing)?;
            */
            // Nope, we retrieve the CURRENTLY active pairing for this session and verify we have permissions.
            let current_session_id = ctx.session.pairing_id;
            let session_pairing = support
                .get_pairing(&current_session_id)
                .await?
                .ok_or(PairingError::UnknownPairing)?;
            if (session_pairing.permissions & 0x01) == 0 {
                // Would be nice to make this into a nice enum...
                return Err(PairingError::AuthenticationError);
            }

            match ctx.server.pairings.method {
                PairingMethod::AddPairing => todo!("implement remove pairing"),
                PairingMethod::RemovePairing => {
                    let state = PairState::from_tlv(&state)?;
                    let identifier = PairingId::from_tlv(&identifier)?;
                    let r =
                        pair_pairings_remove_process_m1(ctx, support, method, state, identifier)
                            .await;
                    if r.is_err() {
                        ctx.server.pairings = Pairings::default();
                    }
                    r
                }
                PairingMethod::ListPairings => todo!("implement list pairing"),
                _ => return Err(PairingError::InvalidData), // also shielded above.
            }
        }

        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
    // NONCOMPLIANCE well, we need to clear the pairingpairing state;
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairings.c#L908
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairings.c#L962C10-L962C38
// HAPPairingPairingsHandleRead
pub async fn handle_outgoing(
    ctx: &mut PairContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    match ctx.server.pair_verify.setup.state {
        PairState::ReceivedM1 => {
            ctx.server.pairings.state = PairState::SentM2;
            pair_setup_process_get_m2(ctx, support, data).await
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairings.c#L351
//HAPPairingPairingsRemovePairingProcessM1
pub async fn pair_pairings_remove_process_m1(
    ctx: &mut PairContext,
    support: &mut impl PlatformSupport,
    method: PairingMethod,
    state: PairState,
    identifier: PairingId,
) -> Result<(), PairingError> {
    if method != PairingMethod::RemovePairing {
        return Err(PairingError::IncorrectState);
    }
    if state != PairState::ReceivedM1 {
        return Err(PairingError::IncorrectState);
    }

    // Nope, we don't yet remove it... we copy it for the next stage >_<
    //support.remove_pairing(&identifier).await?;

    // NONCOMPLIANCE why do they store session->state.pairings.removedPairingIDLength ??
    ctx.server.pairings.removed_pairing_id = Some(identifier);
    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairings.c#L443
pub async fn pair_setup_process_get_m2(
    ctx: &mut PairContext,
    support: &mut impl PlatformSupport,
    data: &mut [u8],
) -> Result<usize, PairingError> {
    if (ctx.server.pairings.method != PairingMethod::RemovePairing) {
        return Err(PairingError::IncorrectState);
    }
    if ctx.server.pairings.state != PairState::SentM2 {
        return Err(PairingError::IncorrectState);
    }
    todo!();
}
