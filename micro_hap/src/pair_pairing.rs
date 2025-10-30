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
    pub removed_pairing_id: PairingId,
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
            info!("not started, so m1");
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

            info!("pair_verify_process_m1 next");
            todo!()
        }

        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
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
            todo!()
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}
