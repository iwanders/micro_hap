use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::pairing::{PairContext, PairState, PairSupport, PairingError, tlv::*};
use crate::tlv::{TLV, TLVError, TLVReader, TLVWriter};
use uuid;

use crate::crypto::{
    aead, aead::CHACHA20_POLY1305_KEY_BYTES, ed25519::ed25519_create_public, ed25519::ed25519_sign,
    ed25519::ed25519_verify, hkdf_sha512, homekit_srp,
};

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L972

// HAPPairingPairVerifyHandleWrite
pub fn handle_incoming(
    ctx: &mut PairContext,
    support: &PairSupport,
    data: &[u8],
) -> Result<(), PairingError> {
    let _ = support;
    match ctx.setup.state {
        PairState::NotStarted => {
            info!("not started, so m1");
            // let mut method = TLVMethod::tied(&data);
            // let mut state = TLVState::tied(&data);
            //let mut flags = TLVFlags::tied(&data);
            // info!("before read into, data: {:0>2x?}", data);
            // TLVReader::new(&data).require_into(&mut [&mut method, &mut state])?;

            info!("pair_verify_process_m1 next");
            pair_verify_process_m1(ctx)
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
    match ctx.setup.state {
        PairState::ReceivedM1 => {
            // Advance the state, and write M2.
            // ctx.setup.state = PairState::SentM2;
            todo!();
            // pair_setup_process_get_m2(ctx, support, data)
        }
        catch_all => {
            todo!("Unhandled state: {:?}", catch_all);
        }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairVerify.c#L135C17-L135C46
// HAPPairingPairVerifyProcessM1
pub fn pair_verify_process_m1(ctx: &mut PairContext) -> Result<(), PairingError> {
    todo!();
    info!("hit verify process m1");

    Ok(())
}
