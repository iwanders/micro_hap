use crate::crypto::hkdf_sha512;
use crate::pairing::{PairContext, PairSupport, PairingError};
// Some helpers to handle the whole broadcast key and global state number stuff.

#[derive(Copy, Clone, Default, Debug)]
pub struct BleBroadcastParameters {
    pub expiration_gsn: u16,
    pub key: crate::pairing::PairingPublicKey,
    pub advertising_id: Option<crate::DeviceId>,
}

// https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEAccessoryServer%2BBroadcast.c#L100
pub fn broadcast_generate_key(
    ctx: &mut PairContext,
    support: &mut impl PairSupport,
    // NONCOMPLIANCE: advertising id
) -> Result<(), PairingError> {
    let mut parameters = support.get_ble_broadcast_parameters()?;

    let gsn = support.get_global_state_number()?;

    parameters.expiration_gsn = gsn.wrapping_add(32767 - 1);

    // NONCOMPLIANCE: setting the advertising id to the device id here.
    parameters.advertising_id = Some(ctx.accessory.device_id);

    // Fetch controller's public key.
    info!("Retrieving pairing id: {:?}", ctx.session.pairing_id);

    let pairing = support
        .get_pairing(&ctx.session.pairing_id)?
        .ok_or(PairingError::UnknownPairing)?;
    info!("pairing retrieved: {:?}", pairing);

    let output_key = &mut parameters.key.0[..];
    let key = &ctx.server.pair_verify.cv_key;
    let salt = &pairing.public_key.0;
    let info = "Broadcast-Encryption-Key".as_bytes();
    hkdf_sha512(key, salt, info, output_key)?;
    info!("Broadcast key: {:0>2x?}", parameters.key);

    // NONCOMPLIANCE if advertising id.

    support.set_ble_broadcast_parameters(&parameters)?;

    Ok(())
}
