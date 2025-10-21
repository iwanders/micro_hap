use crate::crypto::hkdf_sha512;
use crate::pairing::{PairContext, PairingError};
use crate::{CharId, PlatformSupport};
// Some helpers to handle the whole broadcast key and global state number stuff.

#[derive(Copy, Clone, Default, Debug)]
pub struct BleBroadcastParameters {
    pub expiration_gsn: u16,
    pub key: crate::pairing::PairingPublicKey,
    pub advertising_id: Option<crate::DeviceId>,
}

// https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEAccessoryServer%2BBroadcast.c#L100
pub async fn broadcast_generate_key(
    ctx: &mut PairContext,
    support: &mut impl PlatformSupport,
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
        .get_pairing(&ctx.session.pairing_id)
        .await?
        .ok_or(PairingError::UnknownPairing)?;
    info!("pairing retrieved: {:?}", pairing);

    let output_key = &mut parameters.key.0[..];
    let key = &ctx.server.pair_verify.cv_key;
    let salt = &pairing.public_key.0;
    let info = "Broadcast-Encryption-Key".as_bytes();
    hkdf_sha512(key, salt, info, output_key)?;
    info!("Broadcast key: {:02?}", parameters.key);

    // NONCOMPLIANCE if advertising id.

    support.set_ble_broadcast_parameters(&parameters)?;

    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLECharacteristic%2BBroadcast.c#L208
// https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLECharacteristic%2BBroadcast.c#L317
// Combination of HAPBLECharacteristicEnableBroadcastNotifications and HAPBLECharacteristicDisableBroadcastNotifications
//
// also an hint is https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLECharacteristic%2BBroadcast.c#L135
pub fn configure_broadcast_notification(
    broadcast_enabled: bool,
    interval: super::pdu::BleBroadcastInterval,
    char_id: CharId,
) -> Result<(), super::HapBleError> {
    let _ = (broadcast_enabled, interval);
    // How does this work is it just 3 bytes ( bool | interval[0,1] )

    // NONCOMPLIANCE: Completely ignoring this whole broadcast thing.
    error!(
        "skipping broadcast configuration for char id 0x{:02?}",
        char_id
    );
    Ok(())
}
