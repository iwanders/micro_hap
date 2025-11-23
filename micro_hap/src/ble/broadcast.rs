use zerocopy::IntoBytes;

use crate::crypto::hkdf_sha512;
use crate::pairing::PairingError;
use crate::{AccessoryContext, CharId, InterfaceError, PlatformSupport};

// Some helpers to handle the whole broadcast key and global state number stuff.

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Copy, Clone, Default, Debug)]
pub struct BleBroadcastParameters {
    pub expiration_gsn: u16,
    pub key: crate::pairing::PairingPublicKey,
    pub advertising_id: Option<crate::DeviceId>,
}

// https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEAccessoryServer%2BBroadcast.c#L100
pub async fn broadcast_generate_key(
    ctx: &mut AccessoryContext,
    support: &mut impl PlatformSupport,
    // NONCOMPLIANCE: advertising id
) -> Result<(), PairingError> {
    let mut parameters = support.get_ble_broadcast_parameters().await?;

    let gsn = support.get_global_state_number().await?;

    parameters.expiration_gsn = gsn.wrapping_add(32767 - 1);

    // NONCOMPLIANCE: setting the advertising id to the device id here, this function could get a advertising id passed
    // in, but we never see that being passed.
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

    support.set_ble_broadcast_parameters(&parameters).await?;

    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L85
//
// They have some calls to HAPBLEAdvertisingIntervalCreateFromMilliseconds but I think that's handled at another layer for us?
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/PAL/HAPBase.h#L227-L238
pub async fn get_advertising_parameters(
    char_id: CharId,
    data: &mut [u8],
    value: &[u8; 8],
    support: &mut impl PlatformSupport,
) -> Result<usize, InterfaceError> {
    let parameters = support.get_ble_broadcast_parameters().await?;

    // Get the current gsn;
    let gsn = support.get_global_state_number().await?;
    // info!("gsn: {:?}", gsn);

    //
    // Similar to to_advertisement from AdvertisementConfig we start at the section after the company identifier.
    data[0] = 0x11; // TY
    data[1] = 0x36; // STL
    // adv id

    let mut p = 2;
    // Here, the adverising ID must exist.
    let advertising_id = parameters.advertising_id.unwrap(); // This is an assert in reference, so should be fine?
    // info!("Advertising id: {:?}", advertising_id);
    data[p..(p + 6)].copy_from_slice(&advertising_id.0);
    p += 6;

    // Now, encrypted bytes start?
    // encrypted = data[9..]
    let encr = p;
    data[p..(p + 2)].copy_from_slice(&gsn.as_bytes());
    p += 2;

    // There's an iid here... what is it? :O  server->ble.adv.broadcastedEvent.iid
    // It is just the CharId?
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L993
    data[p..(p + 2)].copy_from_slice(&char_id.as_bytes());
    p += 2;

    // Then, the value.
    data[p..(p + value.len())].copy_from_slice(value);
    p += value.len();
    // info!("value: {:?}", value);
    // info!("data: {:?}", data);
    // Next, we do an authenticated encrypted with authenticated data...
    let buffer = &mut data[encr..p];
    let assocated_data = &advertising_id.0;
    let key = parameters.key.as_ref();
    // info!("key: {:?}", key);
    let gsn_u64: u64 = gsn as u64;
    let nonce = gsn_u64.as_bytes();
    let tag = crate::crypto::aead::encrypt_aad(buffer, assocated_data, key, nonce).unwrap();

    // Next, we truncate the tag to the left most four bytes.
    data[p..(p + 4)].copy_from_slice(&tag[0..4]);
    p += 4;

    Ok(p)
}
