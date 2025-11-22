use zerocopy::IntoBytes;

use crate::ble::HapBleError;
use crate::crypto::hkdf_sha512;
use crate::pairing::PairingError;
use crate::{AccessoryContext, CharId, PlatformSupport};

/*

What's the deal with all this broadcasting?

There seem to be two types.
    - The normal; I am here broadcast
    - Broadcasts that pertain to a characteristic.


Following the path of a accesory notifying the HAP Server.
    From app.c; trigger to HAPAccessoryServerRaiseEvent
        https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/App.c#L189
    From HAPAccessoryServer.c;
        https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessoryServer.c#L1161
        Dispatch based on transport, ble to HAPBLEAccessoryServerDidRaiseEvent
            https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer.c#L206
    Which gets us to HAPBLEAccessoryServerDidRaiseEvent
        https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L698
        First check if if the characteristic supports event notification, if so, and not being written to atm:
            HAPBLEPeripheralManagerRaiseEvent
                https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEPeripheralManager.c#L1637
            Which sets a pending notificaiton, does some gatt stuff and calls
                SendPendingEventNotifications  https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEPeripheralManager.c#L279
                Then into HAPPlatformBLEPeripheralManagerSendHandleValueIndication https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEPeripheralManager.c#L279

                Which seems to go to the hardware?
                    for Darwin it does an updateCharacteristic: https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/PAL/Darwin/HAPPlatformBLEPeripheralManager.m#L673
                    This seems to be always called with an empty payload;
                        Does that just indicate a flag that says; this is changed?
                trouble_host::attribute::Characteristic::notify ...
                    We need some elegant way to to tell micro_hap to notify on characteristics that changed.


        This actually calculates the advertisement payload and passes that to updateAdvertisingData.
        There's also a timer being set, possibly to disable the characteristic broadcast again?
        Actual advertisement payload seems to be happening here: HAPBLEAccessoryServerGetAdvertisingParameters
            https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L85

        That also has the normal broadcast spec.
            Also something with times here https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L246


    So 759eaca1278b99e82029785f79e56a27262421e2 added a great hack to explore notifications.

    The problem is that iOS doesn't actually subscribe to my notifications, force sending it does work.

    What's more, the one single characteristic that has indicate, loses the indicate flag if we read it from NRF Connect.
    This does NOT happen if we modify the bas peripheral; https://github.com/embassy-rs/trouble/blob/bb61f8a0b8e84b4afa175674a56c91b6e545acd3/examples/apps/src/ble_bas_peripheral.rs#L24
    to have indicate, in that case a read does NOT make the indicate attribute go away.

    Are we replying incorrectly? Okay, probably not, the problem was that one ON characteristic had indicate, but the other didn't, because of that we lost it.

    Still doesn't make iOS properly register though.

    Separate issue...
        The second lightbulb services has no characteristics, this is despite the characteristics being correctly responded with?
        Is this an NRF connect display issue, or an actual problem?
        Lets assume it is not a problem for now, we should try with a single bulb, see if iOS then subscribes to the notify.

    On timing; https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L246-L253
        Normal advertise:
            - 20ms for 30s after boot.
            - 20ms for 3s after disconnect.
            - Regular interval, whatever that is otherwise.

 */

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

    support.set_ble_broadcast_parameters(&parameters).await?;

    Ok(())
}

// https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLECharacteristic%2BBroadcast.c#L208
// https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLECharacteristic%2BBroadcast.c#L317
// Combination of HAPBLECharacteristicEnableBroadcastNotifications and HAPBLECharacteristicDisableBroadcastNotifications
//
// also an hint is https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLECharacteristic%2BBroadcast.c#L135
/*
pub fn configure_broadcast_notzification(
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
}*/

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L85
//
// They have some calls to HAPBLEAdvertisingIntervalCreateFromMilliseconds but I think that's handled at another layer for us?
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/PAL/HAPBase.h#L227-L238
pub async fn get_advertising_parameters(
    char_id: CharId,
    data: &mut [u8],
    value: &[u8; 8],
    support: &mut impl PlatformSupport,
) -> Result<Option<usize>, HapBleError> {
    let parameters = support.get_ble_broadcast_parameters().await?;

    if parameters.expiration_gsn == 0 {
        return Ok(None);
    }
    // Get the current gsn;
    let gsn = support.get_global_state_number().await?;
    info!("gsn: {:?}", gsn);

    let interval = support.get_ble_broadcast_configuration(char_id).await?;
    // Advertisinginterval is u16?
    //
    // Similar to to_advertisement from AdvertisementConfig we start at the section after the company identifier.
    data[0] = 0x11; // TY
    data[1] = 0x36; // STL
    // adv id

    let mut p = 2;
    // Here, the adverising ID must exist.
    let advertising_id = parameters.advertising_id.unwrap(); // This is an assert in reference, so should be fine?
    info!("Advertising id: {:?}", advertising_id);
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
    info!("value: {:?}", value);
    info!("data: {:?}", data);
    // Next, we do an authenticated encrypted with authenticated data...
    let buffer = &mut data[encr..p];
    let assocated_data = &advertising_id.0;
    let key = parameters.key.as_ref();
    info!("key: {:?}", key);
    let gsn_u64: u64 = gsn as u64;
    let nonce = gsn_u64.as_bytes();
    let tag = crate::crypto::aead::encrypt_aad(buffer, assocated_data, key, nonce).unwrap();

    // Next, we truncate the tag to the left most four bytes.
    data[p..(p + 4)].copy_from_slice(&tag[0..4]);
    p += 4;

    Ok(Some(p))
}
