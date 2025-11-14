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
