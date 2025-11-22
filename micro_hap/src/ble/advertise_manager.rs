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
    This is solved because notify != indicate and I filed a PR to add support for indicate.
    Also be careful with the GattEvent handling as it can gobble up writes to the gatt's CCCD entries.

    On timing; https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L246-L253
        Normal advertise:
            - 20ms for 30s after boot.
            - 20ms for 3s after disconnect.
            - Regular interval, whatever that is otherwise.
        Broadcast advertise:
            - 3s period with broadcast interval. https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L775-L780

    On GSN:
        For characteristics that have supportsBroadcastNotification:
            - GSN Advance occurs for any characteristic that does broadcasts? https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L969
            - Shall advertise for 3s, see above. If change during interval, increment again and reset time, send new value.
        For characteristic that have supportsDisconnectedNotification:
            - GSN Advances once for the connected/disconnected state. https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L1036-L1044
        While connected:
            - Only one advance ever.
 */

use crate::{Characteristic, CharacteristicProperties, InterfaceError, PlatformSupport};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
enum AdvertisementMode {
    Broadcast,
    #[default]
    General,
}

// A helper for the whole gsn and advertisement handling and timing.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct AdvertiseManager {
    gsn_advanced_in_connected_state: bool,
    is_connected: bool,
    mode: AdvertisementMode,
}

impl AdvertiseManager {
    pub fn startup() -> Self {
        Self {
            ..Default::default()
        }
    }
    pub fn state_connected(&mut self, connected: bool) {
        if connected != self.is_connected {
            self.is_connected = connected;
            self.gsn_advanced_in_connected_state = false;
        }
    }

    /// Characteristic with broadcast support changed.
    pub async fn characteristic_changed(
        &mut self,
        properties: &Characteristic,
        accessory: &mut impl crate::AccessoryInterface,
        pair_support: &mut impl PlatformSupport,
    ) -> Result<(), InterfaceError> {
        info!("things");

        if self.is_connected {
            // While connected, we only ever advance the global state once.
            // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.h#L20-L26
            // Gsn can only advance ONCE per connected session.
            if properties.properties.supports_event_notification()
                || properties.properties.supports_broadcast_notification()
                || properties.properties.supports_disconnect_notification()
            {
                if !self.gsn_advanced_in_connected_state {
                    let _ = pair_support.advance_global_state_number().await?;
                    self.gsn_advanced_in_connected_state = true;
                }
            }
        } else {
            // We are not connected, for each broadcast supported change, we advance the global state
            if properties.properties.supports_broadcast_notification() {
                // We do a broadcast, this always advances the global state.
                let _ = pair_support.advance_global_state_number().await?;
            } else {
                // This only ever advances the state once.
                if !self.gsn_advanced_in_connected_state {
                    let _ = pair_support.advance_global_state_number().await?;
                    self.gsn_advanced_in_connected_state = true;
                }
            }
        }
        Ok(())
    }
}
