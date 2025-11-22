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

use trouble_host::prelude::{AdStructure, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};

use crate::{CharId, Characteristic, DeviceId, InterfaceError, PlatformSupport, SetupId};

#[derive(Debug, Clone)]
pub struct AdvertiseFlow {
    pub advertise_data: heapless::Vec<u8, 31>,
    pub scan_data: heapless::Vec<u8, 31>,
    pub advertise_interval_ms: u64,
    pub until: Option<embassy_time::Instant>,
}

#[derive(Debug, Clone)]
pub struct AdvertiseInfo<'a> {
    pub device_id: &'a DeviceId,
    pub setup_id: &'a SetupId,
    pub name: &'a str,
    pub category: &'a u16,
}

const ADVERTISE_HIGH_RATE: u64 = 20;
const ADVERTISE_REGULAR_RATE: u64 = 500;
/*
 * Mode is used to govern the statemachine, all paths lead to General.
 * After the connection disconnects we go to GeneralHighRate
 *
 *      Startup ->       GeneralHighRate--------\
 *      Disconnected   ->  GeneralHighRate       -> General
 *      GeneralHighRate/Generate -> Broadcast---/
 */
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
enum AdvertisementMode {
    /// We are broadcasting a value using the broadcasting key.
    Broadcast {
        char: CharId,
        value: [u8; 8],
        until: embassy_time::Instant,
    },
    /// Our super boring 'we are here' advertisement.
    General,

    /// High rate we are here advertisement, this is after disconnect and at startup.
    GeneralHighRate { until: embassy_time::Instant },

    /// If the state is disconnected, the next advertise will transition to high rate.
    Disconnected,

    /// If we're at startup we will transition into general high rate.
    #[default]
    Startup,
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
            if !self.is_connected {
                // We are disconnecting, so we cannot be doing a broadcast currently, we can overwrite the state.
                self.mode = AdvertisementMode::Disconnected;
            }
        }
    }

    async fn crate_general_advertisement(
        info: &AdvertiseInfo<'_>,
        support: &mut impl PlatformSupport,
    ) -> Result<AdvertiseFlow, InterfaceError> {
        let is_paired = support.is_paired().await.unwrap();
        let broadcast_params = support.get_ble_broadcast_parameters().await.unwrap();
        let adv_config = if is_paired {
            super::advertisement::AdvertisementConfig {
                device_id: broadcast_params.advertising_id.unwrap_or(*info.device_id),
                setup_id: *info.setup_id,
                accessory_category: *info.category,
                global_state: support.get_global_state_number().await.unwrap(),
                config_number: support.get_config_number().await.unwrap(),
                is_paired,
                ..Default::default()
            }
        } else {
            super::advertisement::AdvertisementConfig {
                device_id: *info.device_id,
                setup_id: *info.setup_id,
                accessory_category: *info.category,
                ..Default::default()
            }
        };
        let hap_adv = adv_config.to_advertisement();

        let mut advertise_data = heapless::Vec::<u8, 31>::new();
        advertise_data.resize(31, 0).unwrap();
        let len = AdStructure::encode_slice(
            &[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                // Lets just always shorten this to a single character, then the scan will just retrieve the full
                // name, and we don't have to do math.
                AdStructure::ShortenedLocalName(&info.name.as_bytes()[0..1]),
                AdStructure::ManufacturerSpecificData {
                    company_identifier: super::advertisement::COMPANY_IDENTIFIER_CODE,
                    payload: &hap_adv.as_array(),
                },
            ],
            &mut advertise_data[..],
        )
        .unwrap();
        advertise_data.truncate(len);

        Ok(AdvertiseFlow {
            advertise_data,
            scan_data: [].into(),
            advertise_interval_ms: ADVERTISE_REGULAR_RATE,
            until: None,
        })
    }

    pub async fn create_advertisement(
        &mut self,
        info: &AdvertiseInfo<'_>,
        accessory: &mut impl crate::AccessoryInterface,
        support: &mut impl PlatformSupport,
    ) -> Result<AdvertiseFlow, InterfaceError> {
        // Execute the state machine.
        let t = support.get_time();
        info!("current t: {:?}", t);

        self.mode = match self.mode {
            AdvertisementMode::Disconnected => {
                info!("Disconnected, entering high rate advertise for 3s");
                AdvertisementMode::GeneralHighRate {
                    // 3 seconds high rate after disconnect.
                    until: t + embassy_time::Duration::from_secs(3),
                }
            }
            AdvertisementMode::Startup => {
                info!("Startup, entering high rate advertise for 30s");
                AdvertisementMode::GeneralHighRate {
                    // 30 seconds high rate after startup.
                    until: t + embassy_time::Duration::from_secs(30),
                }
            }
            AdvertisementMode::GeneralHighRate { until } => {
                if t > until {
                    // High rate interval expired, go to general.
                    info!("High rate advertise expired, going to general.");
                    AdvertisementMode::General
                } else {
                    // Still on high rate interval.
                    AdvertisementMode::GeneralHighRate { until }
                }
            }
            AdvertisementMode::Broadcast { until, char, value } => {
                if t > until {
                    info!("High rate broadcast advertise expired, going to general.");
                    // High rate interval expired, go to general.
                    AdvertisementMode::General
                } else {
                    // Still on broadcast
                    AdvertisementMode::Broadcast { until, char, value }
                }
            }
            AdvertisementMode::General => AdvertisementMode::General,
        };

        // Then create the new advertisement.
        match &self.mode {
            AdvertisementMode::Broadcast { char, value, until } => {
                let mut broadcast_data = heapless::Vec::<u8, 31>::new();
                let _ = broadcast_data.resize(31, 0).unwrap();

                let len = super::broadcast::get_advertising_parameters(
                    *char,
                    &mut broadcast_data,
                    &value,
                    support,
                )
                .await?;
                broadcast_data.truncate(len);

                // And encode it into the actual advertisement.
                let mut advertise_data = heapless::Vec::<u8, 31>::new();
                advertise_data.resize(31, 0).unwrap();
                let len = AdStructure::encode_slice(
                    &[
                        AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                        AdStructure::ManufacturerSpecificData {
                            company_identifier: super::advertisement::COMPANY_IDENTIFIER_CODE,
                            payload: &broadcast_data,
                        },
                    ],
                    &mut advertise_data[..],
                )
                .unwrap();
                advertise_data.truncate(len);

                Ok(AdvertiseFlow {
                    advertise_data,
                    scan_data: Default::default(),
                    advertise_interval_ms: ADVERTISE_HIGH_RATE,
                    until: Some(*until),
                })
            }
            AdvertisementMode::General => Self::crate_general_advertisement(info, support).await,
            AdvertisementMode::GeneralHighRate { until } => {
                let mut f = Self::crate_general_advertisement(info, support).await?;
                f.advertise_interval_ms = ADVERTISE_HIGH_RATE;
                f.until = Some(*until);
                Ok(f)
            }
            // These two are never reachable because we advance the state machine above.
            AdvertisementMode::Disconnected => unreachable!(),
            AdvertisementMode::Startup => unreachable!(),
        }
    }

    /// Characteristic with broadcast support changed.
    pub async fn characteristic_changed(
        &mut self,
        properties: &Characteristic,
        accessory: &mut impl crate::AccessoryInterface,
        support: &mut impl PlatformSupport,
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
                    let _ = support.advance_global_state_number().await?;
                    self.gsn_advanced_in_connected_state = true;
                }
            }
        } else {
            // We are not connected, for each broadcast supported change, we advance the global state
            if properties.properties.supports_broadcast_notification() {
                // We do a broadcast, this always advances the global state.
                let _ = support.advance_global_state_number().await?;

                // Enssure we can actually broadcast, a broadcast may be requested by a characteristic getting changed
                // before the actual broadcast configuration is setup (or the device is paired).
                let parameters = support.get_ble_broadcast_parameters().await?;
                if parameters.advertising_id.is_none() {
                    info!("Skipping broadcast stage, no broadcast configuration yet");
                    return Ok(());
                }
                // Then, collect the information necessary to create the broadcast advertisement.
                let mut value = [0u8; 8];
                let read_value: &[u8] = (accessory)
                    .read_characteristic(properties.iid)
                    .await?
                    .into();
                // Value is always 8 bytes long
                // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L793-L798
                value[0..read_value.len()].copy_from_slice(read_value);
                self.mode = AdvertisementMode::Broadcast {
                    char: properties.iid,
                    value,
                    until: support.get_time() + embassy_time::Duration::from_secs(3),
                };
            } else {
                // This only ever advances the state once.
                if !self.gsn_advanced_in_connected_state {
                    let _ = support.advance_global_state_number().await?;
                    self.gsn_advanced_in_connected_state = true;
                }
            }
        }
        Ok(())
    }
}
