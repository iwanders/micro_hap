use cyw43_pio::{PioSpi, DEFAULT_CLOCK_DIVIDER, RM2_CLOCK_DIVIDER};
use defmt::{error, info, unwrap, warn};
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::DMA_CH0;

use embassy_rp::pio::Pio;
use embassy_sync::watch::DynSender;
use static_cell::StaticCell;
use zerocopy::IntoBytes;

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha8,
};

use embassy_futures::join::join;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use micro_hap::IntoBytesForAccessoryInterface;
use trouble_host::prelude::*;

use micro_hap::{
    ble::broadcast::BleBroadcastParameters, ble::services::LightbulbServiceHandles,
    ble::TimedWrite, AccessoryInterface, CharId, CharacteristicResponse, InterfaceError,
    PlatformSupport,
};
struct LightBulbAccessory<'a, 'b> {
    name: HeaplessString<32>,
    bulb_on_state: bool,
    bulb_control: cyw43::Control<'a>,
    temperature_value: f32,
    low_battery: bool,
    latest_temperature: embassy_sync::watch::DynReceiver<'b, f32>,
    temperature_handles: temperature_sensor::TemperatureServiceHandles,
    bulb_handles: LightbulbServiceHandles,
}
impl<'a, 'b> AccessoryInterface for LightBulbAccessory<'a, 'b> {
    async fn read_characteristic<'z>(
        &mut self,
        char_id: CharId,
        output: &'z mut [u8],
    ) -> Result<&'z [u8], InterfaceError> {
        if char_id == self.bulb_handles.name.hap {
            self.name.read_characteristic_into(char_id, output)
        } else if char_id == self.bulb_handles.on.hap {
            self.bulb_on_state.read_characteristic_into(char_id, output)
        } else if char_id == self.temperature_handles.value.hap {
            let value = if self.latest_temperature.contains_value() {
                self.latest_temperature.get().await
            } else {
                self.temperature_value
            };
            self.temperature_value = value;
            self.temperature_value
                .read_characteristic_into(char_id, output)
        } else if char_id == self.temperature_handles.low_battery.hap {
            self.low_battery.read_characteristic_into(char_id, output)
        } else {
            Err(InterfaceError::CharacteristicUnknown(char_id))
        }
    }
    async fn write_characteristic(
        &mut self,
        char_id: CharId,
        data: &[u8],
    ) -> Result<CharacteristicResponse, InterfaceError> {
        info!(
            "AccessoryInterface to characterstic: 0x{:?} data: {:?}",
            char_id.0, data
        );

        if char_id == self.bulb_handles.on.hap {
            let value = data
                .get(0)
                .ok_or(InterfaceError::CharacteristicWriteInvalid)?;
            let val_as_bool = *value != 0;

            let response = if self.bulb_on_state != val_as_bool {
                CharacteristicResponse::Modified
            } else {
                CharacteristicResponse::Unmodified
            };
            self.bulb_on_state = val_as_bool;
            info!("Set bulb to: {:?}", self.bulb_on_state);
            self.bulb_control.gpio_set(0, self.bulb_on_state).await;
            Ok(response)
        } else {
            Err(InterfaceError::CharacteristicUnknown(char_id))
        }
    }
}
/// Max number of connections
const CONNECTIONS_MAX: usize = 3;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 5; // Signal + att

// This macro approach doesn't work to easily managed the CharIds after you have more than one service, since they
// all need unique CharIds, but they're also values in ble descriptors.
// #[gatt_server]
// struct Server {
//     accessory_information: micro_hap::ble::AccessoryInformationService, // 0x003e
//     protocol: micro_hap::ble::ProtocolInformationService,               // 0x00a2
//     pairing: micro_hap::ble::PairingService,                            // 0x0055
//     lightbulb: micro_hap::ble::LightbulbService,                        // 0x0043
//     temp_sensor: temperature_sensor::TemperatureSensorService,
// }
use crate::temperature_sensor;
use micro_hap::pairing::{Pairing, PairingId, ED25519_LTSK};
use micro_hap::BleBroadcastInterval;

pub struct ActualPairSupport {
    pub ed_ltsk: [u8; micro_hap::pairing::ED25519_LTSK],
    pub pairings: heapless::index_map::FnvIndexMap<
        micro_hap::pairing::PairingId,
        micro_hap::pairing::Pairing,
        2,
    >,
    pub global_state_number: u16,
    pub config_number: u8,
    pub broadcast_parameters: BleBroadcastParameters,
    pub ble_broadcast_config: heapless::index_map::FnvIndexMap<CharId, BleBroadcastInterval, 16>,
    pub prng: ChaCha8,
}

impl ActualPairSupport {
    fn new(rng_init: u128) -> Self {
        let mut key = [0u8; 32];
        key[0..16].copy_from_slice(rng_init.as_bytes());
        let nonce = [0u8; 12];

        Self {
            ed_ltsk: [
                182, 215, 245, 151, 120, 82, 56, 100, 73, 148, 49, 127, 131, 22, 235, 192, 207, 15,
                80, 115, 241, 91, 203, 234, 46, 135, 77, 137, 203, 204, 159, 230,
            ],
            pairings: Default::default(),
            global_state_number: 1,
            config_number: 1,
            broadcast_parameters: Default::default(),
            ble_broadcast_config: Default::default(),
            prng: ChaCha8::new_from_slices(&key, &nonce).unwrap(),
        }
    }
}
impl PlatformSupport for ActualPairSupport {
    fn get_time(&self) -> embassy_time::Instant {
        embassy_time::Instant::now()
    }

    async fn get_ltsk(&self) -> [u8; ED25519_LTSK] {
        self.ed_ltsk
    }

    async fn fill_random(&mut self, buffer: &mut [u8]) -> () {
        self.prng.apply_keystream(buffer);
    }

    async fn store_pairing(&mut self, pairing: &Pairing) -> Result<(), InterfaceError> {
        error!("Storing pairing");
        self.pairings
            .insert(pairing.id, *pairing)
            .expect("assuming we have anough space for now");
        Ok(())
    }

    async fn get_pairing(&mut self, id: &PairingId) -> Result<Option<Pairing>, InterfaceError> {
        error!("retrieving id pairing id");
        Ok(self.pairings.get(id).copied())
    }
    async fn remove_pairing(&mut self, id: &PairingId) -> Result<(), InterfaceError> {
        let _ = self.pairings.remove(id);
        Ok(())
    }
    async fn is_paired(&mut self) -> Result<bool, micro_hap::InterfaceError> {
        Ok(!self.pairings.is_empty())
    }

    async fn get_global_state_number(&self) -> Result<u16, InterfaceError> {
        Ok(self.global_state_number)
    }
    /// Set the global state number, this is used by the BLE transport.
    async fn set_global_state_number(&mut self, value: u16) -> Result<(), InterfaceError> {
        self.global_state_number = value;
        Ok(())
    }
    async fn get_config_number(&self) -> Result<u8, InterfaceError> {
        Ok(self.config_number)
    }
    async fn set_config_number(&mut self, value: u8) -> Result<(), InterfaceError> {
        self.config_number = value;
        Ok(())
    }
    async fn get_ble_broadcast_parameters(
        &self,
    ) -> Result<micro_hap::ble::broadcast::BleBroadcastParameters, InterfaceError> {
        Ok(self.broadcast_parameters)
    }
    async fn set_ble_broadcast_parameters(
        &mut self,
        params: &micro_hap::ble::broadcast::BleBroadcastParameters,
    ) -> Result<(), InterfaceError> {
        self.broadcast_parameters = *params;
        Ok(())
    }
    async fn set_ble_broadcast_configuration(
        &mut self,
        char_id: CharId,
        configuration: BleBroadcastInterval,
    ) -> Result<(), InterfaceError> {
        if configuration == BleBroadcastInterval::Disabled {
            self.ble_broadcast_config.remove(&char_id);
        } else {
            let _ = self.ble_broadcast_config.insert(char_id, configuration);
        }
        Ok(())
    }
    /// Get the broadcast configuration for a characteristic.
    async fn get_ble_broadcast_configuration(
        &mut self,
        char_id: CharId,
    ) -> Result<Option<BleBroadcastInterval>, InterfaceError> {
        Ok(self.ble_broadcast_config.get(&char_id).copied())
    }
}

async fn temperature_task(
    mut adc: embassy_rp::adc::Adc<'_, embassy_rp::adc::Async>,
    mut temp_adc: embassy_rp::adc::Channel<'_>,
    sender: DynSender<'_, f32>,
    char_id: CharId,
    control_sender: micro_hap::HapInterfaceSender<'_>,
) {
    let mut i: usize = 0;
    loop {
        embassy_time::Timer::after_secs(1).await;
        i += 1;
        if i > 1000 {
            i = 0;
        }

        let read = adc.read(&mut temp_adc).await;
        match read {
            Ok(value) => {
                info!("Sampled temperature adc with: {}", value);
                // conversion; https://github.com/raspberrypi/pico-micropython-examples/blob/1dc8d73a08f0e791c7694855cb61a5bfe8537756/adc/temperature.py#L5-L14

                let conversion_factor = 3.3f32 / 65535f32;
                let reading = value as f32 * conversion_factor;
                let mut temperature = 27.0 - (reading - 0.706) / 0.001721;
                // This looks so wrong, or my adc reference voltage is way way off.

                // Since this is so wrong, we just fake a value every other value.
                if i.rem_euclid(2) == 0 {
                    temperature = i as f32 * 0.1;
                }

                info!("Sending temperature: {}", temperature);
                sender.send(temperature);
                info!("Notifying characteristic change");
                control_sender.characteristic_changed(char_id).await; // send the notification.
                info!("  notify done.");
            }
            Err(e) => {
                warn!("adc sample failed: {:?}", e);
            }
        }
    }
}

// use bt_hci::cmd::le::LeReadLocalSupportedFeatures;
// use bt_hci::cmd::le::LeSetDataLength;
// use bt_hci::controller::ControllerCmdSync;
const DEVICE_ADDRESS: [u8; 6] = [0xff, 0x8f, 0x1b, 0x33, 0xe4, 0xff];
/// Run the BLE stack.
pub async fn run<'p, 'cyw, C>(
    controller: C,
    bulb_control: cyw43::Control<'_>,
    temp_adc: embassy_rp::adc::Channel<'_>,
    adc: embassy_rp::adc::Adc<'_, embassy_rp::adc::Async>,
) where
    C: Controller, // + ControllerCmdSync<LeReadLocalSupportedFeatures>
                   // + ControllerCmdSync<LeSetDataLength>,
{
    // Using a fixed "random" address can be useful for testing. In real scenarios, one would
    // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
    let address: Address = Address::random(DEVICE_ADDRESS);

    // This is a bit over the top in size... but we have sufficient ram.
    let mut attribute_buffer: &mut [u8] = {
        const ATTRIBUTE_BUFFER_SIZE: usize = 1024;
        static STATE: StaticCell<[u8; ATTRIBUTE_BUFFER_SIZE]> = StaticCell::new();
        STATE.init([0u8; ATTRIBUTE_BUFFER_SIZE])
    };

    const ATTRIBUTE_TABLE_SIZE: usize = 1024;
    let mut attribute_table = trouble_host::attribute::AttributeTable::<
        CriticalSectionRawMutex,
        ATTRIBUTE_TABLE_SIZE,
    >::new();

    // Create the gatt server.
    let name = "Z"; // There's _very_ few bytes left in the advertisement
    info!("Starting advertising and GATT service");
    let gap_config = GapConfig::Peripheral(PeripheralConfig {
        name,
        appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
    });
    //let server = Server::new_with_config().unwrap();
    gap_config.build(&mut attribute_table).unwrap();
    // This is the body of new_with_config

    let (remaining_buffer, information_handles) =
        micro_hap::ble::services::AccessoryInformationService::add_to_attribute_table(
            &mut attribute_table,
            &mut attribute_buffer,
        )
        .unwrap();
    let (remaining_buffer, protocol_handles) =
        micro_hap::ble::services::ProtocolInformationService::add_to_attribute_table(
            &mut attribute_table,
            remaining_buffer,
        )
        .unwrap();
    let (remaining_buffer, pairing_handles) =
        micro_hap::ble::services::PairingService::add_to_attribute_table(
            &mut attribute_table,
            remaining_buffer,
        )
        .unwrap();
    let (remaining_buffer, bulb_handles) =
        micro_hap::ble::services::LightbulbService::add_to_attribute_table(
            &mut attribute_table,
            remaining_buffer,
            0x30,
        )
        .unwrap();
    let (remaining_buffer, temperature_handles) =
        temperature_sensor::TemperatureSensorService::add_to_attribute_table(
            &mut attribute_table,
            remaining_buffer,
            0x40,
        )
        .unwrap();
    // These handles and CharIds exactly match the ones from the derive macro.
    info!("information_handles: {:?}", information_handles);
    info!("protocol_handles: {:?}", protocol_handles);
    info!("pairing_handles: {:?}", pairing_handles);
    // info!("temperature_handles: {:?}", temperature_handles);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();

    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        runner,
        ..
    } = stack.build();

    const CCCD_MAX: usize = 32;
    const CONNECTIONS_MAX: usize = 3;
    let server = trouble_host::prelude::AttributeServer::<_, _, _, CCCD_MAX, CONNECTIONS_MAX>::new(
        attribute_table,
    );

    // Setup the accessory information.
    let static_information = micro_hap::AccessoryInformationStatic {
        name: "micro_hap",
        device_id: micro_hap::DeviceId([
            DEVICE_ADDRESS[0],
            DEVICE_ADDRESS[1],
            DEVICE_ADDRESS[2],
            DEVICE_ADDRESS[3],
            DEVICE_ADDRESS[4],
            DEVICE_ADDRESS[5],
        ]),
        ..Default::default()
    };

    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L472
    // let mut accessory = micro_hap::NopAccessory;
    let pair_ctx = {
        static STATE: StaticCell<micro_hap::AccessoryContext> = StaticCell::new();
        STATE.init_with(micro_hap::AccessoryContext::default)
    };
    pair_ctx.accessory = static_information;
    // srp salt and verifier for [1, 1, 1, 2, 2, 3, 3, 3]
    const SRP_SALT: [u8; 16] = [
        0xbc, 0xd1, 0xf5, 0x2a, 0xd6, 0x68, 0x02, 0x2d, 0x57, 0x01, 0xcb, 0xaa, 0xfa, 0x5f, 0x35,
        0x48,
    ];
    const SRP_VERIFIER: [u8; 384] = [
        0x03, 0x8c, 0x46, 0xe4, 0xa7, 0x69, 0xf8, 0x57, 0xa4, 0xef, 0x7f, 0x3e, 0x6d, 0xcd, 0xce,
        0x8f, 0x1e, 0x06, 0xd9, 0x52, 0xc9, 0x3b, 0x96, 0xde, 0x7e, 0x19, 0x30, 0x9a, 0xd6, 0xb4,
        0x37, 0x9c, 0x31, 0x7a, 0xe1, 0x28, 0x92, 0x7b, 0x31, 0xc4, 0xd3, 0xf4, 0x8d, 0xa2, 0x80,
        0x51, 0xfa, 0x65, 0x35, 0xc2, 0x72, 0xc1, 0x3e, 0x05, 0x99, 0xbc, 0x93, 0x47, 0xaf, 0x0f,
        0xdf, 0x8e, 0xc3, 0x65, 0xdb, 0x19, 0x94, 0x52, 0x69, 0x76, 0x9f, 0x0d, 0x1d, 0x84, 0x37,
        0xb4, 0xc0, 0x9b, 0x2d, 0xd5, 0xed, 0xee, 0xcb, 0x3a, 0xe7, 0x66, 0x3a, 0x7f, 0x7a, 0x8a,
        0xaf, 0xbd, 0x2c, 0x3b, 0xc8, 0x56, 0xf6, 0xe3, 0x1c, 0x0f, 0x7b, 0xde, 0x99, 0x75, 0xde,
        0xdd, 0xe9, 0xd8, 0x58, 0xe5, 0x26, 0xae, 0xc6, 0x64, 0x2c, 0xa6, 0xd3, 0xa4, 0x32, 0x4c,
        0x13, 0x5e, 0x38, 0x0c, 0x84, 0x4a, 0xa4, 0xa5, 0xff, 0x2e, 0x91, 0x61, 0xa2, 0x5f, 0xea,
        0x56, 0xd5, 0x8a, 0x12, 0x55, 0x42, 0x3c, 0x88, 0xc1, 0x2d, 0xfc, 0x97, 0x40, 0x85, 0x83,
        0x20, 0x33, 0xa6, 0xfd, 0x92, 0x57, 0x8b, 0x2c, 0x3d, 0x20, 0x5a, 0x45, 0x64, 0xa4, 0x88,
        0x6b, 0xaa, 0x20, 0xae, 0x6e, 0x20, 0xc5, 0x49, 0x5f, 0xfe, 0x6c, 0x3f, 0x5b, 0xd0, 0xfe,
        0x03, 0x3b, 0x3e, 0x9c, 0xb2, 0x50, 0xa2, 0x22, 0xb2, 0xba, 0x7d, 0x29, 0x1e, 0x2b, 0xa7,
        0xb8, 0x35, 0x18, 0xac, 0xe6, 0x3e, 0xe8, 0x25, 0xef, 0x8b, 0xd7, 0x4f, 0xe9, 0xa0, 0x8b,
        0xec, 0x3f, 0x5d, 0x33, 0x9d, 0x6f, 0xd5, 0xd6, 0x1a, 0xb9, 0x4d, 0xa8, 0x87, 0x32, 0x24,
        0x0e, 0x54, 0x88, 0xb3, 0xce, 0xfc, 0xca, 0x1a, 0xea, 0x8d, 0x9b, 0xac, 0xd7, 0x59, 0x77,
        0x1c, 0xfe, 0x27, 0xaa, 0x92, 0x6a, 0x2e, 0xcd, 0x2b, 0x49, 0x49, 0x29, 0xe4, 0x5c, 0x83,
        0x4b, 0x26, 0x16, 0x88, 0xdd, 0x9d, 0x46, 0xb2, 0x23, 0x27, 0xb0, 0x57, 0x74, 0x61, 0xdf,
        0xdc, 0x1d, 0x79, 0xff, 0x08, 0xb5, 0x5c, 0x96, 0x03, 0xbb, 0x74, 0xcd, 0x68, 0x17, 0x97,
        0x25, 0xc1, 0xc0, 0x61, 0xf3, 0xcb, 0xce, 0x9a, 0x46, 0xc9, 0x47, 0xbb, 0x2c, 0x52, 0x60,
        0x44, 0x97, 0xc0, 0x65, 0xd0, 0xe1, 0xb1, 0x4a, 0x4d, 0x74, 0x95, 0x1f, 0xb8, 0x9e, 0x12,
        0x68, 0x30, 0xa2, 0x26, 0xd1, 0x50, 0x37, 0x16, 0xb1, 0x61, 0x82, 0xda, 0x0f, 0xed, 0xd7,
        0xc4, 0x9a, 0x0b, 0x9a, 0xad, 0x8c, 0x6e, 0xcc, 0x96, 0x6d, 0xd8, 0x60, 0xe0, 0x86, 0xde,
        0xdd, 0xc2, 0xad, 0x7c, 0x64, 0x78, 0x4f, 0x4e, 0xe6, 0x2b, 0x62, 0xb2, 0xee, 0xff, 0x4f,
        0xbc, 0x2c, 0xf6, 0xc2, 0x69, 0xfa, 0xdf, 0xf2, 0x72, 0x21, 0x41, 0xfb, 0x14, 0x9c, 0xfe,
        0x20, 0xaa, 0x58, 0xc7, 0xd1, 0xa2, 0x0d, 0xf3, 0x9a,
    ];

    pair_ctx.info.salt = SRP_SALT;
    pair_ctx.info.verifier = SRP_VERIFIER;

    let out_buffer: &mut [u8] = {
        static STATE: StaticCell<[u8; 2048]> = StaticCell::new();
        STATE.init([0u8; 2048])
    };
    let in_buffer: &mut [u8] = {
        static STATE: StaticCell<[u8; 1024]> = StaticCell::new();
        STATE.init([0u8; 1024])
    };

    const TIMED_WRITE_SLOTS: usize = 8;
    const TIMED_WRITE_SLOTS_DATA: usize = 128;

    let timed_write_data = {
        static DATA_STATE: StaticCell<[u8; TIMED_WRITE_SLOTS * TIMED_WRITE_SLOTS_DATA]> =
            StaticCell::new();
        DATA_STATE.init([0u8; TIMED_WRITE_SLOTS * TIMED_WRITE_SLOTS_DATA])
    };

    let timed_write = {
        static SLOT_STATE: StaticCell<[Option<TimedWrite>; TIMED_WRITE_SLOTS]> = StaticCell::new();
        SLOT_STATE.init([None; TIMED_WRITE_SLOTS])
    };

    let control_channel = {
        type Mutex = embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
        const CONTROL_CHANNEL_N: usize = 16;

        static CONTROL_CHANNEL: StaticCell<micro_hap::HapControlChannel<Mutex, CONTROL_CHANNEL_N>> =
            StaticCell::new();
        CONTROL_CHANNEL.init(micro_hap::HapControlChannel::<Mutex, CONTROL_CHANNEL_N>::new())
    };
    let control_receiver = control_channel.get_receiver();
    let control_sender: micro_hap::HapInterfaceSender<'_> = control_channel.get_sender();
    let _ = &control_sender;

    // This is also pretty big on the stack :/
    let mut hap_context = micro_hap::ble::HapPeripheralContext::new(
        out_buffer,
        in_buffer,
        pair_ctx,
        timed_write_data,
        timed_write,
        control_receiver,
    )
    .unwrap();

    hap_context
        .add_service(information_handles.to_service().unwrap())
        .unwrap();
    hap_context
        .add_service(protocol_handles.to_service().unwrap())
        .unwrap();
    hap_context
        .add_service(pairing_handles.to_service().unwrap())
        .unwrap();
    hap_context
        .add_service(bulb_handles.to_service().unwrap())
        .unwrap();
    hap_context
        .add_service(temperature_handles.to_service().unwrap())
        .unwrap();
    hap_context.assign_static_data(&static_information);

    //info!("hap_context: {:0>#2x?}", hap_context);

    // The handle exists... where does it go wrong??

    hap_context.print_handles();

    static WATCH: embassy_sync::watch::Watch<CriticalSectionRawMutex, f32, 2> =
        embassy_sync::watch::Watch::new_with(3.3);
    let mut rcv0 = WATCH.receiver().unwrap();
    let mut latest_temperature = WATCH.dyn_receiver().unwrap();
    let mut temperature_sender = WATCH.dyn_sender();

    let mut accessory = LightBulbAccessory {
        name: "Light Bulb".try_into().unwrap(),
        bulb_on_state: false,
        bulb_control,
        low_battery: false,
        temperature_value: 13.37,
        latest_temperature,
        temperature_handles,
        bulb_handles,
    };

    // This isn't great, because we always initialise the same way at boot, but the trng spammed the autocorrect error.
    let init_u128 =
        embassy_rp::otp::get_private_random_number().expect("failed to retrieve random bytes");
    let mut support = ActualPairSupport::new(init_u128);
    let support = &mut support;

    let temperature_char_id = temperature_handles.value.hap;

    let _ = join(
        join(
            ble_task(runner),
            temperature_task(
                adc,
                temp_adc,
                temperature_sender,
                temperature_char_id,
                control_sender,
            ),
        ),
        async {
            loop {
                match hap_context
                    .advertise(&mut accessory, support, &mut peripheral)
                    .await
                {
                    Ok(conn) => {
                        // Increase the data length to 251 bytes per package, default is like 27.
                        // conn.update_data_length(&stack, 251, 2120)
                        //     .await
                        //     .expect("Failed to set data length");
                        let conn = conn
                            .with_attribute_server(&server)
                            .expect("Failed to create attribute server");
                        // set up tasks when the connection is established to a central, so they don't run when no one is connected.
                        let a = hap_context.gatt_events_task(&mut accessory, support, &conn);

                        // run until any task ends (usually because the connection has been closed),
                        // then return to advertising state.
                        if let Err(e) = a.await {
                            error!("Error occured in processing: {:?}", e);
                        }
                    }
                    Err(e) => {
                        panic!("[adv] error: {:?}", e);
                    }
                }
            }
        },
    )
    .await;
}

/// This is a background task that is required to run forever alongside any other BLE tasks.
///
/// ## Alternative
///
/// If you didn't require this to be generic for your application, you could statically spawn this with i.e.
///
/// ```rust,ignore
///
/// #[embassy_executor::task]
/// async fn ble_task(mut runner: Runner<'static, SoftdeviceController<'static>>) {
///     runner.run().await;
/// }
///
/// spawner.must_spawn(ble_task(runner));
/// ```
async fn ble_task<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) {
    loop {
        if let Err(e) = runner.run().await {
            let e = defmt::Debug2Format(&e);
            panic!("[ble_task] error: {:?}", e);
        }
    }
}

use trouble_host::prelude::ExternalController;

use embassy_rp::peripherals::PIO2;
use embassy_rp::peripherals::TRNG;
use embassy_rp::pio::InterruptHandler as PioInterruptHandler;
bind_interrupts!(struct Irqs {
    PIO2_IRQ_0 => PioInterruptHandler<PIO2>;
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<TRNG>;
    ADC_IRQ_FIFO => embassy_rp::adc::InterruptHandler;
});

#[embassy_executor::task]
async fn cyw43_task(
    runner: cyw43::Runner<'static, Output<'static>, PioSpi<'static, PIO2, 0, DMA_CH0>>,
) -> ! {
    runner.run().await
}

//#[embassy_executor::main]
use embassy_rp::Peripherals;
pub async fn main(spawner: Spawner, p: Peripherals) {
    //let p = embassy_rp::init(Default::default());

    let (fw, clm, btfw) = {
        let fw = include_bytes!("../../../cyw43-firmware/43439A0.bin");
        let clm = include_bytes!("../../../cyw43-firmware/43439A0_clm.bin");
        let btfw = include_bytes!("../../../cyw43-firmware/43439A0_btfw.bin");
        // let btfw = include_bytes!("../../../cyw43-firmware/43439A0_btfw_old.bin");
        (fw, clm, btfw)
    };

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO2, Irqs);

    // let clock_divider = RM2_CLOCK_DIVIDER;
    let clock_divider = RM2_CLOCK_DIVIDER;
    let spi = PioSpi::new(
        &mut pio.common,
        pio.sm0,
        clock_divider,
        pio.irq0,
        cs,
        p.PIN_24,
        p.PIN_29,
        p.DMA_CH0,
    );
    // let ledpin = Output::new(, Level::Low);
    //
    // /*
    // Check the warnings from here: https://github.com/embassy-rs/embassy/blob/fcd5383f475f7bd413541123d941d3d7e1cd326b/cyw43-pio/src/lib.rs#L63
    use embassy_rp::clocks::clk_sys_freq;
    use fixed::FixedU32;
    let effective_pio_frequency = (clk_sys_freq() as f32 / clock_divider.to_num::<f32>()) as u32;

    defmt::trace!("Effective pio frequency: {}Hz", effective_pio_frequency);
    if clock_divider.frac() != FixedU32::<fixed::types::extra::U8>::ZERO {
        defmt::error!(
             "Configured clock divider is not a whole number. Some clock cycles may violate the maximum recommended GSPI speed. Use at your own risk."
         );
    }
    if effective_pio_frequency > 100_000_000 {
        defmt::error!(
            "Configured clock divider results in a GSPI frequency greater than the manufacturer recommendation (50Mhz). Use at your own risk."
        );
    }
    // */
    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (_net_device, bt_device, mut control, runner) =
        cyw43::new_with_bluetooth(state, pwr, spi, fw, btfw).await;
    unwrap!(spawner.spawn(cyw43_task(runner)));
    control.init(clm).await;
    let controller: ExternalController<_, 10> = ExternalController::new(bt_device);

    // let mut trng = embassy_rp::trng::Trng::new(p.TRNG, Irqs, embassy_rp::trng::Config::default());
    // 13.459326 WARN  TRNG Autocorrect error! Resetting TRNG. Increase sample count to reduce likelihood
    // 13.459846 WARN  TRNG CRNGT error! Increase sample count to reduce likelihood
    // Much much spam of that last command, lets just switch to a cryptographically secure RNG.

    // DO NOT CHANGE ORDER: https://github.com/embassy-rs/embassy/issues/4558
    let adcthing = p.ADC_TEMP_SENSOR;
    let adc = embassy_rp::adc::Adc::new(p.ADC, Irqs, embassy_rp::adc::Config::default());
    let temp_channel = embassy_rp::adc::Channel::new_temp_sensor(adcthing);

    // let mut bulb_pin = Output::new(p.PIN_26, Level::Low);
    // let mut bulb = move |state: bool| {
    //     //embassy_futures::block_on(control.gpio_set(0, true));
    //     info!("setting pin to: {}", state);
    //     bulb_pin.set_level(if state { Level::High } else { Level::Low });
    // };

    run(controller, control, temp_channel, adc).await;
}
