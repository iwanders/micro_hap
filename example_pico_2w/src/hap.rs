use cyw43_pio::{PioSpi, RM2_CLOCK_DIVIDER};
use defmt::{error, info, unwrap};
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::DMA_CH0;

use embassy_rp::pio::Pio;
use embassy_sync::watch::DynSender;
use static_cell::StaticCell;
use zerocopy::IntoBytes;

use super::hap_temp_sensor;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha8,
};

use embassy_futures::{join::join, select::select};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::Timer;
use micro_hap::IntoBytesForAccessoryInterface;
use trouble_host::prelude::*;

use micro_hap::{
    ble::broadcast::BleBroadcastParameters, ble::HapBleService, ble::TimedWrite,
    AccessoryInterface, CharId, CharacteristicResponse, InterfaceError, PlatformSupport,
};
struct LightBulbAccessory<'a, 'b> {
    name: HeaplessString<32>,
    bulb_on_state: bool,
    bulb_control: cyw43::Control<'a>,
    temperature_value: f32,
    low_battery: bool,
    latest_temperature: embassy_sync::watch::DynReceiver<'b, f32>,
}
impl<'a, 'b> AccessoryInterface for LightBulbAccessory<'a, 'b> {
    async fn read_characteristic<'z>(
        &self,
        char_id: CharId,
        output: &'z mut [u8],
    ) -> Result<&'z [u8], InterfaceError> {
        if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_NAME {
            self.name.read_characteristic_into(char_id, output)
        } else if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_ON {
            self.bulb_on_state.read_characteristic_into(char_id, output)
        } else if char_id == hap_temp_sensor::CHAR_ID_TEMP_SENSOR_VALUE {
            self.temperature_value
                .read_characteristic_into(char_id, output)
        } else if char_id == hap_temp_sensor::CHAR_ID_TEMP_LOW_BATTERY {
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

        if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_ON {
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

// Putting the bulb at the end means ios will jump over the service request.
// Is this because of the +1 here?
// https://github.com/embassy-rs/trouble/blob/366ee88a2aa19db11eb0707c71d797156abe23f5/host/src/attribute.rs#L616
// GATT Server definition
#[gatt_server]
struct Server {
    accessory_information: micro_hap::ble::AccessoryInformationService, // 0x003e
    protocol: micro_hap::ble::ProtocolInformationService,               // 0x00a2
    pairing: micro_hap::ble::PairingService,                            // 0x0055
    lightbulb: micro_hap::ble::LightbulbService,                        // 0x0043
    temp_sensor: hap_temp_sensor::TemperatureSensorService,
}
impl Server<'_> {
    pub fn as_hap(&self) -> micro_hap::ble::HapServices<'_> {
        micro_hap::ble::HapServices {
            information: &self.accessory_information,
            protocol: &self.protocol,
            pairing: &self.pairing,
        }
    }
}
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
    control_sender: micro_hap::HapInterfaceSender<'_>,
) {
    loop {
        embassy_time::Timer::after_secs(1).await;
        continue;
        let value = adc.read(&mut temp_adc).await.unwrap();
        info!("Sampled temperature adc with: {}", value);
        // conversion; https://github.com/raspberrypi/pico-micropython-examples/blob/1dc8d73a08f0e791c7694855cb61a5bfe8537756/adc/temperature.py#L5-L14
        let conversion_factor = 3.3f32 / 65535f32;
        let reading = value as f32 * conversion_factor;
        let temperature = 27.0 - (reading - 0.706) / 0.001721;
        info!("temperature : {}", temperature);
        // Send the value.
        sender.send(temperature);
        control_sender
            .characteristic_changed(hap_temp_sensor::CHAR_ID_TEMP_SENSOR_VALUE)
            .await; // send the notification.
    }
}

// use bt_hci::cmd::le::LeReadLocalSupportedFeatures;
// use bt_hci::cmd::le::LeSetDataLength;
// use bt_hci::controller::ControllerCmdSync;
const DEVICE_ADDRESS: [u8; 6] = [0xff, 0x8f, 0x1b, 0x10, 0xe4, 0xff];
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

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();

    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        runner,
        ..
    } = stack.build();

    let name = "W"; // There's _very_ few bytes left in the advertisement
    info!("Starting advertising and GATT service");
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name,
        appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
    }))
    .unwrap();

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
    // let _ = server.accessory_information.unwrap();
    //

    // let mut pin = pin;
    // let mut bulb = move |value: bool| pin.set_level(if value { Level::High } else { Level::Low });
    // let mut bulb = bulb;

    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L472
    // let mut accessory = micro_hap::NopAccessory;
    let pair_ctx = {
        static STATE: StaticCell<micro_hap::AccessoryContext> = StaticCell::new();
        STATE.init_with(micro_hap::AccessoryContext::default)
    };
    pair_ctx.accessory = static_information;
    // We need real commissioning for this, such that the verifier matches the setup code.
    pair_ctx.info.salt = [
        0xb3, 0x5b, 0x84, 0xc4, 0x04, 0x8b, 0x2d, 0x91, 0x35, 0xc4, 0xaf, 0xa3, 0x6d, 0xf6, 0x2b,
        0x29,
    ];
    pair_ctx.info.verifier = [
        0x84, 0x3e, 0x54, 0xd4, 0x61, 0xd8, 0xbd, 0xee, 0x78, 0xcf, 0x96, 0xb3, 0x30, 0x85, 0x4c,
        0xba, 0x90, 0x89, 0xb6, 0x8a, 0x10, 0x7c, 0x51, 0xd6, 0xde, 0x2f, 0xc3, 0xe2, 0x9e, 0xdb,
        0x55, 0xd0, 0xe1, 0xa3, 0xc3, 0x80, 0x6a, 0x1c, 0xae, 0xa3, 0x4d, 0x8b, 0xbe, 0xae, 0x91,
        0x51, 0xe1, 0x78, 0xf6, 0x48, 0x9e, 0xa5, 0x09, 0x73, 0x91, 0xcd, 0xc4, 0xae, 0x12, 0xad,
        0x09, 0x04, 0xdf, 0x44, 0x6d, 0xbe, 0x10, 0x15, 0x58, 0x02, 0xb2, 0x1e, 0x9e, 0xff, 0xfe,
        0xa4, 0x91, 0xf4, 0xb7, 0xa6, 0xb5, 0x12, 0xaa, 0x04, 0xbc, 0xff, 0xe1, 0x86, 0xeb, 0x27,
        0x6a, 0xef, 0xe5, 0xc3, 0x9f, 0x18, 0x6f, 0xe3, 0x53, 0xc7, 0x56, 0x2b, 0x58, 0x4a, 0xa9,
        0x16, 0x12, 0x79, 0x04, 0x81, 0x22, 0x2f, 0xb8, 0xf1, 0xce, 0xb0, 0xb9, 0xda, 0x6b, 0x0e,
        0x39, 0x24, 0xcc, 0xf2, 0x1d, 0xf3, 0xfc, 0x47, 0x58, 0xce, 0x16, 0xd4, 0x08, 0xfe, 0x9d,
        0x77, 0x20, 0xa3, 0x43, 0x3a, 0x45, 0xb0, 0xd4, 0xfb, 0xab, 0x3b, 0xad, 0x36, 0x13, 0xe0,
        0xb3, 0xc2, 0x2a, 0x6a, 0x22, 0x5a, 0xc3, 0xd6, 0xdc, 0x49, 0x41, 0x0c, 0xd6, 0x48, 0x26,
        0x8d, 0x07, 0xe8, 0x57, 0x84, 0xa9, 0xda, 0xb0, 0xe0, 0x54, 0xed, 0x59, 0xe9, 0xcf, 0x03,
        0x26, 0x1f, 0x46, 0x3a, 0x41, 0x01, 0xa9, 0xf8, 0x44, 0x60, 0xc3, 0x5d, 0x9c, 0xb4, 0x66,
        0x42, 0xe7, 0x9f, 0x98, 0x7c, 0xbb, 0x0f, 0x08, 0x7e, 0x36, 0x04, 0x12, 0xcc, 0x7b, 0x4f,
        0x05, 0x44, 0x3b, 0xdd, 0x35, 0x3d, 0x44, 0x2a, 0x47, 0x1d, 0xe0, 0x3e, 0x03, 0xe2, 0x51,
        0xeb, 0x12, 0x96, 0xad, 0x08, 0x46, 0x07, 0xfd, 0xc4, 0x94, 0x9f, 0xc2, 0x59, 0x9d, 0x0f,
        0x79, 0x93, 0x51, 0x0b, 0xb5, 0xe8, 0xfd, 0xbc, 0xd4, 0x5a, 0xcf, 0xf0, 0x08, 0xf7, 0xd6,
        0x44, 0x6a, 0x63, 0x86, 0x88, 0x56, 0x13, 0xcf, 0x5c, 0x51, 0x68, 0xfb, 0xa9, 0xb7, 0x63,
        0x6a, 0xce, 0x64, 0xe1, 0xe1, 0x5a, 0x55, 0xea, 0xb1, 0x0c, 0x0a, 0x82, 0xe9, 0x23, 0x61,
        0x2f, 0x0d, 0xa9, 0x09, 0xb3, 0x48, 0xd4, 0xcf, 0x19, 0x53, 0x81, 0x38, 0x5d, 0x74, 0x4d,
        0xf8, 0x9d, 0x66, 0xaf, 0x52, 0xaf, 0xab, 0xef, 0x22, 0xce, 0x6f, 0xbe, 0xbe, 0xa1, 0x40,
        0x44, 0xd0, 0x01, 0xef, 0x9e, 0x8e, 0xed, 0xd7, 0x99, 0xa0, 0x1f, 0x6f, 0x89, 0x48, 0x98,
        0xa7, 0x61, 0x01, 0x18, 0x77, 0x58, 0x82, 0xfe, 0x5f, 0x8f, 0x5e, 0xf6, 0xf3, 0x25, 0xb0,
        0xda, 0xd2, 0xbf, 0xb0, 0x9e, 0x08, 0x3b, 0x6b, 0x07, 0xff, 0x54, 0x0d, 0xc7, 0x45, 0xcf,
        0x75, 0x51, 0x16, 0x5d, 0x08, 0xe0, 0xea, 0x98, 0xc8, 0xd7, 0xab, 0x21, 0x4a, 0x08, 0x17,
        0xd0, 0x97, 0x13, 0x49, 0xd7, 0xe7, 0xbe, 0xf1, 0x8f,
    ];

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
        &server.accessory_information,
        &server.protocol,
        &server.pairing,
        control_receiver,
    )
    .unwrap();
    hap_context
        .add_service(server.lightbulb.populate_support().unwrap())
        .unwrap();
    hap_context
        .add_service(
            server
                .temp_sensor
                .create_hap_service(&server.server)
                .unwrap(),
        )
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
    };
    //let mut support = ActualPairSupport::default();
    // Put this in static memory instead of the stack, we got some very short messages without this, did we corrupt the
    // stack? How can we detect that?
    // Still getting connection termination.
    // let support = {
    //     static STATE: StaticCell<
    //         ActualPairSupport<embassy_rp::trng::Trng<'_, embassy_rp::trng::Instance>>,
    //     > = StaticCell::new();
    //     STATE.init)
    // };
    // Not sure how to allocate this statically now that it borrows.
    //

    // This isn't great, because we always initialise the same way at boot, but the trng spammed the autocorrect error.
    let init_u128 =
        embassy_rp::otp::get_private_random_number().expect("failed to retrieve random bytes");
    let mut support = ActualPairSupport::new(init_u128);
    let support = &mut support;

    let _ = join(
        join(
            ble_task(runner),
            temperature_task(adc, temp_adc, temperature_sender, control_sender),
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
                        let hap_services = server.as_hap();
                        let a = hap_context.gatt_events_task(
                            &mut accessory,
                            support,
                            &hap_services,
                            &conn,
                        );

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
//use {defmt_rtt as _, panic_probe as _};

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
        (fw, clm, btfw)
    };

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO2, Irqs);
    let spi = PioSpi::new(
        &mut pio.common,
        pio.sm0,
        RM2_CLOCK_DIVIDER,
        pio.irq0,
        cs,
        p.PIN_24,
        p.PIN_29,
        p.DMA_CH0,
    );
    // let ledpin = Output::new(, Level::Low);

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

    let adcthing = p.ADC_TEMP_SENSOR;
    let temp_channel = embassy_rp::adc::Channel::new_temp_sensor(adcthing);
    let adc = embassy_rp::adc::Adc::new(p.ADC, Irqs, embassy_rp::adc::Config::default());

    // let mut bulb_pin = Output::new(p.PIN_26, Level::Low);

    // let mut bulb = move |state: bool| {
    //     //embassy_futures::block_on(control.gpio_set(0, true));
    //     info!("setting pin to: {}", state);
    //     bulb_pin.set_level(if state { Level::High } else { Level::Low });
    // };

    run(controller, control, temp_channel, adc).await;
}
