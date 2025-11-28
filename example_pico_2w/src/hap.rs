use cyw43_pio::{PioSpi, RM2_CLOCK_DIVIDER};
use defmt::{error, info, unwrap};
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::DMA_CH0;

use embassy_rp::pio::Pio;
use static_cell::StaticCell;

use embassy_futures::join::join;
use micro_hap::IntoBytesForAccessoryInterface;
use trouble_host::prelude::*;

use micro_hap::{
    ble::broadcast::BleBroadcastParameters, ble::HapBleService, ble::TimedWrite,
    AccessoryInterface, CharId, CharacteristicResponse, InterfaceError, PlatformSupport,
};
struct LightBulbAccessory<'a> {
    name: HeaplessString<32>,
    bulb_on_state: bool,
    bulb_control: cyw43::Control<'a>,
}
impl<'a> AccessoryInterface for LightBulbAccessory<'a> {
    async fn read_characteristic<'b>(
        &self,
        char_id: CharId,
        output: &'b mut [u8],
    ) -> Result<&'b [u8], InterfaceError> {
        if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_NAME {
            self.name.read_characteristic_into(char_id, output)
        } else if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_ON {
            self.bulb_on_state.read_characteristic_into(char_id, output)
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

pub struct ActualPairSupport<'a, R: embassy_rp::trng::Instance> {
    pub ed_ltsk: [u8; micro_hap::pairing::ED25519_LTSK],
    pub pairings: heapless::index_map::FnvIndexMap<
        micro_hap::pairing::PairingId,
        micro_hap::pairing::Pairing,
        2,
    >,
    pub global_state_number: u16,
    pub config_number: u8,
    pub broadcast_parameters: BleBroadcastParameters,
    pub rng: embassy_rp::trng::Trng<'a, R>,
    pub random_bytes: &'static [u8],
    pub random_byte_index: usize,
    pub ble_broadcast_config: heapless::index_map::FnvIndexMap<CharId, BleBroadcastInterval, 16>,
}

impl<'a, R: embassy_rp::trng::Instance> ActualPairSupport<'a, R> {
    fn new(rng: embassy_rp::trng::Trng<'a, R>) -> Self {
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
            // [random.randrange(0,255) for i in range(512)]
            random_byte_index: 0,
            random_bytes: &[
                175, 37, 92, 197, 240, 140, 237, 84, 151, 244, 199, 38, 241, 51, 93, 148, 199, 20,
                34, 56, 27, 118, 245, 101, 158, 19, 199, 132, 16, 59, 154, 45, 165, 249, 75, 158,
                49, 89, 185, 246, 197, 61, 128, 246, 221, 171, 185, 58, 242, 94, 197, 84, 33, 34,
                161, 158, 204, 239, 117, 116, 33, 41, 76, 189, 48, 116, 81, 96, 22, 127, 106, 112,
                36, 136, 174, 148, 191, 67, 130, 107, 151, 195, 161, 24, 55, 115, 227, 169, 160,
                22, 20, 21, 10, 1, 17, 132, 201, 237, 74, 170, 49, 105, 110, 219, 245, 239, 175,
                17, 125, 145, 121, 13, 236, 155, 10, 43, 82, 64, 93, 242, 30, 37, 62, 190, 125,
                131, 227, 61, 1, 123, 211, 166, 253, 141, 44, 239, 6, 82, 201, 207, 17, 155, 141,
                67, 173, 172, 179, 224, 108, 177, 43, 137, 75, 18, 54, 61, 218, 252, 74, 98, 166,
                173, 11, 250, 148, 21, 113, 107, 50, 17, 211, 75, 49, 223, 156, 14, 155, 196, 10,
                97, 6, 107, 41, 123, 113, 57, 18, 89, 214, 62, 94, 165, 200, 83, 46, 81, 169, 114,
                238, 52, 188, 111, 250, 175, 41, 42, 217, 55, 240, 89, 197, 48, 35, 252, 140, 224,
                145, 22, 35, 96, 154, 251, 248, 90, 228, 2, 150, 233, 74, 82, 237, 175, 117, 167,
                114, 150, 213, 24, 125, 186, 83, 203, 153, 127, 233, 93, 70, 24, 237, 113, 157, 43,
                93, 220, 225, 210, 42, 130, 56, 200, 117, 248, 200, 19, 112, 241, 91, 6, 46, 159,
                130, 251, 76, 86, 148, 134, 150, 97, 31, 240, 18, 211, 110, 42, 142, 73, 8, 27,
                212, 169, 105, 250, 85, 12, 224, 103, 216, 183, 191, 54, 83, 5, 152, 180, 238, 124,
                227, 83, 97, 207, 30, 126, 220, 244, 101, 43, 199, 152, 148, 51, 41, 187, 69, 10,
                22, 210, 54, 141, 40, 136, 213, 249, 171, 21, 83, 230, 118, 199, 9, 90, 32, 48,
                234, 1, 210, 148, 241, 75, 252, 26, 116, 64, 59, 212, 48, 6, 161, 248, 70, 55, 176,
                95, 144, 58, 219, 60, 35, 115, 100, 49, 93, 86, 178, 68, 231, 211, 239, 156, 34,
                27, 39, 31, 110, 108, 171, 17, 202, 133, 170, 254, 156, 185, 70, 105, 44, 184, 41,
                117, 45, 210, 49, 172, 101, 209, 25, 155, 111, 59, 252, 32, 230, 61, 244, 109, 162,
                216, 17, 220, 238, 48, 104, 204, 44, 135, 33, 120, 135, 36, 114, 182, 216, 117,
                247, 254, 111, 13, 150, 66, 164, 36, 181, 163, 127, 6, 81, 77, 151, 161, 154, 100,
                239, 115, 82, 185, 95, 183, 125, 14, 168, 69, 66, 38, 5, 54, 15, 13, 3, 185, 162,
                59, 44, 80, 22, 15, 206, 43, 7, 54, 151, 252, 11, 254, 203, 19, 209, 88, 105, 204,
                39, 49, 237, 61, 146, 85, 218, 188, 78, 191, 156, 83, 197, 130, 115, 109, 26, 154,
                215, 213, 159, 46, 86, 186,
            ],
            rng,
        }
    }
}
impl<'a, R: embassy_rp::trng::Instance> PlatformSupport for ActualPairSupport<'a, R> {
    fn get_time(&self) -> embassy_time::Instant {
        embassy_time::Instant::now()
    }

    async fn get_ltsk(&self) -> [u8; ED25519_LTSK] {
        self.ed_ltsk
    }

    async fn fill_random(&mut self, buffer: &mut [u8]) -> () {
        // buffer.copy_from_slice(&self.random_bytes[self.random_byte_index..buffer.len()]);

        // self.random_byte_index += buffer.len();
        //
        self.rng.fill_bytes(buffer).await;
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

// use bt_hci::cmd::le::LeReadLocalSupportedFeatures;
// use bt_hci::cmd::le::LeSetDataLength;
// use bt_hci::controller::ControllerCmdSync;
const DEVICE_ADDRESS: [u8; 6] = [0xff, 0x8f, 0x1a, 0x02, 0xe4, 0xff];
/// Run the BLE stack.
pub async fn run<'p, 'cyw, C, R: embassy_rp::trng::Instance>(
    controller: C,
    bulb_control: cyw43::Control<'_>,
    rng: embassy_rp::trng::Trng<'_, R>,
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
    let mut accessory = LightBulbAccessory {
        name: "Light Bulb".try_into().unwrap(),
        bulb_on_state: false,
        bulb_control,
    };
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
        &server.accessory_information,
        &server.protocol,
        &server.pairing,
        control_receiver,
    )
    .unwrap();
    hap_context
        .add_service(server.lightbulb.populate_support().unwrap())
        .unwrap();

    hap_context.assign_static_data(&static_information);

    //info!("hap_context: {:0>#2x?}", hap_context);

    // The handle exists... where does it go wrong??

    hap_context.print_handles();

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
    let mut support = ActualPairSupport::new(rng);
    let support = &mut support;

    let _ = join(ble_task(runner), async {
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
                    let a =
                        hap_context.gatt_events_task(&mut accessory, support, &hap_services, &conn);

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
    })
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

    let trng = embassy_rp::trng::Trng::new(p.TRNG, Irqs, embassy_rp::trng::Config::default());

    // let mut bulb_pin = Output::new(p.PIN_26, Level::Low);
    // let mut bulb = move |state: bool| {
    //     //embassy_futures::block_on(control.gpio_set(0, true));
    //     info!("setting pin to: {}", state);
    //     bulb_pin.set_level(if state { Level::High } else { Level::Low });
    // };

    run(controller, control, trng).await;
}
