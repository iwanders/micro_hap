use cyw43_pio::{PioSpi, RM2_CLOCK_DIVIDER};
use defmt::{error, info, unwrap, warn};
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::DMA_CH0;

use embassy_rp::pio::Pio;
use static_cell::StaticCell;

use embassy_futures::{join::join, select::select};
use embassy_time::Timer;
use trouble_host::prelude::*;

use zerocopy::IntoBytes;

use micro_hap::{
    ble::broadcast::BleBroadcastParameters, AccessoryInterface, CharId, CharacteristicResponse,
    PlatformSupport,
};

struct LightBulbAccessory<'a> {
    name: HeaplessString<32>,
    bulb_on_state: bool,
    bulb_control: cyw43::Control<'a>,
}
impl<'a> AccessoryInterface for LightBulbAccessory<'a> {
    async fn read_characteristic(&self, char_id: CharId) -> Option<impl Into<&[u8]>> {
        if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_NAME {
            Some(self.name.as_bytes())
        } else if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_ON {
            Some(self.bulb_on_state.as_bytes())
        } else {
            todo!("accessory interface for char id: 0x{:02?}", char_id)
        }
    }
    async fn write_characteristic(
        &mut self,
        char_id: CharId,
        data: &[u8],
    ) -> Result<CharacteristicResponse, ()> {
        info!(
            "AccessoryInterface to characterstic: 0x{:?} data: {:?}",
            char_id.0, data
        );

        if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_ON {
            let value = data.get(0).ok_or(())?;
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
            todo!("accessory interface for char id: 0x{:02?}", char_id)
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

use micro_hap::pairing::{Pairing, PairingError, PairingId, ED25519_LTSK};
#[derive(Debug, Clone)]
pub struct ActualPairSupport {
    pub ed_ltsk: [u8; micro_hap::pairing::ED25519_LTSK],
    pub pairings: heapless::index_map::FnvIndexMap<
        micro_hap::pairing::PairingId,
        micro_hap::pairing::Pairing,
        2,
    >,
    pub global_state_number: u16,
    pub config_number: u16,
    pub broadcast_parameters: BleBroadcastParameters,
    pub random_bytes: &'static [u8],
    pub random_byte_index: usize,
}
impl Default for ActualPairSupport {
    fn default() -> Self {
        Self {
            ed_ltsk: [
                182, 215, 245, 151, 120, 82, 56, 100, 73, 148, 49, 127, 131, 22, 235, 192, 207, 15,
                80, 115, 241, 91, 203, 234, 46, 135, 77, 137, 203, 204, 159, 230,
            ],
            pairings: Default::default(),
            global_state_number: 1,
            config_number: 1,
            broadcast_parameters: Default::default(),
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
        }
    }
}
impl PlatformSupport for ActualPairSupport {
    async fn get_ltsk(&self) -> [u8; ED25519_LTSK] {
        self.ed_ltsk
    }

    async fn fill_random(&mut self, buffer: &mut [u8]) -> () {
        buffer.copy_from_slice(&self.random_bytes[self.random_byte_index..buffer.len()]);

        self.random_byte_index += buffer.len();
    }

    async fn store_pairing(&mut self, pairing: &Pairing) -> Result<(), PairingError> {
        error!("Storing pairing");
        self.pairings
            .insert(pairing.id, *pairing)
            .map_err(|_| PairingError::IncorrectLength)?;
        Ok(())
    }

    async fn get_pairing(&mut self, id: &PairingId) -> Result<Option<Pairing>, PairingError> {
        error!("retrieving id pairing id");
        Ok(self.pairings.get(id).copied())
    }

    async fn get_global_state_number(&self) -> Result<u16, PairingError> {
        Ok(self.global_state_number)
    }
    /// Set the global state number, this is used by the BLE transport.
    async fn set_global_state_number(&mut self, value: u16) -> Result<(), PairingError> {
        self.global_state_number = value;
        Ok(())
    }
    async fn get_config_number(&self) -> Result<u16, PairingError> {
        Ok(self.config_number)
    }
    async fn set_config_number(&mut self, value: u16) -> Result<(), PairingError> {
        self.config_number = value;
        Ok(())
    }
    async fn get_ble_broadcast_parameters(
        &self,
    ) -> Result<micro_hap::ble::broadcast::BleBroadcastParameters, PairingError> {
        Ok(self.broadcast_parameters)
    }
    async fn set_ble_broadcast_parameters(
        &mut self,
        params: &micro_hap::ble::broadcast::BleBroadcastParameters,
    ) -> Result<(), PairingError> {
        self.broadcast_parameters = *params;
        Ok(())
    }
}

// use bt_hci::cmd::le::LeReadLocalSupportedFeatures;
// use bt_hci::cmd::le::LeSetDataLength;
// use bt_hci::controller::ControllerCmdSync;
const DEVICE_ADDRESS: [u8; 6] = [0xff, 0x8f, 0x1a, 0x07, 0xe4, 0xff];
/// Run the BLE stack.
pub async fn run<'p, 'cyw, C>(controller: C, bulb_control: cyw43::Control<'_>)
where
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
        static STATE: StaticCell<micro_hap::pairing::PairContext> = StaticCell::new();
        STATE.init_with(micro_hap::pairing::PairContext::default)
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

    let buffer: &mut [u8] = {
        static STATE: StaticCell<[u8; 2048]> = StaticCell::new();
        STATE.init([0u8; 2048])
    };

    // This is also pretty big on the stack :/
    let mut hap_context = micro_hap::ble::HapPeripheralContext::new(
        buffer,
        pair_ctx,
        &server.accessory_information,
        &server.protocol,
        &server.pairing,
    )
    .unwrap();
    hap_context.add_service(&server.lightbulb).unwrap();

    hap_context.assign_static_data(&static_information);

    //info!("hap_context: {:0>#2x?}", hap_context);

    // The handle exists... where does it go wrong??

    hap_context.print_handles();

    //let mut support = ActualPairSupport::default();
    // Put this in static memory instead of the stack, we got some very short messages without this, did we corrupt the
    // stack? How can we detect that?
    // Still getting connection termination.
    let support = {
        static STATE: StaticCell<ActualPairSupport> = StaticCell::new();
        STATE.init(ActualPairSupport::default())
    };

    // _benchmark_srp().await;

    let _ = join(ble_task(runner), async {
        loop {
            match advertise(name, &mut peripheral, &server, &static_information).await {
                Ok(conn) => {
                    // Increase the data length to 251 bytes per package, default is like 27.
                    // conn.update_data_length(&stack, 251, 2120)
                    //     .await
                    //     .expect("Failed to set data length");
                    let conn = conn
                        .with_attribute_server(&server)
                        .expect("Failed to create attribute server");
                    // set up tasks when the connection is established to a central, so they don't run when no one is connected.
                    let a =
                        gatt_events_task(&mut hap_context, &mut accessory, support, &server, &conn);
                    let b = custom_task(&server, &conn, &stack);
                    // run until any task ends (usually because the connection has been closed),
                    // then return to advertising state.
                    let x = select(a, b).await;
                    match x {
                        embassy_futures::select::Either::First(a) => {
                            if let Err(e) = a {
                                error!("Error occured in processing: {:?}", e);
                            }
                        }
                        embassy_futures::select::Either::Second(_) => {}
                    }
                }
                Err(e) => {
                    let e = defmt::Debug2Format(&e);
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

/// Stream Events until the connection closes.
///
/// This function will handle the GATT events and process them.
/// This is how we interact with read and write requests.
async fn gatt_events_task<P: PacketPool>(
    hap_context: &mut micro_hap::ble::HapPeripheralContext,
    accessory: &mut impl micro_hap::AccessoryInterface,
    support: &mut impl PlatformSupport,
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, P>,
) -> Result<(), Error> {
    //let level = server.battery_service.level;
    let reason = loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { reason } => break reason,

            GattConnectionEvent::Gatt { event } => {
                match &event {
                    GattEvent::Read(event) => {
                        /*if event.handle() == level.handle {
                            let value = server.get(&level);
                            info!("[gatt] Read Event to Level Characteristic: {:?}", value);
                        }*/
                        let peek = event.payload();
                        match peek.incoming() {
                            trouble_host::att::AttClient::Request(att_req) => {
                                info!("[gatt-attclient]: {:?}", att_req);
                            }
                            trouble_host::att::AttClient::Command(att_cmd) => {
                                info!("[gatt-attclient]: {:?}", att_cmd);
                            }
                            trouble_host::att::AttClient::Confirmation(att_cfm) => {
                                info!("[gatt-attclient]: {:?}", att_cfm);
                            }
                        }
                    }
                    GattEvent::Write(event) => {
                        info!(
                            "[gatt] Write Event to Level Characteristic: {:?}",
                            event.data()
                        );
                    }
                    GattEvent::Other(t) => {
                        let peek = t.payload();
                        if let Some(handle) = peek.handle() {
                            info!("[gatt] other event on handle: {}", handle);
                        }
                        match peek.incoming() {
                            trouble_host::att::AttClient::Request(att_req) => {
                                info!("[gatt-attclient]: {:?}", att_req);
                            }
                            trouble_host::att::AttClient::Command(att_cmd) => {
                                info!("[gatt-attclient]: {:?}", att_cmd);
                            }
                            trouble_host::att::AttClient::Confirmation(att_cfm) => {
                                info!("[gatt-attclient]: {:?}", att_cfm);
                            }
                        }
                        info!("[gatt] other event ");
                    } //_ => {}
                };
                // This step is also performed at drop(), but writing it explicitly is necessary
                // in order to ensure reply is sent.

                let fallthrough_event = hap_context
                    .process_gatt_event(&server.as_hap(), support, accessory, event)
                    .await;
                if let Err(e) = &fallthrough_event {
                    error!("fallthrough_event error: {:?}", e)
                };

                let fallthrough_event = fallthrough_event?;

                if let Some(event) = fallthrough_event {
                    match event.accept() {
                        Ok(reply) => reply.send().await,
                        Err(e) => {
                            warn!("[gatt] error sending response: {:?}", e)
                        }
                    };
                } else {
                    warn!("Omitted processing for event because it was handled");
                }
            }
            _ => {} // ignore other Gatt Connection Events
        }
    };
    info!("[gatt] disconnected: {:?}", reason);
    Ok(())
}

/// Create an advertiser to use to connect to a BLE Central, and wait for it to connect.
async fn advertise<'values, 'server, C: Controller>(
    name: &'values str,
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    server: &'server Server<'values>,
    static_info: &micro_hap::AccessoryInformationStatic,
) -> Result<Connection<'values, DefaultPacketPool>, BleHostError<C::Error>> {
    // ) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
    let _ = server;
    let adv_config = micro_hap::adv::AdvertisementConfig {
        device_id: static_info.device_id,
        setup_id: static_info.setup_id,
        accessory_category: static_info.category,
        ..Default::default()
    };
    let hap_adv = adv_config.to_advertisement();
    let adv = hap_adv.as_advertisement();

    let mut advertiser_data = [0; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            //AdStructure::ServiceUuids16(&[[0x0f, 0x18]]),
            AdStructure::CompleteLocalName(name.as_bytes()),
            adv,
        ],
        &mut advertiser_data[..],
    )?;
    let params = AdvertisementParameters {
        interval_min: embassy_time::Duration::from_millis(100),
        interval_max: embassy_time::Duration::from_millis(500),
        ..Default::default()
    };
    let advertiser = peripheral
        .advertise(
            &params,
            Advertisement::ConnectableScannableUndirected {
                adv_data: &advertiser_data[..len],
                scan_data: &[],
            },
        )
        .await?;
    info!("[adv] advertising");
    let conn = advertiser.accept().await?;
    info!("[adv] connection established");
    Ok(conn)
}

/// Example task to use the BLE notifier interface.
/// This task will notify the connected central of a counter value every 2 seconds.
/// It will also read the RSSI value every 2 seconds.
/// and will stop when the connection is closed by the central or an error occurs.
async fn custom_task<C: Controller, P: PacketPool>(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, P>,
    stack: &Stack<'_, C, P>,
) {
    let _ = server;
    let mut tick: u8 = 0;
    // let level = server.battery_service.level;
    loop {
        tick = tick.wrapping_add(1);
        info!("[custom_task] notifying connection of tick {}", tick);
        /*if level.notify(conn, &tick).await.is_err() {
            info!("[custom_task] error notifying connection");
            break;
        };*/
        // read RSSI (Received Signal Strength Indicator) of the connection.
        if let Ok(rssi) = conn.raw().rssi(stack).await {
            info!("[custom_task] RSSI: {:?}", rssi);
        } else {
            info!("[custom_task] error getting RSSI");
            break;
        };
        Timer::after_secs(2).await;
    }
}
use trouble_host::prelude::ExternalController;
//use {defmt_rtt as _, panic_probe as _};

use embassy_rp::peripherals::PIO2;
use embassy_rp::pio::InterruptHandler as PioInterruptHandler;
bind_interrupts!(struct Irqs {
    PIO2_IRQ_0 => PioInterruptHandler<PIO2>;
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

    // let mut bulb_pin = Output::new(p.PIN_26, Level::Low);

    // let mut bulb = move |state: bool| {
    //     //embassy_futures::block_on(control.gpio_set(0, true));
    //     info!("setting pin to: {}", state);
    //     bulb_pin.set_level(if state { Level::High } else { Level::Low });
    // };

    run(controller, control).await;
}
