#![allow(unused_variables)]
#![allow(dead_code)]
use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;

// This contains one service that's a temperature sensor.

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPCharacteristicTypes.h#L194
// paired read, notify
// 0 to 100, steps of 0.1? can't be negative?! But it's also a float, probably ignores the range

mod hap_temp_sensor {
    use micro_hap::{
        BleProperties, CharId, Characteristic, CharacteristicProperties, DataSource, Service,
        ServiceProperties, SvcId,
        ble::{FacadeDummyType, HapBleError, HapBleService, sig},
        characteristic, descriptor, service,
        uuid::HomekitUuid16,
    };
    use trouble_host::prelude::*;

    // This makes a lightbulb with a color temperature.
    pub const SERVICE_ID_TEMP_SENSOR: SvcId = SvcId(0x40);
    pub const CHAR_ID_TEMP_SENSOR_SIGNATURE: CharId = CharId(0x41);
    pub const CHAR_ID_TEMP_SENSOR_VALUE: CharId = CharId(0x42);

    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPCharacteristicTypes.c#L23
    pub const CHARACTERISTIC_CURRENT_TEMPERATURE: HomekitUuid16 = HomekitUuid16::new(0x0011);
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPServiceTypes.c#L51
    pub const SERVICE_TEMPERATURE_SENSOR: HomekitUuid16 = HomekitUuid16::new(0x8A);

    #[gatt_service(uuid = SERVICE_TEMPERATURE_SENSOR)]
    pub struct TemperatureSensorService {
        #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = SERVICE_ID_TEMP_SENSOR.0)]
        pub service_instance: u16,

        /// Service signature, only two bytes.
        #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=CHAR_ID_TEMP_SENSOR_SIGNATURE.0.to_le_bytes())]
        pub service_signature: FacadeDummyType,

        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_TEMP_SENSOR_VALUE.0.to_le_bytes())]
        #[characteristic(uuid=CHARACTERISTIC_CURRENT_TEMPERATURE, read, write )]
        pub value: FacadeDummyType,
    }
    impl HapBleService for TemperatureSensorService {
        fn populate_support(&self) -> Result<Service, HapBleError> {
            let mut service = Service {
                ble_handle: Some(self.handle),
                uuid: SERVICE_TEMPERATURE_SENSOR.into(),
                iid: SERVICE_ID_TEMP_SENSOR,
                characteristics: Default::default(),
                properties: ServiceProperties::new().with_primary(false),
            };

            service
                .characteristics
                .push(
                    Characteristic::new(
                        characteristic::SERVICE_SIGNATURE.into(),
                        CHAR_ID_TEMP_SENSOR_SIGNATURE,
                    )
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.service_signature.handle)
                            .with_format_opaque(),
                    ),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;

            service
                .characteristics
                .push(
                    Characteristic::new(
                        CHARACTERISTIC_CURRENT_TEMPERATURE.into(),
                        CHAR_ID_TEMP_SENSOR_VALUE,
                    )
                    .with_properties(
                        CharacteristicProperties::new()
                            .with_rw(true)
                            .with_supports_event_notification(true)
                            .with_supports_disconnect_notification(true)
                            .with_supports_broadcast_notification(true),
                    )
                    .with_range(micro_hap::VariableRange {
                        start: micro_hap::VariableUnion::F32(0.0),
                        end: micro_hap::VariableUnion::F32(100.0),
                        inclusive: true,
                    })
                    .with_step(micro_hap::VariableUnion::F32(0.1))
                    .with_ble_properties(
                        BleProperties::from_handle(self.value.handle)
                            .with_format(sig::Format::F32)
                            .with_unit(sig::Unit::Celsius),
                    )
                    .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;

            Ok(service)
        }
    }
}

mod hap_temp_accessory {
    use super::hap_temp_sensor;
    use example_std::RuntimeConfig;
    use example_std::{ActualPairSupport, AddressType, make_address};

    use embassy_futures::join::join;
    use log::info;
    use static_cell::StaticCell;
    use trouble_host::prelude::*;
    use zerocopy::IntoBytes;

    use micro_hap::{
        AccessoryInterface, CharId, CharacteristicResponse, InterfaceError, PairCode,
        ble::TimedWrite,
    };

    /// Struct to keep state for this specific accessory, with only a lightbulb.
    #[repr(C)]
    struct TemperatureAccessory {
        temperature_value: f32,
    }

    /// Implement the accessory interface for the lightbulb.
    impl AccessoryInterface for TemperatureAccessory {
        async fn read_characteristic(
            &self,
            char_id: CharId,
        ) -> Result<impl Into<&[u8]>, InterfaceError> {
            if char_id == hap_temp_sensor::CHAR_ID_TEMP_SENSOR_VALUE {
                Ok(self.temperature_value.as_bytes())
            } else {
                Err(InterfaceError::CharacteristicUnknown(char_id))
            }
        }
        async fn write_characteristic(
            &mut self,
            char_id: CharId,
            data: &[u8],
        ) -> Result<CharacteristicResponse, InterfaceError> {
            // Nothing is writable here.
            Err(InterfaceError::CharacteristicUnknown(char_id))
        }
    }

    /// Max number of connections
    const CONNECTIONS_MAX: usize = 3;

    /// Max number of L2CAP channels.
    const L2CAP_CHANNELS_MAX: usize = 5; // Signal + att

    // GATT Server definition
    #[gatt_server]
    struct Server {
        accessory_information: micro_hap::ble::AccessoryInformationService,
        protocol: micro_hap::ble::ProtocolInformationService,
        pairing: micro_hap::ble::PairingService,
        //lightbulb: micro_hap::ble::LightbulbService,
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
    use bt_hci::cmd::le::LeReadLocalSupportedFeatures;
    use bt_hci::cmd::le::LeSetDataLength;
    use bt_hci::controller::ControllerCmdSync;
    /// Run the BLE stack.
    pub async fn run<C>(controller: C, runtime_config: RuntimeConfig)
    where
        C: Controller
            + ControllerCmdSync<LeReadLocalSupportedFeatures>
            + ControllerCmdSync<LeSetDataLength>,
    {
        // Bring up the stack.
        let address = make_address(AddressType::Random);
        info!("Our address = {:?}", address);

        let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
            HostResources::new();

        let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
        let Host {
            mut peripheral,
            runner,
            ..
        } = stack.build();

        // Create the gatt server.
        let name = "Z"; // There's _very_ few bytes left in the advertisement
        info!("Starting advertising and GATT service");
        let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::power_device::LED_DRIVER,
        }))
        .unwrap();

        // Create this specific accessory.
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L472
        let mut accessory = TemperatureAccessory {
            temperature_value: -6.0,
        };

        // And the platform support.
        let mut support =
            ActualPairSupport::new_from_config(runtime_config).expect("failed to load file");

        let static_information = micro_hap::AccessoryInformationStatic {
            name: "micro_hap",
            device_id: support.device_id,
            setup_id: support.setup_id,
            category: 10, // 10 is sensors
            ..Default::default()
        };
        let setup_id = static_information.setup_id;

        // Create the pairing context.
        let pair_ctx = {
            static STATE: StaticCell<micro_hap::AccessoryContext> = StaticCell::new();
            STATE.init_with(micro_hap::AccessoryContext::default)
        };
        let pair_code = PairCode::from_str("111-22-333").unwrap();
        pair_ctx.info.assign_from(rand::random(), pair_code);
        pair_ctx.accessory = static_information;

        // Create the buffer for hap messages in the gatt server.
        let buffer: &mut [u8] = {
            static STATE: StaticCell<[u8; 2048]> = StaticCell::new();
            STATE.init([0u8; 2048])
        };

        const TIMED_WRITE_SLOTS: usize = 8;
        const TIMED_WRITE_SLOTS_DATA: usize = 128;

        let timed_write_data = {
            static DATA_STATE: StaticCell<[u8; TIMED_WRITE_SLOTS * TIMED_WRITE_SLOTS_DATA]> =
                StaticCell::new();
            DATA_STATE.init([0u8; TIMED_WRITE_SLOTS * TIMED_WRITE_SLOTS_DATA])
        };

        let timed_write = {
            static SLOT_STATE: StaticCell<[Option<TimedWrite>; TIMED_WRITE_SLOTS]> =
                StaticCell::new();
            SLOT_STATE.init([None; TIMED_WRITE_SLOTS])
        };

        // Then finally we can create the hap peripheral context.
        let mut hap_context = micro_hap::ble::HapPeripheralContext::new(
            buffer,
            pair_ctx,
            timed_write_data,
            timed_write,
            &server.accessory_information,
            &server.protocol,
            &server.pairing,
        )
        .unwrap();
        // hap_context.add_service(&server.lightbulb).unwrap();
        hap_context.add_service(&server.temp_sensor).unwrap();

        hap_context.assign_static_data(&static_information);
        example_std::print_pair_qr(&pair_code, &setup_id, static_information.category as u8);

        println!("support: {support:?}");

        let _ = join(ble_task(runner), async {
            loop {
                match hap_context
                    .advertise(&mut accessory, &mut support, &mut peripheral)
                    .await
                {
                    Ok(conn) => {
                        // Increase the data length to 251 bytes per package, default is like 27.
                        conn.update_data_length(&stack, 251, 2120)
                            .await
                            .expect("Failed to set data length");
                        let conn = conn
                            .with_attribute_server(&server)
                            .expect("Failed to create attribute server");
                        // set up tasks when the connection is established to a central, so they don't run when no one is connected.
                        let hap_services = server.as_hap();
                        let a = hap_context.gatt_events_task(
                            &mut accessory,
                            &mut support,
                            &hap_services,
                            &conn,
                        );

                        // run until any task ends (usually because the connection has been closed),
                        // then return to advertising state.
                        if let Err(e) = a.await {
                            log::error!("Error occured in processing: {e:?}");
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
    async fn ble_task<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) {
        loop {
            if let Err(e) = runner.run().await {
                panic!("[ble_task] error: {:?}", e);
            }
        }
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), std::io::Error> {
    use clap::Parser;
    env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .init();

    let args = example_std::CommonArgs::parse();
    println!("args: {args:?}");

    let dev = args.device.unwrap_or(0);
    let config = args.to_runtime_config();
    let transport = Transport::new(dev)?;
    let controller = ExternalController::<_, 8>::new(transport);
    hap_temp_accessory::run(controller, config).await;
    Ok(())
}
