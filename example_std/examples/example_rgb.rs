#![allow(unused_variables)]
#![allow(dead_code)]
use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;

// This contains two services that are different lightbulbs:
// - A lightbulb with a color temperature
// - A lightbulb with hue, saturation and brightness control.

mod hap_rgb_bulb {
    use micro_hap::{
        BleProperties, CharId, Characteristic, CharacteristicProperties, DataSource, Service,
        ServiceProperties, SvcId,
        ble::{FacadeDummyType, HapBleError, HapBleService, sig},
        characteristic, descriptor, service,
        uuid::HomekitUuid16,
    };
    use trouble_host::prelude::*;

    // This makes a lightbulb with a color temperature.
    pub const SERVICE_ID_TEMP_BULB: SvcId = SvcId(0x40);
    pub const CHAR_ID_TEMP_BULB_SIGNATURE: CharId = CharId(0x41);
    pub const CHAR_ID_TEMP_BULB_NAME: CharId = CharId(0x42);
    pub const CHAR_ID_TEMP_BULB_ON: CharId = CharId(0x43);
    pub const CHAR_ID_TEMP_BULB_COLOR: CharId = CharId(0x44);

    pub const CHARACTERISTIC_COLOR_TEMPERATURE: HomekitUuid16 = HomekitUuid16::new(0x00CE);
    #[gatt_service(uuid = service::LIGHTBULB)]
    pub struct TemperatureBulbService {
        #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = SERVICE_ID_TEMP_BULB.0)]
        pub service_instance: u16,

        /// Service signature, only two bytes.
        #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=CHAR_ID_TEMP_BULB_SIGNATURE.0.to_le_bytes())]
        pub service_signature: FacadeDummyType,

        /// Name for the device.
        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_TEMP_BULB_NAME.0.to_le_bytes())]
        #[characteristic(uuid=characteristic::NAME, read, write )]
        pub name: FacadeDummyType,

        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_TEMP_BULB_ON.0.to_le_bytes())]
        #[characteristic(uuid=characteristic::ON, read, write )]
        pub on: FacadeDummyType,

        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_TEMP_BULB_COLOR.0.to_le_bytes())]
        #[characteristic(uuid=CHARACTERISTIC_COLOR_TEMPERATURE, read, write )]
        pub color_temp: FacadeDummyType,
    }
    impl HapBleService for TemperatureBulbService {
        fn populate_support(&self) -> Result<Service, HapBleError> {
            let mut service = Service {
                ble_handle: Some(self.handle),
                uuid: service::LIGHTBULB.into(),
                iid: SERVICE_ID_TEMP_BULB,
                characteristics: Default::default(),
                properties: ServiceProperties::new().with_primary(false),
            };

            service
                .characteristics
                .push(
                    Characteristic::new(
                        characteristic::SERVICE_SIGNATURE.into(),
                        CHAR_ID_TEMP_BULB_SIGNATURE,
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
                    Characteristic::new(characteristic::NAME.into(), CHAR_ID_TEMP_BULB_NAME)
                        .with_properties(CharacteristicProperties::new().with_read(true))
                        .with_ble_properties(
                            BleProperties::from_handle(self.name.handle)
                                .with_format(sig::Format::StringUtf8),
                        )
                        .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;

            service
                .characteristics
                .push(
                    Characteristic::new(characteristic::ON.into(), CHAR_ID_TEMP_BULB_ON)
                        .with_properties(
                            CharacteristicProperties::new()
                                .with_rw(true)
                                .with_supports_event_notification(true)
                                .with_supports_disconnect_notification(true)
                                .with_supports_broadcast_notification(true),
                        )
                        .with_ble_properties(
                            BleProperties::from_handle(self.on.handle)
                                .with_format(sig::Format::Boolean),
                        )
                        .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;

            service
                .characteristics
                .push(
                    Characteristic::new(
                        CHARACTERISTIC_COLOR_TEMPERATURE.into(),
                        CHAR_ID_TEMP_BULB_COLOR,
                    )
                    .with_properties(
                        CharacteristicProperties::new()
                            .with_rw(true)
                            .with_supports_event_notification(true)
                            .with_supports_disconnect_notification(true)
                            .with_supports_broadcast_notification(true),
                    )
                    .with_range(micro_hap::VariableRange {
                        start: micro_hap::VariableUnion::U32(50),
                        end: micro_hap::VariableUnion::U32(400),
                        inclusive: true,
                    })
                    .with_step(micro_hap::VariableUnion::U32(1))
                    .with_ble_properties(
                        BleProperties::from_handle(self.color_temp.handle)
                            .with_format(sig::Format::U32)
                            //.with_unit(sig::Unit::Other(0x2763)), // in arcdegrees...
                            .with_unit(sig::Unit::Other(0x2705)), // in thermodynamic temperature, Kelvin
                                                                  //.with_unit(sig::Unit::ArcDegrees),
                    )
                    .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;
            Ok(service)
        }
    }

    // And this here makes an Hue, saturation, brightness lightbulb.
    // Maybe hue needs to be paired with saturation & brightness??
    // Perhaps color temperature is more standalone
    pub const SERVICE_ID_HSB_BULB: SvcId = SvcId(0x50);
    pub const CHAR_ID_HSB_BULB_SIGNATURE: CharId = CharId(0x51);
    pub const CHAR_ID_HSB_BULB_NAME: CharId = CharId(0x52);
    pub const CHAR_ID_HSB_BULB_ON: CharId = CharId(0x53);
    pub const CHAR_ID_HSB_BULB_HUE: CharId = CharId(0x54);
    pub const CHAR_ID_HSB_BULB_SATURATION: CharId = CharId(0x55);
    pub const CHAR_ID_HSB_BULB_BRIGHTNESS: CharId = CharId(0x56);

    pub const CHARACTERISTIC_HUE: HomekitUuid16 = HomekitUuid16::new(0x0013); // f32, 0..360, step=1, arcdegrees
    pub const CHARACTERISTIC_SATURATION: HomekitUuid16 = HomekitUuid16::new(0x002F); // f32, 0..100, step=1, percentage
    pub const CHARACTERISTIC_BRIGHTNESS: HomekitUuid16 = HomekitUuid16::new(0x0008); // int, 0..100, step=1, percentage

    #[gatt_service(uuid = service::LIGHTBULB)]
    pub struct RgbBulbService {
        #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = SERVICE_ID_HSB_BULB.0)]
        pub service_instance: u16,
        /// Service signature, only two bytes.
        #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=CHAR_ID_HSB_BULB_SIGNATURE.0.to_le_bytes())]
        pub service_signature: FacadeDummyType,

        /// Name for the device.
        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_HSB_BULB_NAME.0.to_le_bytes())]
        #[characteristic(uuid=characteristic::NAME, read, write )]
        pub name: FacadeDummyType,

        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_HSB_BULB_ON.0.to_le_bytes())]
        #[characteristic(uuid=characteristic::ON, read, write )]
        pub on: FacadeDummyType,

        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_HSB_BULB_HUE.0.to_le_bytes())]
        #[characteristic(uuid=CHARACTERISTIC_HUE, read, write )]
        pub hue: FacadeDummyType,
        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_HSB_BULB_SATURATION.0.to_le_bytes())]
        #[characteristic(uuid=CHARACTERISTIC_SATURATION, read, write )]
        pub saturation: FacadeDummyType,
        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_HSB_BULB_BRIGHTNESS.0.to_le_bytes())]
        #[characteristic(uuid=CHARACTERISTIC_BRIGHTNESS, read, write )]
        pub brightness: FacadeDummyType,
    }
    impl HapBleService for RgbBulbService {
        fn populate_support(&self) -> Result<Service, HapBleError> {
            let mut service = Service {
                ble_handle: Some(self.handle),
                uuid: service::LIGHTBULB.into(),
                iid: SERVICE_ID_HSB_BULB,
                characteristics: Default::default(),
                properties: ServiceProperties::new().with_primary(false),
            };

            service
                .characteristics
                .push(
                    Characteristic::new(
                        characteristic::SERVICE_SIGNATURE.into(),
                        CHAR_ID_HSB_BULB_SIGNATURE,
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
                    Characteristic::new(characteristic::NAME.into(), CHAR_ID_HSB_BULB_NAME)
                        .with_properties(CharacteristicProperties::new().with_read(true))
                        .with_ble_properties(
                            BleProperties::from_handle(self.name.handle)
                                .with_format(sig::Format::StringUtf8),
                        )
                        .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;

            service
                .characteristics
                .push(
                    Characteristic::new(characteristic::ON.into(), CHAR_ID_HSB_BULB_ON)
                        .with_properties(
                            CharacteristicProperties::new()
                                .with_rw(true)
                                .with_supports_event_notification(true)
                                .with_supports_disconnect_notification(true)
                                .with_supports_broadcast_notification(true),
                        )
                        .with_ble_properties(
                            BleProperties::from_handle(self.on.handle)
                                .with_format(sig::Format::Boolean),
                        )
                        .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;

            service
                .characteristics
                .push(
                    Characteristic::new(CHARACTERISTIC_HUE.into(), CHAR_ID_HSB_BULB_HUE)
                        .with_properties(
                            CharacteristicProperties::new()
                                .with_rw(true)
                                .with_supports_event_notification(true)
                                .with_supports_disconnect_notification(true)
                                .with_supports_broadcast_notification(true),
                        )
                        .with_range(micro_hap::VariableRange {
                            start: micro_hap::VariableUnion::F32(0.0),
                            end: micro_hap::VariableUnion::F32(360.0),
                            inclusive: true,
                        })
                        .with_step(micro_hap::VariableUnion::F32(1.0))
                        .with_ble_properties(
                            BleProperties::from_handle(self.hue.handle)
                                .with_format(sig::Format::F32)
                                .with_unit(sig::Unit::Other(0x2763)), // in arcdegrees...
                        )
                        .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;

            service
                .characteristics
                .push(
                    Characteristic::new(
                        CHARACTERISTIC_SATURATION.into(),
                        CHAR_ID_HSB_BULB_SATURATION,
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
                    .with_step(micro_hap::VariableUnion::F32(1.0))
                    .with_ble_properties(
                        BleProperties::from_handle(self.saturation.handle)
                            .with_format(sig::Format::F32)
                            .with_unit(sig::Unit::Percentage),
                    )
                    .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;

            service
                .characteristics
                .push(
                    Characteristic::new(
                        CHARACTERISTIC_BRIGHTNESS.into(),
                        CHAR_ID_HSB_BULB_BRIGHTNESS,
                    )
                    .with_properties(
                        CharacteristicProperties::new()
                            .with_rw(true)
                            .with_supports_event_notification(true)
                            .with_supports_disconnect_notification(true)
                            .with_supports_broadcast_notification(true),
                    )
                    .with_range(micro_hap::VariableRange {
                        start: micro_hap::VariableUnion::U32(0),
                        end: micro_hap::VariableUnion::U32(100),
                        inclusive: true,
                    })
                    .with_step(micro_hap::VariableUnion::U32(1))
                    .with_ble_properties(
                        BleProperties::from_handle(self.hue.handle)
                            .with_format(sig::Format::U32)
                            .with_unit(sig::Unit::Percentage),
                    )
                    .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;
            Ok(service)
        }
    }
}

mod hap_rgb {
    use super::hap_rgb_bulb;
    use example_std::{ActualPairSupport, AddressType, advertise, gatt_events_task, make_address};

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
    struct LightBulbAccessory {
        // Values for the color temperature bulb.
        // temp_name: HeaplessString<32>,
        temp_on_state: bool,
        temp_color_temperature_state: u32,
        // Values for the HSB bulbs.
        hsb_on_state: bool,
        hsb_hue: f32,
        hsb_saturation: f32,
        hsb_brightness: u32,
    }

    /// Implement the accessory interface for the lightbulb.
    impl AccessoryInterface for LightBulbAccessory {
        async fn read_characteristic(
            &self,
            char_id: CharId,
        ) -> Result<impl Into<&[u8]>, InterfaceError> {
            if char_id == hap_rgb_bulb::CHAR_ID_TEMP_BULB_NAME {
                Ok("warm_temperature_bulb".as_bytes())
            } else if char_id == hap_rgb_bulb::CHAR_ID_TEMP_BULB_ON {
                Ok(self.temp_on_state.as_bytes())
            } else if char_id == hap_rgb_bulb::CHAR_ID_TEMP_BULB_COLOR {
                Ok(self.temp_color_temperature_state.as_bytes())
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_NAME {
                Ok("hsb_superbulb".as_bytes())
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_ON {
                Ok(self.hsb_on_state.as_bytes())
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_HUE {
                Ok(self.hsb_hue.as_bytes())
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_SATURATION {
                Ok(self.hsb_saturation.as_bytes())
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_BRIGHTNESS {
                Ok(self.hsb_brightness.as_bytes())
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
                "AccessoryInterface to characterstic: 0x{:02?} data: {:02?}",
                char_id, data
            );

            let updater = |incoming: &[u8], dest: &mut [u8]| {
                let modified = incoming != dest;
                dest.copy_from_slice(incoming);
                if modified {
                    CharacteristicResponse::Modified
                } else {
                    CharacteristicResponse::Unmodified
                }
            };

            if char_id == hap_rgb_bulb::CHAR_ID_TEMP_BULB_ON {
                let togle_bool = &mut self.temp_on_state;

                let value = data
                    .get(0)
                    .ok_or(InterfaceError::CharacteristicWriteInvalid)?;
                let val_as_bool = *value != 0;

                let response = if *togle_bool != val_as_bool {
                    CharacteristicResponse::Modified
                } else {
                    CharacteristicResponse::Unmodified
                };
                *togle_bool = val_as_bool;
                info!("\nSet value to: {:?}\n", *togle_bool);
                Ok(response)
            } else if char_id == hap_rgb_bulb::CHAR_ID_TEMP_BULB_COLOR {
                let value_as_f32 = u32::from_le_bytes(data.try_into().unwrap());

                let response = if self.temp_color_temperature_state != value_as_f32 {
                    CharacteristicResponse::Modified
                } else {
                    CharacteristicResponse::Unmodified
                };
                self.temp_color_temperature_state = value_as_f32;
                info!("\nColor temperature value to: {:?}\n", value_as_f32);

                Ok(response)
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_ON {
                info!("Set on to {:?}", data);

                let togle_bool = &mut self.hsb_on_state;

                let value = data
                    .get(0)
                    .ok_or(InterfaceError::CharacteristicWriteInvalid)?;
                let val_as_bool = *value != 0;

                let response = if *togle_bool != val_as_bool {
                    CharacteristicResponse::Modified
                } else {
                    CharacteristicResponse::Unmodified
                };
                *togle_bool = val_as_bool;
                info!("\nSet hsb bulb to: {:?}\n", *togle_bool);
                Ok(response)
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_HUE {
                info!("Set hue to {:?}", data);
                Ok(updater(data, &mut self.hsb_hue.as_mut_bytes()))
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_SATURATION {
                info!("Set saturation to {:?}", data);
                Ok(updater(data, &mut self.hsb_saturation.as_mut_bytes()))
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_BRIGHTNESS {
                info!("Set brightness to {:?}", data);
                Ok(updater(data, &mut self.hsb_brightness.as_mut_bytes()))
            } else {
                Err(InterfaceError::CharacteristicUnknown(char_id))
            }
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
        temp_bulb: hap_rgb_bulb::TemperatureBulbService,
        rgb_bulb: hap_rgb_bulb::RgbBulbService,
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
    pub async fn run<C>(controller: C)
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

        // Setup the accessory information.
        let static_information = micro_hap::AccessoryInformationStatic {
            name: "micro_hap",
            device_id: micro_hap::DeviceId([
                address.addr.raw()[0],
                address.addr.raw()[1],
                address.addr.raw()[2],
                address.addr.raw()[3],
                address.addr.raw()[4],
                address.addr.raw()[5],
            ]),
            category: 5, // 5 is lighting
            ..Default::default()
        };

        // Create this specific accessory.
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L472
        let mut accessory = LightBulbAccessory {
            // name: "Light Bulb".try_into().unwrap(),
            temp_on_state: false,
            temp_color_temperature_state: 100,
            hsb_on_state: true,
            hsb_hue: 0.0,
            hsb_saturation: 25.0,
            hsb_brightness: 50,
        };

        // Create the pairing context.
        let pair_ctx = {
            static STATE: StaticCell<micro_hap::AccessoryContext> = StaticCell::new();
            STATE.init_with(micro_hap::AccessoryContext::default)
        };
        pair_ctx.accessory = static_information;
        pair_ctx
            .info
            .assign_from(rand::random(), PairCode::from_str("111-22-333").unwrap());

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
        hap_context.add_service(&server.temp_bulb).unwrap();
        hap_context.add_service(&server.rgb_bulb).unwrap();

        hap_context.assign_static_data(&static_information);

        // And the platform support.
        let mut support = ActualPairSupport::default();

        let _ = join(ble_task(runner), async {
            loop {
                match advertise(name, &mut peripheral, &static_information).await {
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
                        let a = gatt_events_task(
                            &mut hap_context,
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
    env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .init();

    let dev = match std::env::args().collect::<Vec<_>>()[..] {
        [_] => 0,
        [_, ref s] => s.parse::<u16>().expect("Could not parse device number"),
        _ => panic!(
            "Provide the device number as the one and only command line argument, or no arguments to use device 0."
        ),
    };
    let transport = Transport::new(dev)?;
    let controller = ExternalController::<_, 8>::new(transport);
    hap_rgb::run(controller).await;
    Ok(())
}
