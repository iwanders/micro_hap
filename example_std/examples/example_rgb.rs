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
    use example_std::{ActualPairSupport, AddressType, RuntimeConfig, make_address};

    use log::info;
    use micro_hap::IntoBytesForAccessoryInterface;
    use micro_hap::ble::HapBleService;
    use trouble_host::prelude::*;
    use zerocopy::IntoBytes;

    use micro_hap::{AccessoryInterface, CharId, CharacteristicResponse, InterfaceError, PairCode};

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
        async fn read_characteristic<'a>(
            &self,
            char_id: CharId,
            output: &'a mut [u8],
        ) -> Result<&'a [u8], InterfaceError> {
            if char_id == hap_rgb_bulb::CHAR_ID_TEMP_BULB_NAME {
                "warm_temperature_bulb".read_characteristic_into(char_id, output)
            } else if char_id == hap_rgb_bulb::CHAR_ID_TEMP_BULB_ON {
                self.temp_on_state.read_characteristic_into(char_id, output)
            } else if char_id == hap_rgb_bulb::CHAR_ID_TEMP_BULB_COLOR {
                self.temp_color_temperature_state
                    .read_characteristic_into(char_id, output)
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_NAME {
                "hsb_superbulb".read_characteristic_into(char_id, output)
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_ON {
                self.hsb_on_state.read_characteristic_into(char_id, output)
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_HUE {
                self.hsb_hue.read_characteristic_into(char_id, output)
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_SATURATION {
                self.hsb_saturation
                    .read_characteristic_into(char_id, output)
            } else if char_id == hap_rgb_bulb::CHAR_ID_HSB_BULB_BRIGHTNESS {
                self.hsb_brightness
                    .read_characteristic_into(char_id, output)
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
    pub async fn run<C>(controller: C, runtime_config: RuntimeConfig)
    where
        C: Controller
            + ControllerCmdSync<LeReadLocalSupportedFeatures>
            + ControllerCmdSync<LeSetDataLength>,
    {
        // Bring up the stack.
        let address = make_address(AddressType::Random);
        info!("Our address = {:?}", address);

        // Create the gatt server.
        let name = "Z"; // There's _very_ few bytes left in the advertisement
        info!("Starting advertising and GATT service");
        let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
        }))
        .unwrap();

        // And the platform support.
        let mut support =
            ActualPairSupport::new_from_config(runtime_config).expect("failed to load file");

        let setup_id = support.setup_id;
        let pair_code = PairCode::from_str("111-22-333").unwrap();

        let (mut hap_context, control_sender) = example_std::example_context_factory(
            pair_code,
            &support,
            &server.accessory_information,
            &server.protocol,
            &server.pairing,
        );
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

        // hap_context.add_service(&server.lightbulb).unwrap();
        hap_context
            .add_service(server.temp_bulb.populate_support().unwrap())
            .unwrap();
        hap_context
            .add_service(server.rgb_bulb.populate_support().unwrap())
            .unwrap();

        let hap_category = 5; // lighting
        example_std::print_pair_qr(&pair_code, &setup_id, hap_category);

        let _ = example_std::example_hap_loop(
            address,
            controller,
            &mut hap_context,
            &mut accessory,
            &mut support,
            &server,
            &server.as_hap(),
        )
        .await;
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
    hap_rgb::run(controller, config).await;
    Ok(())
}
