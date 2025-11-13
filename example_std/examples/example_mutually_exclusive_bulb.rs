#![allow(unused_variables)]
#![allow(dead_code)]
use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;

mod services {
    use micro_hap::ble::{FacadeDummyType, HapBleError, HapBleService, sig};
    use micro_hap::{
        BleProperties, CharId, Characteristic, CharacteristicProperties, DataSource, Service,
        ServiceProperties, SvcId, characteristic, descriptor, service,
    };
    use trouble_host::prelude::*;

    // Why do we duplicate this from micro_hap::ble::services? because the gatt_service macro contains a static cell
    // and we want to allocate two of them... They must also be offset with their CharIds.
    // TODO: This is obviously less than ideal.
    const ID_OFFSET: u16 = 0x10;
    pub const CHAR_ID_LIGHTBULB_NAME: CharId = CharId(0x32 + ID_OFFSET);
    pub const CHAR_ID_LIGHTBULB_ON: CharId = CharId(0x33 + ID_OFFSET);
    #[gatt_service(uuid = service::LIGHTBULB)]
    pub struct OtherLightbulbService {
        #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x30 + ID_OFFSET)]
        pub service_instance: u16,

        /// Service signature, only two bytes.
        #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=(0x31u16 + ID_OFFSET).to_le_bytes())]
        pub service_signature: FacadeDummyType,

        // 0x0023
        /// Name for the device.
        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=(CHAR_ID_LIGHTBULB_NAME.0 ).to_le_bytes())]
        #[characteristic(uuid=characteristic::NAME, read, write )]
        pub name: FacadeDummyType,

        #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=(CHAR_ID_LIGHTBULB_ON.0 ).to_le_bytes())]
        #[characteristic(uuid=characteristic::ON, read, write, indicate, notify )]
        pub on: FacadeDummyType,
    }
    //
    //
    //
    //
    use embassy_sync::blocking_mutex::raw::RawMutex;
    impl OtherLightbulbService {
        pub fn create_hap_service<
            'server,
            'values,
            M: RawMutex,
            const ATT_MAX: usize,
            const CCCD_MAX: usize,
            const CONN_MAX: usize,
        >(
            &self,
            server: &'server AttributeServer<
                'values,
                M,
                DefaultPacketPool,
                ATT_MAX,
                CCCD_MAX,
                CONN_MAX,
            >,
        ) -> Result<Service, HapBleError> {
            let mut service = Service {
                ble_handle: Some(self.handle),
                uuid: service::LIGHTBULB.into(),
                iid: SvcId(0x30 + ID_OFFSET),
                characteristics: Default::default(),
                properties: ServiceProperties::new().with_primary(true),
            };

            service
                .characteristics
                .push(
                    Characteristic::new(
                        characteristic::SERVICE_SIGNATURE.into(),
                        CharId(0x31u16 + ID_OFFSET),
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
                    Characteristic::new(characteristic::NAME.into(), CharId(0x32u16 + ID_OFFSET))
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
                    Characteristic::new(characteristic::ON.into(), CharId(0x33u16 + ID_OFFSET))
                        .with_properties(
                            CharacteristicProperties::new()
                                .with_rw(true)
                                .with_supports_event_notification(true)
                                .with_supports_disconnect_notification(true)
                                .with_supports_broadcast_notification(true),
                        )
                        .with_ble_properties(
                            BleProperties::from_handle(self.on.handle)
                                .with_format(sig::Format::Boolean)
                                .with_characteristic(
                                    server
                                        .table()
                                        .find_characteristic_by_value_handle(self.on.handle)
                                        .unwrap(),
                                ),
                        )
                        .with_data(DataSource::AccessoryInterface),
                )
                .map_err(|_| HapBleError::AllocationOverrun)?;

            Ok(service)
        }
    }
}

mod hap_lightbulb {
    use example_std::RuntimeConfig;
    use example_std::{ActualPairSupport, AddressType, make_address};

    use log::info;
    use micro_hap::ble::FacadeDummyType;
    use micro_hap::ble::HapBleService;
    use micro_hap::{AccessoryInterface, CharId, CharacteristicResponse, InterfaceError, PairCode};
    use trouble_host::prelude::*;
    use zerocopy::IntoBytes;
    /// Struct to keep state for this specific accessory, with only a lightbulb.
    struct LightBulbAccessory {
        name_a: HeaplessString<32>,
        name_b: HeaplessString<32>,
        bulb_state_a: bool,
        bulb_state_b: bool,
        characteristic_a: trouble_host::attribute::Characteristic<FacadeDummyType>,
        characteristic_b: trouble_host::attribute::Characteristic<FacadeDummyType>,
    }

    /// Implement the accessory interface for the lightbulb.
    impl AccessoryInterface for LightBulbAccessory {
        async fn read_characteristic(
            &self,
            char_id: CharId,
        ) -> Result<impl Into<&[u8]>, InterfaceError> {
            if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_NAME {
                Ok(self.name_a.as_bytes())
            } else if char_id == super::services::CHAR_ID_LIGHTBULB_NAME {
                Ok(self.name_b.as_bytes())
            } else if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_ON {
                Ok(self.bulb_state_a.as_bytes())
            } else if char_id == super::services::CHAR_ID_LIGHTBULB_ON {
                Ok(self.bulb_state_b.as_bytes())
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

            if char_id != micro_hap::ble::CHAR_ID_LIGHTBULB_ON
                && char_id != super::services::CHAR_ID_LIGHTBULB_ON
            {
                return Err(InterfaceError::CharacteristicUnknown(char_id));
            }

            println!("Before {}, {}", self.bulb_state_a, self.bulb_state_b);
            let (boolean_val, boolean_other) = if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_ON {
                (&mut self.bulb_state_a, &mut self.bulb_state_b)
            } else {
                (&mut self.bulb_state_b, &mut self.bulb_state_a)
            };
            let (_, characteristic_other) = if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_ON {
                (&mut self.characteristic_a, &mut self.characteristic_b)
            } else {
                // always return b.
                (&mut self.characteristic_a, &mut self.characteristic_b)
            };

            let value = data
                .get(0)
                .ok_or(InterfaceError::CharacteristicWriteInvalid)?;
            let val_as_bool = *value != 0;

            if val_as_bool {
                *boolean_other = false;
            }

            let response = if *boolean_val != val_as_bool {
                CharacteristicResponse::Notify(*characteristic_other)
            } else {
                // CharacteristicResponse::Unmodified
                CharacteristicResponse::Notify(*characteristic_other)
            };
            *boolean_val = val_as_bool;
            println!("After {}, {}", self.bulb_state_a, self.bulb_state_b);
            Ok(response)
        }
    }

    // GATT Server definition
    #[gatt_server]
    struct Server {
        accessory_information: micro_hap::ble::AccessoryInformationService, // 0x003e
        protocol: micro_hap::ble::ProtocolInformationService,               // 0x00a2
        pairing: micro_hap::ble::PairingService,                            // 0x0055
        lightbulb_a: micro_hap::ble::LightbulbService,                      // 0x0043
        lightbulb_b: super::services::OtherLightbulbService,                // 0x0043
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

        // Create this specific accessory.
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L472
        let mut accessory = LightBulbAccessory {
            name_a: "Bulb A".try_into().unwrap(),
            name_b: "Bulb B".try_into().unwrap(),
            bulb_state_a: false,
            bulb_state_b: false,
            characteristic_a: server
                .table()
                .find_characteristic_by_value_handle(server.lightbulb_a.on.handle)
                .unwrap(),
            characteristic_b: server
                .table()
                .find_characteristic_by_value_handle(server.lightbulb_b.on.handle)
                .unwrap(),
        };

        // And the platform support.
        let mut support =
            ActualPairSupport::new_from_config(runtime_config).expect("failed to load file");

        let setup_id = support.setup_id;
        let pair_code = PairCode::from_str("111-22-333").unwrap();

        let mut hap_context = example_std::example_context_factory(
            pair_code,
            &support,
            &server.accessory_information,
            &server.protocol,
            &server.pairing,
        );

        // hap_context.add_service(&server.lightbulb_a).unwrap();
        hap_context
            .add_service(server.lightbulb_a.populate_support().unwrap())
            .unwrap();
        hap_context
            .add_service(
                server
                    .lightbulb_b
                    .create_hap_service(&server.server)
                    .unwrap(),
            )
            .unwrap();
        let hap_category = 8;
        example_std::print_pair_qr(&pair_code, &setup_id, hap_category);

        let value_a = server.lightbulb_a.on;
        let value_b = server.lightbulb_b.on;

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
    hap_lightbulb::run(controller, config).await;
    Ok(())
}
