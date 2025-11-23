#![allow(unused_variables)]
#![allow(dead_code)]
use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;

// This contains one service that's a temperature sensor.

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPCharacteristicTypes.h#L194
//
// This is the wrong way to do this:
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAP.h#L473-L475
//
// * - Disconnected events should only be used to reflect important state changes in the accessory.
// *   For example, contact sensor state changes or current door state changes should use this property.
// *   On the other hand, a temperature sensor must not use this property for changes in temperature readings.

mod hap_temp_sensor {
    use micro_hap::{
        BleProperties, CharId, Characteristic, CharacteristicProperties, DataSource, Service,
        ServiceProperties, SvcId,
        ble::{FacadeDummyType, HapBleError, sig},
        characteristic, descriptor,
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
        #[characteristic(uuid=CHARACTERISTIC_CURRENT_TEMPERATURE, read, write, indicate)]
        pub value: FacadeDummyType,
    }
    use embassy_sync::blocking_mutex::raw::RawMutex;
    impl TemperatureSensorService {
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
                            .with_supports_disconnect_notification(true) // Without this, it doesn't show up as a value.
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
                            .with_unit(sig::Unit::Celsius)
                            .with_characteristic(
                                server
                                    .table()
                                    .find_characteristic_by_value_handle(self.value.handle)
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

mod hap_temp_accessory {
    use super::hap_temp_sensor;
    use example_std::RuntimeConfig;
    use example_std::{ActualPairSupport, AddressType, make_address};

    use log::info;
    use trouble_host::prelude::*;

    use micro_hap::{AccessoryInterface, CharId, CharacteristicResponse, InterfaceError, PairCode};

    // Put the value in a mutexed arc, that way we can modify it freely.
    type SharedF32 = std::sync::Arc<std::sync::Mutex<f32>>;

    /// Struct to keep state for this specific accessory, with only a lightbulb.
    #[repr(C)]
    struct TemperatureAccessory {
        temperature_value: SharedF32,
    }

    /// Implement the accessory interface for the lightbulb.
    impl AccessoryInterface for TemperatureAccessory {
        async fn read_characteristic(
            &self,
            char_id: CharId,
        ) -> Result<impl Into<&[u8]>, InterfaceError> {
            info!("read on {:?}", char_id);
            info!(
                "hap_temp_sensor::CHAR_ID_TEMP_SENSOR_VALUE {:?}",
                hap_temp_sensor::CHAR_ID_TEMP_SENSOR_VALUE
            );
            if char_id == hap_temp_sensor::CHAR_ID_TEMP_SENSOR_VALUE {
                let value = *self.temperature_value.lock().unwrap();
                // TODO: Ugh this returns a borrow but I don't have a value to borrow out now that it's behind a mutex.
                // And this interface is not &mut, so I can also not retrieve it and write it to the local state.
                // Does this need to be a read into a byte slice..? or do we need to start returning heapless::Vec?
                // For now, lets just leak it such that I can make this example that increments the temperature
                // to test the broadcast notifications.
                let value_array = value.to_bits().to_le_bytes();
                let boxed_array = Box::new(value_array);
                let leaked = Box::leak(boxed_array);
                Ok(&leaked[0..4])
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

        // Create the gatt server.
        let name = "ThisIsALongName"; // There's _very_ few bytes left in the advertisement
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
        let f32ptr: SharedF32 = Default::default();
        let accessory_ptr = f32ptr.clone();
        let mut accessory = TemperatureAccessory {
            temperature_value: accessory_ptr,
        };
        // hap_context.add_service(&server.lightbulb).unwrap();
        hap_context
            .add_service(
                server
                    .temp_sensor
                    .create_hap_service(&server.server)
                    .unwrap(),
            )
            .unwrap();

        let category = 10; // sensors
        example_std::print_pair_qr(&pair_code, &setup_id, category as u8);

        println!("support: {support:?}");

        // a function that increments the temperature, and sends an control_sender event.
        /// This is a background task that is required to run forever alongside any other BLE tasks.
        async fn temperature_modification_task(
            temp_charid: CharId,
            f32_ptr: SharedF32,
            controller: &micro_hap::HapInterfaceSender<'_>,
        ) {
            loop {
                embassy_time::Timer::after_secs(15).await;
                let mut value = f32_ptr.lock().unwrap();
                *value += 1.0; // Increment the temperature.
                info!(
                    ">>>>>>>>>   Incrementing the temperature by 1, new value is {value}    <<<<<<<<"
                );
                controller.characteristic_changed(temp_charid).await; // send the notification.
            }
        }

        use embassy_futures::join::join;
        let _ = join(
            example_std::example_hap_loop(
                address,
                controller,
                &mut hap_context,
                &mut accessory,
                &mut support,
                &server,
                &server.as_hap(),
            ),
            temperature_modification_task(
                hap_temp_sensor::CHAR_ID_TEMP_SENSOR_VALUE,
                f32ptr,
                &control_sender,
            ),
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
    hap_temp_accessory::run(controller, config).await;
    Ok(())
}
