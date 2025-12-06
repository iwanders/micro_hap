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
//
// Disabling disconnected_events however, ~makes the sensor disappear~ show up as '--' in the room view
// from the apple home application, and it also does not register for broadcasts, is that expected behaviour because
// my phone isn't a home hub, which would (probably) fulfill the role of listening to broadcasts normally?
//
// Weirdly enough, even it doesn't show up, I can ask Siri for the temperature in my living room (the room of the sensor)
// and when asked, it does actually connect immediately, retrieves the temperature value and reports the correct value.
//
// Long pressing on the sensor shows 'This accessory requires an update before it can be used in the Home App, Try updating
// it using the manufacturer's app.'
//
// Wonder if this is https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAP.h#L470C14-L471
//
// * - This property must be set on at least one characteristic of an accessory to work around an issue
// *   in certain versions of the Home app that would otherwise claim that Additional Setup is required.
//
// Let's try adding a low battery characteristic that will have the disconnected events enabled. This ONLY works if you
// give it a range & step, but this can now actually show 'low battery' for the accessory.
//  Probably because min<max validation here: https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessoryValidation.c#L534
//
//
// Nope, that doesn't help, the moment I remove disconnected_events from anything it gives the warning that it needs
// an update..
//
// THere's a LOT of validation here: https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessoryValidation.c#L321
// But it's basically Disconnected > Broadcast > Event Notification
// So it doesn't rule out disabling disconnected events.
//
//
// I've tried reproducing it with the reference implementation, see:
// https://github.com/iwanders/HomeKitADK_program/tree/9f4512d4de91e1bb2d66ea0037a1ec3a8bcdf518/TemperatureSensor
// This changes the lightbulb to the temperature sensor to the best of my knowledge, the IP transport makes this into
// a working sensor, but the BLE side does display the 'this accessory needs an update', perhaps the disconnected events
// do just always need to be set to true if broadcasts are set... and perhaps the guidance is just to not advance the GSN
// and emit the broadcast message that causes a connection?
//
//
// There is a Broadcast Characteristic property that I've not yet explored, explored in f58dd6db151fbc922adb95fa6183cb69b9a2ff8a
// with the _builder flavour of this one, it doesn't result in the iPhone setting up the broadcast configuration.
// In addition to the 'this accessory needs an update' of course.
// So it is still not possible to get ios to report on the temperature just by doing a broadcast with the encrypted
// value in it :(

mod hap_temp_accessory {
    use example_std::RuntimeConfig;
    use example_std::temperature_sensor::TemperatureSensorService;
    use example_std::{ActualPairSupport, AddressType, make_address};

    use log::info;
    use trouble_host::prelude::*;

    use micro_hap::{
        AccessoryInterface, CharId, CharacteristicResponse, InterfaceError,
        IntoBytesForAccessoryInterface, PairCode,
    };

    // Put the value in a mutexed arc, that way we can modify it freely.
    type SharedF32 = std::sync::Arc<std::sync::Mutex<f32>>;

    /// Struct to keep state for this specific accessory, with only a lightbulb.
    #[repr(C)]
    struct TemperatureAccessory {
        temperature_value: SharedF32,
        low_battery: u8,
    }

    /// Implement the accessory interface for the lightbulb.
    impl AccessoryInterface for TemperatureAccessory {
        async fn read_characteristic<'a>(
            &mut self,
            char_id: CharId,
            output: &'a mut [u8],
        ) -> Result<&'a [u8], InterfaceError> {
            info!("read on {:?}", char_id);
            info!(
                "hap_temp_sensor::CHAR_ID_TEMP_SENSOR_VALUE {:?}",
                example_std::temperature_sensor::CHAR_ID_TEMP_SENSOR_VALUE
            );
            if char_id == example_std::temperature_sensor::CHAR_ID_TEMP_SENSOR_VALUE {
                let value = *self.temperature_value.lock().unwrap();

                value.read_characteristic_into(char_id, output)
            } else if char_id == example_std::temperature_sensor::CHAR_ID_TEMP_LOW_BATTERY {
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
        temp_sensor: TemperatureSensorService,
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
            low_battery: 0,
        };
        // hap_context.add_service(&server.lightbulb).unwrap();
        hap_context
            .add_service(server.temp_sensor.populate_support().unwrap())
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
            ),
            temperature_modification_task(
                example_std::temperature_sensor::CHAR_ID_TEMP_SENSOR_VALUE,
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
