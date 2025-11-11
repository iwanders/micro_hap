#![allow(unused_variables)]
#![allow(dead_code)]
use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;

mod hap_lightbulb {
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
    struct LightBulbAccessory {
        name: HeaplessString<32>,
        bulb_on_state: bool,
    }

    /// Implement the accessory interface for the lightbulb.
    impl AccessoryInterface for LightBulbAccessory {
        async fn read_characteristic(
            &self,
            char_id: CharId,
        ) -> Result<impl Into<&[u8]>, InterfaceError> {
            if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_NAME {
                Ok(self.name.as_bytes())
            } else if char_id == micro_hap::ble::CHAR_ID_LIGHTBULB_ON {
                Ok(self.bulb_on_state.as_bytes())
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
                info!("\nSet bulb to: {:?}\n", self.bulb_on_state);
                Ok(response)
            } else {
                Err(InterfaceError::CharacteristicUnknown(char_id))
            }
        }
    }

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
            name: "Light Bulb".try_into().unwrap(),
            bulb_on_state: false,
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

        hap_context.add_service(&server.lightbulb).unwrap();
        let hap_category = 8;
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
    hap_lightbulb::run(controller, config).await;
    Ok(())
}
