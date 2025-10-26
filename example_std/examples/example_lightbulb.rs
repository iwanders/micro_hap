#![allow(unused_variables)]
#![allow(dead_code)]
use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;

mod hap_lightbulb {
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

    /// Max number of connections
    const CONNECTIONS_MAX: usize = 3;

    /// Max number of L2CAP channels.
    const L2CAP_CHANNELS_MAX: usize = 5; // Signal + att

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
            appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
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
            ..Default::default()
        };

        // Create this specific accessory.
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L472
        let mut accessory = LightBulbAccessory {
            name: "Light Bulb".try_into().unwrap(),
            bulb_on_state: false,
        };

        // Create the pairing context.
        let pair_ctx = {
            static STATE: StaticCell<micro_hap::pairing::PairContext> = StaticCell::new();
            STATE.init_with(micro_hap::pairing::PairContext::default)
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
        hap_context.add_service(&server.lightbulb).unwrap();

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
    hap_lightbulb::run(controller).await;
    Ok(())
}
