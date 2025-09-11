#![allow(unused_variables)]
#![allow(dead_code)]
use bt_hci::controller::ExternalController;
//use trouble_example_apps::ble_bas_peripheral;
use bt_hci_linux::Transport;

mod ble_bas_peripheral {

    use example_std::{ActualPairSupport, AddressType, advertise, gatt_events_task, make_address};
    use rand::prelude::*;

    use embassy_futures::join::join;
    use embassy_futures::select::select;
    use embassy_time::Timer;
    use log::{error, info, warn};
    use static_cell::StaticCell;
    use trouble_host::prelude::*;
    use zerocopy::IntoBytes;

    use micro_hap::{
        AccessoryInterface, CharId, CharacteristicResponse, PairCode, PlatformSupport,
        ble::broadcast::BleBroadcastParameters,
    };

    struct LightBulbAccessory {
        name: HeaplessString<32>,
        bulb_on_state: bool,
    }
    impl AccessoryInterface for LightBulbAccessory {
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
                "AccessoryInterface to characterstic: 0x{:02?} data: {:02?}",
                char_id, data
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
        // let _ = server.accessory_information.unwrap();

        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L472
        let mut accessory = LightBulbAccessory {
            name: "Light Bulb".try_into().unwrap(),
            bulb_on_state: false,
        };
        // let mut accessory = micro_hap::NopAccessory;
        let pair_ctx = {
            static STATE: StaticCell<micro_hap::pairing::PairContext> = StaticCell::new();
            STATE.init_with(micro_hap::pairing::PairContext::default)
        };
        pair_ctx.accessory = static_information;
        // We need real commissioning for this, such that the verifier matches the setup code.
        pair_ctx.info.salt.fill_with(rand::random);
        let pair_code = PairCode::from_str("111-22-333").unwrap();
        pair_code.calculate_verifier(&pair_ctx.info.salt, &mut pair_ctx.info.verifier);

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
        info!(
            "table {:?}",
            server
                .table()
                .find_characteristic_by_value_handle::<[u8; 0]>(0x6a)
        );

        hap_context.print_handles();

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
                        let b = custom_task(&server, &conn, &stack);
                        // run until any task ends (usually because the connection has been closed),
                        // then return to advertising state.
                        let x = select(a, b).await;
                        match x {
                            embassy_futures::select::Either::First(a) => {
                                if let Err(e) = a {
                                    log::error!("Error occured in processing: {e:?}");
                                }
                            }
                            embassy_futures::select::Either::Second(_) => {}
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
                panic!("[ble_task] error: {:?}", e);
            }
        }
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
        //let mut tick: u8 = 0;
        //let level = server.battery_service.level;
        loop {
            //tick = tick.wrapping_add(1);
            //info!("[custom_task] notifying connection of tick {}", tick);
            // if level.notify(conn, &tick).await.is_err() {
            //     info!("[custom_task] error notifying connection");
            //     break;
            // };
            // read RSSI (Received Signal Strength Indicator) of the connection.
            // if let Ok(rssi) = conn.raw().rssi(stack).await {
            //     info!("[custom_task] RSSI: {:?}", rssi);
            // } else {
            //     info!("[custom_task] error getting RSSI");
            //     break;
            // };
            Timer::after_secs(2).await;
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
    ble_bas_peripheral::run(controller).await;
    Ok(())
}
