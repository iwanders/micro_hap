use bt_hci::controller::ExternalController;
//use trouble_example_apps::ble_bas_peripheral;
use trouble_linux_examples::Transport;

mod ble_bas_peripheral {
    use embassy_futures::join::join;
    use embassy_futures::select::select;
    use embassy_time::Timer;
    use log::{info, warn};
    use static_cell::StaticCell;
    use trouble_host::prelude::*;

    /// Max number of connections

    /// Max number of connections
    const CONNECTIONS_MAX: usize = 1;

    /// Max number of L2CAP channels.
    const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

    // GATT Server definition
    #[gatt_server]
    struct Server {
        //battery_service: BatteryService,
        //protocol_service: micro_hap::ProtocolInformationServiceFacade,
        accessory_information: micro_hap::ble::AccessoryInformationService,
        protocol: micro_hap::ble::ProtocolInformationService,
        pairing: micro_hap::ble::PairingService,
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

    /// Battery service
    // #[gatt_service(uuid = service::BATTERY)]
    // struct BatteryService {
    //     /// Battery Level
    //     #[descriptor(uuid = descriptors::VALID_RANGE, read, value = [0, 100])]
    //     #[descriptor(uuid = descriptors::MEASUREMENT_DESCRIPTION, name = "hello", read, value = "Battery Level")]
    //     #[characteristic(uuid = characteristic::BATTERY_LEVEL, read, notify, value = 10)]
    //     level: u8,
    //     #[characteristic(uuid = "408813df-5dd4-1f87-ec11-cdb001100000", write, read, notify)]
    //     status: bool,
    // }

    /// Run the BLE stack.
    pub async fn run<C>(controller: C)
    where
        C: Controller,
    {
        // Using a fixed "random" address can be useful for testing. In real scenarios, one would
        // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
        const ACTUAL_RANDOM_ADDRESS: bool = true;
        let address: Address = if ACTUAL_RANDOM_ADDRESS {
            // So it was caching my services, and it cost me a while to figure that out, make a true random address here
            // here.
            let mut rng = rand::rng();
            use rand::prelude::*;

            Address::random([
                0xff,
                0x8f,
                rng.random::<u8>(),
                0x05,
                rng.random::<u8>(),
                rng.random::<u8>() | 0b11, // ensure its considered a static device address.
            ])
        } else {
            Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff])
        };
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
        let value = micro_hap::AccessoryInformationStatic {
            name: "micro_hap",
            ..Default::default()
        };
        let _ = server
            .accessory_information
            .set_information_static(&server, &value)
            .unwrap();

        let buffer: &mut [u8] = {
            static STATE: StaticCell<[u8; 2048]> = StaticCell::new();
            STATE.init([0u8; 2048])
        };
        let mut hap_context = micro_hap::ble::HapPeripheralContext::new(buffer);

        let _ = join(ble_task(runner), async {
            loop {
                match advertise(name, &mut peripheral, &server).await {
                    Ok(conn) => {
                        // set up tasks when the connection is established to a central, so they don't run when no one is connected.
                        let a = gatt_events_task(&mut hap_context, &server, &conn);
                        let b = custom_task(&server, &conn, &stack);
                        // run until any task ends (usually because the connection has been closed),
                        // then return to advertising state.
                        select(a, b).await;
                    }
                    Err(e) => {
                        #[cfg(feature = "defmt")]
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
                #[cfg(feature = "defmt")]
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
                            /*
                            if event.handle() == level.handle {
                                info!(
                                    "[gatt] Write Event to Level Characteristic: {:?}",
                                    event.data()
                                );
                            }*/
                        }
                        GattEvent::Other(t) => {
                            let peek = t.payload();
                            if let Some(handle) = peek.handle() {
                                info!("[gatt] other event on handle: {handle}");
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
                        .process_gatt_event(&server.as_hap(), event)
                        .await?;
                    //let fallthrough_event = Some(event);

                    if let Some(event) = fallthrough_event {
                        match event.accept() {
                            Ok(reply) => reply.send().await,
                            Err(e) => warn!("[gatt] error sending response: {:?}", e),
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
    ) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
        const DEVICE_ADDRESS: [u8; 6] = [0xA8, 0x41, 0xf4, 0xd3, 0xd0, 0x4d];
        let adv_config = micro_hap::adv::AdvertisementConfig {
            device_id: micro_hap::adv::DeviceId([
                DEVICE_ADDRESS[0],
                DEVICE_ADDRESS[1],
                DEVICE_ADDRESS[2],
                DEVICE_ADDRESS[3],
                DEVICE_ADDRESS[4],
                DEVICE_ADDRESS[5],
            ]),
            accessory_category: 7,
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
        let advertiser = peripheral
            .advertise(
                &Default::default(),
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &advertiser_data[..len],
                    scan_data: &[],
                },
            )
            .await?;
        info!("[adv] advertising");
        let conn = advertiser.accept().await?.with_attribute_server(server)?;
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
