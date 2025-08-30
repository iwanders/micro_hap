#![allow(unused_variables)]
#![allow(dead_code)]
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
    const CONNECTIONS_MAX: usize = 3;

    /// Max number of L2CAP channels.
    const L2CAP_CHANNELS_MAX: usize = 4; // Signal + att

    // GATT Server definition
    #[gatt_server]
    struct Server {
        //battery_service: BatteryService,
        //protocol_service: micro_hap::ProtocolInformationServiceFacade,
        accessory_information: micro_hap::ble::AccessoryInformationService,
        protocol: micro_hap::ble::ProtocolInformationService,
        pairing: micro_hap::ble::PairingService,
        lightbulb: micro_hap::ble::LightbulbService,
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

    use micro_hap::pairing::{ED25519_LTSK, Pairing, PairingError, PairingId};
    #[derive(Debug, Clone, Default)]
    pub struct ActualPairSupport {
        pub ed_ltsk: [u8; micro_hap::pairing::ED25519_LTSK],
        pub pairings:
            std::collections::HashMap<micro_hap::pairing::PairingId, micro_hap::pairing::Pairing>,
    }
    impl micro_hap::pairing::PairSupport for ActualPairSupport {
        fn get_ltsk(&self) -> &[u8; ED25519_LTSK] {
            &self.ed_ltsk
        }

        fn get_random(&mut self) -> u8 {
            use rand::prelude::*;
            rand::rng().random::<u8>()
        }

        fn store_pairing(&mut self, pairing: &Pairing) -> Result<(), PairingError> {
            self.pairings.insert(pairing.id, *pairing);
            Ok(())
        }

        fn get_pairing(&mut self, id: &PairingId) -> Result<Option<&Pairing>, PairingError> {
            Ok(self.pairings.get(id))
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
    use bt_hci::cmd::le::LeReadLocalSupportedFeatures;
    use bt_hci::cmd::le::LeSetDataLength;
    use bt_hci::controller::ControllerCmdSync;
    const DEVICE_ADDRESS: [u8; 6] = [0xA8, 0x41, 0xf4, 0xd3, 0xd0, 0x4f];
    /// Run the BLE stack.
    pub async fn run<C>(controller: C)
    where
        C: Controller
            + ControllerCmdSync<LeReadLocalSupportedFeatures>
            + ControllerCmdSync<LeSetDataLength>,
    {
        // Using a fixed "random" address can be useful for testing. In real scenarios, one would
        // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
        const ACTUAL_RANDOM_ADDRESS: bool = true;
        const USE_DEVICE_ADDRESS: bool = false;
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
        } else if USE_DEVICE_ADDRESS {
            Address::random(DEVICE_ADDRESS)
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
        let static_information = micro_hap::AccessoryInformationStatic {
            name: "micro_hap",
            device_id: micro_hap::DeviceId([
                DEVICE_ADDRESS[0],
                DEVICE_ADDRESS[1],
                DEVICE_ADDRESS[2],
                DEVICE_ADDRESS[3],
                DEVICE_ADDRESS[4],
                DEVICE_ADDRESS[5],
            ]),
            ..Default::default()
        };
        let _ = server
            .accessory_information
            .set_information_static(&server, &static_information) // don't forget to also assign to the pair ctx.
            .unwrap();

        let accessory = micro_hap::NopAccessory;
        let pair_ctx = {
            static STATE: StaticCell<micro_hap::pairing::PairContext> = StaticCell::new();
            STATE.init_with(micro_hap::pairing::PairContext::default)
        };
        pair_ctx.accessory = static_information;
        // We need real commissioning for this, such that the verifier matches the setup code.
        pair_ctx.info.salt = [
            0xb3, 0x5b, 0x84, 0xc4, 0x04, 0x8b, 0x2d, 0x91, 0x35, 0xc4, 0xaf, 0xa3, 0x6d, 0xf6,
            0x2b, 0x29,
        ];
        pair_ctx.info.verifier = [
            0x84, 0x3e, 0x54, 0xd4, 0x61, 0xd8, 0xbd, 0xee, 0x78, 0xcf, 0x96, 0xb3, 0x30, 0x85,
            0x4c, 0xba, 0x90, 0x89, 0xb6, 0x8a, 0x10, 0x7c, 0x51, 0xd6, 0xde, 0x2f, 0xc3, 0xe2,
            0x9e, 0xdb, 0x55, 0xd0, 0xe1, 0xa3, 0xc3, 0x80, 0x6a, 0x1c, 0xae, 0xa3, 0x4d, 0x8b,
            0xbe, 0xae, 0x91, 0x51, 0xe1, 0x78, 0xf6, 0x48, 0x9e, 0xa5, 0x09, 0x73, 0x91, 0xcd,
            0xc4, 0xae, 0x12, 0xad, 0x09, 0x04, 0xdf, 0x44, 0x6d, 0xbe, 0x10, 0x15, 0x58, 0x02,
            0xb2, 0x1e, 0x9e, 0xff, 0xfe, 0xa4, 0x91, 0xf4, 0xb7, 0xa6, 0xb5, 0x12, 0xaa, 0x04,
            0xbc, 0xff, 0xe1, 0x86, 0xeb, 0x27, 0x6a, 0xef, 0xe5, 0xc3, 0x9f, 0x18, 0x6f, 0xe3,
            0x53, 0xc7, 0x56, 0x2b, 0x58, 0x4a, 0xa9, 0x16, 0x12, 0x79, 0x04, 0x81, 0x22, 0x2f,
            0xb8, 0xf1, 0xce, 0xb0, 0xb9, 0xda, 0x6b, 0x0e, 0x39, 0x24, 0xcc, 0xf2, 0x1d, 0xf3,
            0xfc, 0x47, 0x58, 0xce, 0x16, 0xd4, 0x08, 0xfe, 0x9d, 0x77, 0x20, 0xa3, 0x43, 0x3a,
            0x45, 0xb0, 0xd4, 0xfb, 0xab, 0x3b, 0xad, 0x36, 0x13, 0xe0, 0xb3, 0xc2, 0x2a, 0x6a,
            0x22, 0x5a, 0xc3, 0xd6, 0xdc, 0x49, 0x41, 0x0c, 0xd6, 0x48, 0x26, 0x8d, 0x07, 0xe8,
            0x57, 0x84, 0xa9, 0xda, 0xb0, 0xe0, 0x54, 0xed, 0x59, 0xe9, 0xcf, 0x03, 0x26, 0x1f,
            0x46, 0x3a, 0x41, 0x01, 0xa9, 0xf8, 0x44, 0x60, 0xc3, 0x5d, 0x9c, 0xb4, 0x66, 0x42,
            0xe7, 0x9f, 0x98, 0x7c, 0xbb, 0x0f, 0x08, 0x7e, 0x36, 0x04, 0x12, 0xcc, 0x7b, 0x4f,
            0x05, 0x44, 0x3b, 0xdd, 0x35, 0x3d, 0x44, 0x2a, 0x47, 0x1d, 0xe0, 0x3e, 0x03, 0xe2,
            0x51, 0xeb, 0x12, 0x96, 0xad, 0x08, 0x46, 0x07, 0xfd, 0xc4, 0x94, 0x9f, 0xc2, 0x59,
            0x9d, 0x0f, 0x79, 0x93, 0x51, 0x0b, 0xb5, 0xe8, 0xfd, 0xbc, 0xd4, 0x5a, 0xcf, 0xf0,
            0x08, 0xf7, 0xd6, 0x44, 0x6a, 0x63, 0x86, 0x88, 0x56, 0x13, 0xcf, 0x5c, 0x51, 0x68,
            0xfb, 0xa9, 0xb7, 0x63, 0x6a, 0xce, 0x64, 0xe1, 0xe1, 0x5a, 0x55, 0xea, 0xb1, 0x0c,
            0x0a, 0x82, 0xe9, 0x23, 0x61, 0x2f, 0x0d, 0xa9, 0x09, 0xb3, 0x48, 0xd4, 0xcf, 0x19,
            0x53, 0x81, 0x38, 0x5d, 0x74, 0x4d, 0xf8, 0x9d, 0x66, 0xaf, 0x52, 0xaf, 0xab, 0xef,
            0x22, 0xce, 0x6f, 0xbe, 0xbe, 0xa1, 0x40, 0x44, 0xd0, 0x01, 0xef, 0x9e, 0x8e, 0xed,
            0xd7, 0x99, 0xa0, 0x1f, 0x6f, 0x89, 0x48, 0x98, 0xa7, 0x61, 0x01, 0x18, 0x77, 0x58,
            0x82, 0xfe, 0x5f, 0x8f, 0x5e, 0xf6, 0xf3, 0x25, 0xb0, 0xda, 0xd2, 0xbf, 0xb0, 0x9e,
            0x08, 0x3b, 0x6b, 0x07, 0xff, 0x54, 0x0d, 0xc7, 0x45, 0xcf, 0x75, 0x51, 0x16, 0x5d,
            0x08, 0xe0, 0xea, 0x98, 0xc8, 0xd7, 0xab, 0x21, 0x4a, 0x08, 0x17, 0xd0, 0x97, 0x13,
            0x49, 0xd7, 0xe7, 0xbe, 0xf1, 0x8f,
        ];

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

        let _ = join(ble_task(runner), async {
            loop {
                match advertise(name, &mut peripheral, &server, &static_information).await {
                    Ok(conn) => {
                        // Increase the data length to 251 bytes per package, default is like 27.
                        conn.update_data_length(&stack, 251, 2120)
                            .await
                            .expect("Failed to set data length");
                        let conn = conn
                            .with_attribute_server(&server)
                            .expect("Failed to create attribute server");
                        // set up tasks when the connection is established to a central, so they don't run when no one is connected.
                        let a = gatt_events_task(&mut hap_context, &accessory, &server, &conn);
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
        accessory: &impl micro_hap::AccessoryInterface,
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

                    let mut support = ActualPairSupport {
                        ed_ltsk: [
                            182, 215, 245, 151, 120, 82, 56, 100, 73, 148, 49, 127, 131, 22, 235,
                            192, 207, 15, 80, 115, 241, 91, 203, 234, 46, 135, 77, 137, 203, 204,
                            159, 230,
                        ],
                        ..Default::default()
                    };

                    let fallthrough_event = hap_context
                        .process_gatt_event(&server.as_hap(), &mut support, accessory, event)
                        .await?;

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
        static_info: &micro_hap::AccessoryInformationStatic,
    ) -> Result<Connection<'values, DefaultPacketPool>, BleHostError<C::Error>> {
        // ) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
        let adv_config = micro_hap::adv::AdvertisementConfig {
            device_id: static_info.device_id,
            setup_id: static_info.setup_id,
            accessory_category: static_info.category,
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
        let params = AdvertisementParameters {
            interval_min: embassy_time::Duration::from_millis(1000),
            interval_max: embassy_time::Duration::from_millis(5000),
            ..Default::default()
        };
        let advertiser = peripheral
            .advertise(
                &params,
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &advertiser_data[..len],
                    scan_data: &[],
                },
            )
            .await?;
        info!("[adv] advertising");
        let conn = advertiser.accept().await?;
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
