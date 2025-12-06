#![allow(unused_variables)]
#![allow(dead_code)]
use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;

mod hap_lightbulb {
    use example_std::RuntimeConfig;
    use example_std::{ActualPairSupport, AddressType, make_address};

    use log::info;
    use micro_hap::IntoBytesForAccessoryInterface;
    use micro_hap::ble::{FacadeDummyType, TimedWrite, services::LightbulbServiceHandles};
    use micro_hap::{AccessoryInterface, CharId, CharacteristicResponse, InterfaceError, PairCode};
    use trouble_host::prelude::*;
    /// Struct to keep state for this specific accessory, with only a lightbulb.
    struct LightBulbAccessory<'c> {
        name_a: HeaplessString<32>,
        name_b: HeaplessString<32>,
        bulb_state_a: bool,
        bulb_state_b: bool,
        handles_a: LightbulbServiceHandles,
        handles_b: LightbulbServiceHandles,
        control_sender: micro_hap::HapInterfaceSender<'c>,
    }

    /// Implement the accessory interface for the lightbulb.
    impl<'c> AccessoryInterface for LightBulbAccessory<'c> {
        async fn read_characteristic<'a>(
            &mut self,
            char_id: CharId,
            output: &'a mut [u8],
        ) -> Result<&'a [u8], InterfaceError> {
            if char_id == self.handles_a.name.hap {
                self.name_a.read_characteristic_into(char_id, output)
            } else if char_id == self.handles_b.name.hap {
                self.name_b.read_characteristic_into(char_id, output)
            } else if char_id == self.handles_a.on.hap {
                self.bulb_state_a.read_characteristic_into(char_id, output)
            } else if char_id == self.handles_b.on.hap {
                self.bulb_state_b.read_characteristic_into(char_id, output)
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

            if char_id != self.handles_a.on.hap && char_id != self.handles_b.on.hap {
                return Err(InterfaceError::CharacteristicUnknown(char_id));
            }

            println!("Before {}, {}", self.bulb_state_a, self.bulb_state_b);
            let (boolean_val, boolean_other) = if char_id == self.handles_a.on.hap {
                (&mut self.bulb_state_a, &mut self.bulb_state_b)
            } else {
                (&mut self.bulb_state_b, &mut self.bulb_state_a)
            };

            let (char_id_val, char_id_other) = if char_id == self.handles_a.on.hap {
                (self.handles_a.on.hap, self.handles_b.on.hap)
            } else {
                (self.handles_b.on.hap, self.handles_a.on.hap)
            };

            let value = data
                .get(0)
                .ok_or(InterfaceError::CharacteristicWriteInvalid)?;
            let val_as_bool = *value != 0;

            if val_as_bool {
                *boolean_other = false;
                self.control_sender
                    .characteristic_changed(char_id_other)
                    .await;
            }

            *boolean_val = val_as_bool;
            println!("After {}, {}", self.bulb_state_a, self.bulb_state_b);

            // CharacteristicResponse::Unmodified
            // // Should always be umodified, because we shouldn't send an indication if the value was changed because
            // of an active write from the controller.
            Ok(CharacteristicResponse::Unmodified)
        }
    }

    use bt_hci::cmd::le::LeReadLocalSupportedFeatures;
    use bt_hci::cmd::le::LeSetDataLength;
    use bt_hci::controller::ControllerCmdSync;
    use static_cell::StaticCell;

    const CCCD_MAX: usize = 32;
    /// Max number of connections
    const CONNECTIONS_MAX: usize = 3;
    /// Max number of L2CAP channels.
    const L2CAP_CHANNELS_MAX: usize = 5; // Signal + att
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

    pub async fn run<C>(controller: C, runtime_config: RuntimeConfig)
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

        let mut attribute_buffer: &mut [u8] = {
            const ATTRIBUTE_BUFFER_SIZE: usize = 1024;
            static STATE: StaticCell<[u8; ATTRIBUTE_BUFFER_SIZE]> = StaticCell::new();
            STATE.init([0u8; ATTRIBUTE_BUFFER_SIZE])
        };

        const ATTRIBUTE_TABLE_SIZE: usize = 1024;
        let mut attribute_table = trouble_host::attribute::AttributeTable::<
            CriticalSectionRawMutex,
            ATTRIBUTE_TABLE_SIZE,
        >::new();

        // Create the gatt server.
        let name = "Z"; // There's _very_ few bytes left in the advertisement
        info!("Starting advertising and GATT service");
        let gap_config = GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
        });
        //let server = Server::new_with_config().unwrap();
        gap_config.build(&mut attribute_table).unwrap();
        // This is the body of new_with_config

        let (remaining_buffer, information_handles) =
            micro_hap::ble::services::AccessoryInformationService::add_to_attribute_table(
                &mut attribute_table,
                &mut attribute_buffer,
            )
            .unwrap();
        let (remaining_buffer, protocol_handles) =
            micro_hap::ble::services::ProtocolInformationService::add_to_attribute_table(
                &mut attribute_table,
                remaining_buffer,
            )
            .unwrap();
        let (remaining_buffer, pairing_handles) =
            micro_hap::ble::services::PairingService::add_to_attribute_table(
                &mut attribute_table,
                remaining_buffer,
            )
            .unwrap();
        let (remaining_buffer, handles_a) =
            micro_hap::ble::services::LightbulbService::add_to_attribute_table(
                &mut attribute_table,
                remaining_buffer,
                0x30,
            )
            .unwrap();
        let (remaining_buffer, handles_b) =
            micro_hap::ble::services::LightbulbService::add_to_attribute_table(
                &mut attribute_table,
                remaining_buffer,
                0x40,
            )
            .unwrap();

        let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
        let Host {
            mut peripheral,
            runner,
            ..
        } = stack.build();

        let server =
            trouble_host::prelude::AttributeServer::<_, _, _, CCCD_MAX, CONNECTIONS_MAX>::new(
                attribute_table,
            );
        // Create the pairing context.
        let pair_ctx = {
            static STATE: StaticCell<micro_hap::AccessoryContext> = StaticCell::new();
            STATE.init_with(micro_hap::AccessoryContext::default)
        };
        let pair_code = PairCode::from_str("111-22-333").unwrap();
        pair_ctx.info.assign_from(rand::random(), pair_code);

        // Create the buffer for hap messages in the gatt server.
        let out_buffer: &mut [u8] = {
            static STATE: StaticCell<[u8; 2048]> = StaticCell::new();
            STATE.init([0u8; 2048])
        };
        let in_buffer: &mut [u8] = {
            static STATE: StaticCell<[u8; 1024]> = StaticCell::new();
            STATE.init([0u8; 1024])
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

        // And the platform support.
        let mut support =
            ActualPairSupport::new_from_config(runtime_config).expect("failed to load file");

        let setup_id = support.setup_id;
        let pair_code = PairCode::from_str("111-22-333").unwrap();
        let hap_category = 8;
        example_std::print_pair_qr(&pair_code, &setup_id, hap_category);

        let control_channel = {
            type Mutex = embassy_sync::blocking_mutex::raw::NoopRawMutex;
            const CONTROL_CHANNEL_N: usize = 16;

            static CONTROL_CHANNEL: StaticCell<
                micro_hap::HapControlChannel<Mutex, CONTROL_CHANNEL_N>,
            > = StaticCell::new();
            CONTROL_CHANNEL.init(micro_hap::HapControlChannel::<Mutex, CONTROL_CHANNEL_N>::new())
        };
        let control_receiver = control_channel.get_receiver();
        let control_sender: micro_hap::HapInterfaceSender<'_> = control_channel.get_sender();

        // Setup the accessory information.
        let static_information = micro_hap::AccessoryInformationStatic {
            name: "micro_hap",
            device_id: support.device_id,
            setup_id: support.setup_id,
            ..Default::default()
        };
        pair_ctx.accessory = static_information;

        let setup_id = support.setup_id;

        // Setup the accessory now.
        let mut accessory = LightBulbAccessory {
            name_a: "Bulb A".try_into().unwrap(),
            name_b: "Bulb B".try_into().unwrap(),
            bulb_state_a: false,
            bulb_state_b: false,
            handles_a,
            handles_b,
            control_sender,
        };

        // Then finally we can create the hap peripheral context.
        let mut hap_context = micro_hap::ble::HapPeripheralContext::new(
            out_buffer,
            in_buffer,
            pair_ctx,
            timed_write_data,
            timed_write,
            control_receiver,
        )
        .unwrap();
        hap_context
            .add_service(information_handles.to_service().unwrap())
            .unwrap();
        hap_context
            .add_service(protocol_handles.to_service().unwrap())
            .unwrap();
        hap_context
            .add_service(pairing_handles.to_service().unwrap())
            .unwrap();
        hap_context
            .add_service(handles_a.to_service().unwrap())
            .unwrap();
        hap_context
            .add_service(handles_b.to_service().unwrap())
            .unwrap();
        hap_context.assign_static_data(&static_information);

        use embassy_futures::join::join;
        let _ = join(
            hap_context.service(&mut accessory, &mut support, &server, &mut peripheral),
            ble_task(runner),
        )
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
