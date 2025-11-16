use anyhow::Context;
use log::{error, info, warn};
use micro_hap::PairCode;
use micro_hap::{
    DeviceId, InterfaceError, PlatformSupport, SetupId, ble::broadcast::BleBroadcastParameters,
};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use trouble_host::prelude::*;

use micro_hap::pairing::{ED25519_LTSK, Pairing, PairingId};

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CommonArgs {
    /// File to load and store the pairing support data to.
    #[arg(short, long)]
    pub state: Option<PathBuf>,

    #[arg(short, long,action = clap::ArgAction::SetTrue)]
    pub wipe: bool,

    /// The bluetooth device number to use
    #[arg(short, long)]
    pub device: Option<u16>,
}
impl CommonArgs {
    pub fn to_runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            file_path: self.state.clone(),
            wipe: self.wipe.clone(),
        }
    }
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeConfig {
    pub file_path: Option<PathBuf>,
    pub wipe: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActualPairSupport {
    #[serde(skip)]
    pub runtime_config: RuntimeConfig,

    /// THe long term secret key
    pub ed_ltsk: [u8; micro_hap::pairing::ED25519_LTSK],
    /// Storage of all available paired devices.
    pub pairings:
        std::collections::HashMap<micro_hap::pairing::PairingId, micro_hap::pairing::Pairing>,
    /// The global state number, this advances on changes and is part of the broadcast.
    pub global_state_number: u16,
    /// The config number denotes the configuration, like the number of services etc.
    pub config_number: u8,
    /// Parameters for broadcast.
    ///
    /// TODO: I forgot how these are used >_<
    pub broadcast_parameters: BleBroadcastParameters,

    /// The device id for this accessory, must be constant across reboots.
    pub device_id: DeviceId,

    /// The setup id, constant across factory reset.
    pub setup_id: SetupId,
}
use std::fs;
use std::path::{Path, PathBuf};

// jskdlfjsdf
impl ActualPairSupport {
    pub fn new_from_config(runtime_config: RuntimeConfig) -> Result<Self, anyhow::Error> {
        if let Some(path) = &runtime_config.file_path {
            let mut z = Self::new_or_load(path)?;
            z.runtime_config = runtime_config;
            if z.runtime_config.wipe {
                let c = z.runtime_config;
                z = Default::default();
                z.runtime_config = c;

                z.save()?;
            }
            Ok(z)
        } else {
            Ok(Self {
                runtime_config,
                ..Default::default()
            })
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let p: &Path = path.as_ref();
        let contents = fs::read_to_string(&p)
            .with_context(|| format!("Failed to read instrs from {:?}", p))?;
        serde_json::from_str(&contents).map_err(|e| e.into())
    }
    pub fn new_or_load<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let p: &Path = path.as_ref();
        if p.exists() {
            Self::load_from_file(p)
        } else {
            Ok(Default::default())
        }
    }
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), anyhow::Error> {
        let p: &Path = path.as_ref();
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(&p, contents).with_context(|| format!("Failed to write to {:?}", p))
    }

    pub fn save(&self) -> Result<(), InterfaceError> {
        if let Some(p) = self.runtime_config.file_path.as_ref() {
            self.save_to_file(p)
                .map_err(|_e| InterfaceError::Custom("failing state save"))?
        }
        Ok(())
    }
}
impl Default for ActualPairSupport {
    fn default() -> Self {
        let mut ed_ltsk = [0; ED25519_LTSK];
        ed_ltsk.fill_with(rand::random);
        let mut device_id = DeviceId::default();
        device_id.0.fill_with(rand::random);
        device_id.0[0] |= 0b11;
        device_id.0[5] |= 0b11;
        let mut r_bytes = [0u8; 4];
        r_bytes.fill_with(rand::random);
        let setup_id = SetupId::from(&r_bytes);
        Self {
            runtime_config: Default::default(),
            ed_ltsk,
            pairings: Default::default(),
            global_state_number: 1,
            config_number: 1,
            broadcast_parameters: Default::default(),
            device_id,
            setup_id,
        }
    }
}
impl PlatformSupport for ActualPairSupport {
    /// Return the time of this platform
    fn get_time(&self) -> embassy_time::Instant {
        let dt = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        let micros = dt.as_micros();
        embassy_time::Instant::from_micros(micros as u64)
    }

    async fn get_ltsk(&self) -> [u8; ED25519_LTSK] {
        self.ed_ltsk
    }

    async fn fill_random(&mut self, buffer: &mut [u8]) -> () {
        buffer.fill_with(|| rand::rng().random::<u8>())
    }

    async fn store_pairing(&mut self, pairing: &Pairing) -> Result<(), InterfaceError> {
        error!("store_pairing {:?}", pairing);
        self.pairings.insert(pairing.id, *pairing);
        self.save()?;
        Ok(())
    }

    async fn get_pairing(&mut self, id: &PairingId) -> Result<Option<Pairing>, InterfaceError> {
        error!("get_pairing id {:?}", id);
        Ok(self.pairings.get(id).cloned())
    }
    async fn remove_pairing(&mut self, id: &PairingId) -> Result<(), InterfaceError> {
        error!("remove_pairing {:?}", id);
        self.pairings.remove(id);
        self.save()?;
        Ok(())
    }

    async fn is_paired(&mut self) -> Result<bool, InterfaceError> {
        Ok(!self.pairings.is_empty())
    }

    async fn get_global_state_number(&self) -> Result<u16, InterfaceError> {
        Ok(self.global_state_number)
    }
    /// Set the global state number, this is used by the BLE transport.
    async fn set_global_state_number(&mut self, value: u16) -> Result<(), InterfaceError> {
        self.global_state_number = value;
        self.save()?;
        Ok(())
    }

    async fn get_config_number(&self) -> Result<u8, InterfaceError> {
        Ok(self.config_number)
    }
    async fn set_config_number(&mut self, value: u8) -> Result<(), InterfaceError> {
        self.config_number = value;
        self.save()?;
        Ok(())
    }
    async fn get_ble_broadcast_parameters(
        &self,
    ) -> Result<micro_hap::ble::broadcast::BleBroadcastParameters, InterfaceError> {
        error!(
            "get_ble_broadcast_parameters {:?}",
            self.broadcast_parameters
        );
        Ok(self.broadcast_parameters)
    }
    async fn set_ble_broadcast_parameters(
        &mut self,
        params: &micro_hap::ble::broadcast::BleBroadcastParameters,
    ) -> Result<(), InterfaceError> {
        error!("set_ble_broadcast_parameters {:?}", params);
        self.broadcast_parameters = *params;
        self.save()?;
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub enum AddressType {
    #[default]
    Random,
    Fixed,
}

pub fn make_address(address_type: AddressType) -> Address {
    match address_type {
        AddressType::Random => Address::random([
            0xff,
            0x8f,
            rand::random::<u8>(),
            0x05,
            rand::random::<u8>(),
            rand::random::<u8>() | 0b11, // ensure its considered a static device address.
        ]),
        AddressType::Fixed => Address {
            kind: AddrKind::RANDOM,
            addr: BdAddr::new([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]),
        },
    }
}

pub fn print_pair_qr(pair_code: &PairCode, setup_id: &SetupId, category: u8) {
    println!("Qr code for: pair {pair_code:?}, setup id: {setup_id:?}");
    let pairstr = micro_hap::setup_payload(&pair_code, &setup_id, category.into());
    use qrcode::QrCode;
    use qrcode::render::unicode;

    let code = QrCode::new(pairstr.as_bytes()).unwrap();
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{image}");
}

use micro_hap::ble::HapPeripheralContext;
use micro_hap::ble::TimedWrite;
use static_cell::StaticCell;

type Mutex = embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
const CONTROL_CHANNEL_N: usize = 16;

// This is just a helper to reduce boilerplate in the examples!
pub fn example_context_factory(
    pair_code: PairCode,
    support: &ActualPairSupport,
    information_service: &micro_hap::ble::services::AccessoryInformationService,
    protocol: &micro_hap::ble::services::ProtocolInformationService,
    pairing: &micro_hap::ble::services::PairingService,
) -> (
    HapPeripheralContext<'static>,
    micro_hap::HapInterfaceSender<'static>,
) {
    // Create the pairing context.
    let pair_ctx = {
        static STATE: StaticCell<micro_hap::AccessoryContext> = StaticCell::new();
        STATE.init_with(micro_hap::AccessoryContext::default)
    };
    pair_ctx.info.assign_from(rand::random(), pair_code);

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
        static SLOT_STATE: StaticCell<[Option<TimedWrite>; TIMED_WRITE_SLOTS]> = StaticCell::new();
        SLOT_STATE.init([None; TIMED_WRITE_SLOTS])
    };

    // Setup the accessory information.
    let static_information = micro_hap::AccessoryInformationStatic {
        name: "micro_hap",
        device_id: support.device_id,
        setup_id: support.setup_id,
        ..Default::default()
    };
    pair_ctx.accessory = static_information;

    let control_channel = {
        static CONTROL_CHANNEL: StaticCell<micro_hap::HapControlChannel<Mutex, CONTROL_CHANNEL_N>> =
            StaticCell::new();
        CONTROL_CHANNEL.init(micro_hap::HapControlChannel::<Mutex, CONTROL_CHANNEL_N>::new())
    };
    let control_receiver = control_channel.get_receiver();
    let control_sender: micro_hap::HapInterfaceSender<'_> = control_channel.get_sender();
    // Then finally we can create the hap peripheral context.
    let mut ctx = micro_hap::ble::HapPeripheralContext::new(
        buffer,
        pair_ctx,
        timed_write_data,
        timed_write,
        information_service,
        protocol,
        pairing,
        control_receiver,
    )
    .unwrap();

    ctx.assign_static_data(&static_information);
    (ctx, control_sender)
}

use bt_hci::cmd::le::LeReadLocalSupportedFeatures;
use bt_hci::cmd::le::LeSetDataLength;
use bt_hci::controller::ControllerCmdSync;
use embassy_sync::blocking_mutex::raw::RawMutex;
/// Max number of connections
const CONNECTIONS_MAX: usize = 3;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 5; // Signal + att

use trouble_host::PacketPool;

pub async fn example_hap_loop<
    'values,
    'server,
    'c,
    C: Controller,
    M: RawMutex,
    const ATT_MAX: usize,
    const CCCD_MAX: usize,
    const CONN_MAX: usize,
>(
    address: Address,
    controller: C,
    ctx: &mut HapPeripheralContext<'c>,
    accessory: &mut impl micro_hap::AccessoryInterface,
    support: &mut impl PlatformSupport,
    server: &'server AttributeServer<'values, M, DefaultPacketPool, ATT_MAX, CCCD_MAX, CONN_MAX>,
    hap_services: &'server micro_hap::ble::HapServices<'_>,
) where
    C: Controller
        + ControllerCmdSync<LeReadLocalSupportedFeatures>
        + ControllerCmdSync<LeSetDataLength>,
{
    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();

    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        runner,
        ..
    } = stack.build();

    /// This is a background task that is required to run forever alongside any other BLE tasks.
    async fn ble_task<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) {
        loop {
            if let Err(e) = runner.run().await {
                panic!("[ble_task] error: {:?}", e);
            }
        }
    }

    use embassy_futures::join::join;
    let _ = join(ble_task(runner), async {
        loop {
            match ctx.advertise(accessory, support, &mut peripheral).await {
                Ok(conn) => {
                    // Increase the data length to 251 bytes per package, default is like 27.
                    conn.update_data_length(&stack, 251, 2120)
                        .await
                        .expect("Failed to set data length");
                    let z = server.get_cccd_table(&conn);
                    println!("ccd table: {z:?}");
                    let conn = conn
                        .with_attribute_server(server)
                        .expect("Failed to create attribute server");

                    // set up tasks when the connection is established to a central, so they don't run when no one is connected.
                    let a = ctx.gatt_events_task(accessory, support, &hap_services, &conn);

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
