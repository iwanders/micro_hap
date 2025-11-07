use anyhow::Context;
use log::{error, info, warn};
use micro_hap::{InterfaceError, PlatformSupport, ble::broadcast::BleBroadcastParameters};
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

    /// The bluetooth device number to use
    #[arg(short, long)]
    pub device: Option<u16>,
}
impl CommonArgs {
    pub fn to_runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            file_path: self.state.clone(),
        }
    }
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeConfig {
    pub file_path: Option<PathBuf>,
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
}
use std::fs;
use std::path::{Path, PathBuf};

impl ActualPairSupport {
    pub fn new_from_config(runtime_config: RuntimeConfig) -> Result<Self, anyhow::Error> {
        if let Some(path) = &runtime_config.file_path {
            let mut z = Self::new_or_load(path)?;
            z.runtime_config = runtime_config;
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
        Self {
            runtime_config: Default::default(),
            ed_ltsk,
            pairings: Default::default(),
            global_state_number: 1,
            config_number: 1,
            broadcast_parameters: Default::default(),
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
        error!("Storing {:?}", pairing);
        self.pairings.insert(pairing.id, *pairing);
        self.save()?;
        Ok(())
    }

    async fn get_pairing(&mut self, id: &PairingId) -> Result<Option<Pairing>, InterfaceError> {
        error!("retrieving id {:?}", id);
        Ok(self.pairings.get(id).cloned())
    }
    async fn remove_pairing(&mut self, id: &PairingId) -> Result<(), InterfaceError> {
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
        Ok(self.broadcast_parameters)
    }
    async fn set_ble_broadcast_parameters(
        &mut self,
        params: &micro_hap::ble::broadcast::BleBroadcastParameters,
    ) -> Result<(), InterfaceError> {
        self.broadcast_parameters = *params;
        self.save()?;
        Ok(())
    }
}

/// Create an advertiser to use to connect to a BLE Central, and wait for it to connect.
pub async fn advertise<'values, C: Controller>(
    name: &'values str,
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    static_info: &micro_hap::AccessoryInformationStatic,
) -> Result<Connection<'values, DefaultPacketPool>, BleHostError<C::Error>> {
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
        interval_min: embassy_time::Duration::from_millis(100),
        interval_max: embassy_time::Duration::from_millis(500),
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
