use log::{error, info, warn};
use micro_hap::{PlatformSupport, ble::broadcast::BleBroadcastParameters};
use rand::prelude::*;
use trouble_host::prelude::*;

use micro_hap::pairing::{ED25519_LTSK, Pairing, PairingError, PairingId};
#[derive(Debug, Clone)]
pub struct ActualPairSupport {
    pub ed_ltsk: [u8; micro_hap::pairing::ED25519_LTSK],
    pub pairings:
        std::collections::HashMap<micro_hap::pairing::PairingId, micro_hap::pairing::Pairing>,
    pub global_state_number: u16,
    pub config_number: u16,
    pub broadcast_parameters: BleBroadcastParameters,
}
impl Default for ActualPairSupport {
    fn default() -> Self {
        let mut ed_ltsk = [0; ED25519_LTSK];
        ed_ltsk.fill_with(rand::random);
        Self {
            ed_ltsk,
            pairings: Default::default(),
            global_state_number: 1,
            config_number: 1,
            broadcast_parameters: Default::default(),
        }
    }
}
impl PlatformSupport for ActualPairSupport {
    async fn get_ltsk(&self) -> [u8; ED25519_LTSK] {
        self.ed_ltsk
    }

    async fn fill_random(&mut self, buffer: &mut [u8]) -> () {
        buffer.fill_with(|| rand::rng().random::<u8>())
    }

    fn store_pairing(&mut self, pairing: &Pairing) -> Result<(), PairingError> {
        error!("Storing {:?}", pairing);
        self.pairings.insert(pairing.id, *pairing);
        Ok(())
    }

    fn get_pairing(&mut self, id: &PairingId) -> Result<Option<&Pairing>, PairingError> {
        error!("retrieving id {:?}", id);
        Ok(self.pairings.get(id))
    }

    fn get_global_state_number(&self) -> Result<u16, PairingError> {
        Ok(self.global_state_number)
    }
    /// Set the global state number, this is used by the BLE transport.
    fn set_global_state_number(&mut self, value: u16) -> Result<(), PairingError> {
        self.global_state_number = value;
        Ok(())
    }
    fn get_config_number(&self) -> Result<u16, PairingError> {
        Ok(self.config_number)
    }
    fn set_config_number(&mut self, value: u16) -> Result<(), PairingError> {
        self.config_number = value;
        Ok(())
    }
    fn get_ble_broadcast_parameters(
        &self,
    ) -> Result<micro_hap::ble::broadcast::BleBroadcastParameters, PairingError> {
        Ok(self.broadcast_parameters)
    }
    fn set_ble_broadcast_parameters(
        &mut self,
        params: &micro_hap::ble::broadcast::BleBroadcastParameters,
    ) -> Result<(), PairingError> {
        self.broadcast_parameters = *params;
        Ok(())
    }
}

/// Stream Events until the connection closes.
///
/// This function will handle the GATT events and process them.
/// This is how we interact with read and write requests.
pub async fn gatt_events_task<P: PacketPool>(
    hap_context: &mut micro_hap::ble::HapPeripheralContext,
    accessory: &mut impl micro_hap::AccessoryInterface,
    support: &mut impl PlatformSupport,
    hap_services: &micro_hap::ble::HapServices<'_>,
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
                        info!(
                            "[gatt] Write Event to Level Characteristic: {:?}",
                            event.data()
                        );
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
                    .process_gatt_event(hap_services, support, accessory, event)
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
