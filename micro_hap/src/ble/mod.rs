use crate::AccessoryInformationStatic;
use crate::{characteristic, descriptor, service};
use trouble_host::prelude::*;
mod util;
use embassy_sync::blocking_mutex::raw::RawMutex;
use util::GattString;
mod pdu;
use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

// Todo, we should probably detach this completely from the HapServices struct
// because it would be really nice if we can keep properties per service, characteristic and property.

#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct CharId(pub u16);

#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct SvcId(pub u16);

#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct TId(pub u8);

#[derive(Debug, Copy, Clone)]
pub enum HapBleError {
    UnexpectedDataLength { expected: usize, actual: usize },
    UnexpectedRequest,
    InvalidValue,
    BufferOverrun,
}

impl From<HapBleError> for trouble_host::Error {
    fn from(e: HapBleError) -> trouble_host::Error {
        match e {
            HapBleError::UnexpectedDataLength { expected, actual } => {
                trouble_host::Error::UnexpectedDataLength { expected, actual }
            }
            HapBleError::UnexpectedRequest => trouble_host::Error::Other,
            HapBleError::InvalidValue => trouble_host::Error::InvalidValue,
            HapBleError::BufferOverrun => trouble_host::Error::OutOfMemory,
        }
    }
}

#[gatt_service(uuid = service::ACCESSORY_INFORMATION)]
pub struct AccessoryInformationService {
    /// Describes hardware revision string; "<major>.<minor>.<revision>"
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x01, 0x01])]
    #[characteristic(uuid=characteristic::HARDWARE_REVISION, read, write)]
    pub hardware_revision: GattString<16>,

    /// Manufacturer serial number, length must be greater than one.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x01, 0x02])]
    #[characteristic(uuid=characteristic::SERIAL_NUMBER, read, write)]
    pub serial_number: GattString<64>,

    /// Service instance ID, must be a 16 bit unsigned integer.
    // Service instance id for accessory information must be 1, 0 is invalid.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x01, 0x03])]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 1)]
    pub service_instance: u16,

    /// Manufacturer specific model, length must be greater than one.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x01, 0x04])]
    #[characteristic(uuid=characteristic::MODEL, read, write)]
    pub model: GattString<64>,

    /// Name for the device.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x01, 0x05])]
    #[characteristic(uuid=characteristic::NAME, read, write)]
    pub name: GattString<64>,

    /// Manufacturer name that created the device.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x01, 0x06])]
    #[characteristic(uuid=characteristic::MANUFACTURER, read, write)]
    pub manufacturer: GattString<64>,

    /// Firmware revision string; "<major>.<minor>.<revision>"
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x01, 0x07])]
    #[characteristic(uuid=characteristic::FIRMWARE_REVISION, read, write)]
    pub firmware_revision: GattString<16>,

    /// Identify routine, triggers something, it does not contain data.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x01, 0x08])]
    #[characteristic(uuid=characteristic::IDENTIFY, read, write)]
    pub identify: bool,
}

impl AccessoryInformationService {
    pub fn set_information_static<
        M: RawMutex,
        P: PacketPool,
        const AT: usize,
        const CT: usize,
        const CN: usize,
    >(
        &self,
        server: &AttributeServer<'_, M, P, AT, CT, CN>,
        value: &AccessoryInformationStatic,
    ) -> Result<(), Error> {
        self.hardware_revision.set(
            server,
            &util::GattString::try_from(value.hardware_revision)
                .map_err(|_| Error::InsufficientSpace)?,
        )?;
        self.serial_number.set(
            server,
            &util::GattString::try_from(value.serial_number)
                .map_err(|_| Error::InsufficientSpace)?,
        )?;
        self.model.set(
            server,
            &util::GattString::try_from(value.model).map_err(|_| Error::InsufficientSpace)?,
        )?;
        self.name.set(
            server,
            &util::GattString::try_from(value.name).map_err(|_| Error::InsufficientSpace)?,
        )?;
        self.manufacturer.set(
            server,
            &util::GattString::try_from(value.manufacturer)
                .map_err(|_| Error::InsufficientSpace)?,
        )?;
        self.firmware_revision.set(
            server,
            &util::GattString::try_from(value.firmware_revision)
                .map_err(|_| Error::InsufficientSpace)?,
        )?;
        Ok(())
    }
}

type FacadeDummyType = [u8; 0];

#[gatt_service(uuid = service::PROTOCOL_INFORMATION)]
pub struct ProtocolInformationService {
    /// Service instance ID, must be a 16 bit unsigned integer.
    // May not be 1, value 1 is for accessory information.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x02, 0x01])]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x02)]
    service_instance: u16,

    /// Service signature, only two bytes.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x02, 0x02])]
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
    service_signature: FacadeDummyType,

    /// Version string.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x02, 0x03])]
    #[characteristic(uuid=characteristic::VERSION, value="2.2.0".try_into().unwrap(), read)]
    version: GattString<16>,
}

#[gatt_service(uuid = service::PAIRING)]
pub struct PairingService {
    /// Service instance ID, must be a 16 bit unsigned integer.
    // May not be 1, value 1 is for accessory information.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x03, 0x01])]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 3)]
    service_instance: u16,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x03, 0x02])]
    #[characteristic(uuid=characteristic::PAIRING_PAIR_SETUP, read, write)]
    pair_setup: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x03, 0x03])]
    #[characteristic(uuid=characteristic::PAIRING_PAIR_VERIFY, read, write)]
    pair_verify: FacadeDummyType,

    // Software authentication is 0x2.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x03, 0x04])]
    #[characteristic(uuid=characteristic::PAIRING_FEATURES, read, value=0x02)]
    features: u8,

    // Paired read and write only.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x03, 0x05])]
    #[characteristic(uuid=characteristic::PAIRING_PAIRINGS, read, write)]
    pairings: FacadeDummyType,
}

#[bitfield(u16)]
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable)]
pub struct ServiceProperties {
    #[bits(1)]
    primary: bool,
    #[bits(1)]
    hidden: bool,
    #[bits(1)]
    configurable: bool,

    #[bits(13)]
    __: u16,
}

/// Simple helper struct that's used to capture input to the gatt event handler.
pub struct HapServices<'a> {
    pub information: &'a AccessoryInformationService,
    pub protocol: &'a ProtocolInformationService,
    pub pairing: &'a PairingService,
}

use pdu::{BleTLVType, BodyBuilder, ParsePdu, WriteIntoLength};

struct Reply {
    payload: BufferResponse,
    handle: u16,
}

pub struct HapPeripheralContext {
    protocol_service_properties: ServiceProperties,
    buffer: &'static mut [u8],
    prepared_reply: Option<Reply>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct BufferResponse(pub usize);

impl HapPeripheralContext {
    pub fn new(buffer: &'static mut [u8]) -> Self {
        Self {
            protocol_service_properties: Default::default(),
            buffer,
            prepared_reply: None,
        }
    }

    pub async fn service_signature_request(
        &mut self,
        req: &pdu::ServiceSignatureReadRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L249

        let resp = req.header.to_success();

        let len = resp.write_into_length(&mut self.buffer)?;
        // WHat is the actual output?
        // Something something TLV...
        //
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEService%2BSignature.c#L10
        // which then goes into
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEPDU%2BTLV.c#L600
        // and linked services in
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEPDU%2BTLV.c#L640

        // NONCOMPLIANCE: Ignoring linked services.
        // I have no idea what a linked service is yet... so lets ehm, just ignore that?
        // read was:
        // 00 06 93 10 00
        // Reply was
        //    02 93 00 06 00 0f 02 04 00 10 00
        // So Payload is 6 body length, then 0f 02 04 and no linked svc.
        // What does this service property do!?
        //   [2, 81, 0, 6, 0, f, 2, 4, 0, 10, 0]
        let len = BodyBuilder::new_at(&mut self.buffer, len)
            .add_u16(
                BleTLVType::HAPServiceProperties,
                ServiceProperties::new().with_configurable(true).0,
            )
            .add_u16s(BleTLVType::HAPLinkedServices, &[])
            .end();

        Ok(BufferResponse(len))
    }
    pub async fn characteristic_signature_request(
        &mut self,
        req: &pdu::CharacteristicSignatureReadRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L289

        // NONCOMPLIANCE: should drop connection when requesting characteristics on the pairing characteristics.

        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLECharacteristic%2BSignature.c#L10
        let reply = req.header.to_success();
        let len = reply.write_into_length(&mut self.buffer)?;
        let len = BodyBuilder::new_at(&mut self.buffer, len)
            .add_u16(
                BleTLVType::HAPServiceProperties,
                ServiceProperties::new().with_configurable(true).0,
            )
            .add_u16s(BleTLVType::HAPLinkedServices, &[])
            .end();

        Ok(BufferResponse(len))
    }

    fn get_response(&self, v: BufferResponse) -> &[u8] {
        &self.buffer[0..v.0]
    }

    pub async fn process_gatt_event<'stack, 'server, 'hap, P: PacketPool>(
        &mut self,
        hap: &HapServices<'hap>,
        event: trouble_host::gatt::GattEvent<'stack, 'server, P>,
    ) -> Result<Option<trouble_host::gatt::GattEvent<'stack, 'server, P>>, trouble_host::Error>
    {
        // we seem to miss 'read by type' requests on handlex 0x0010 - 0x0012
        match event {
            GattEvent::Read(event) => {
                if event.handle() == hap.information.hardware_revision.handle {
                    warn!("Reading information.hardware_revision");
                } else if event.handle() == hap.information.serial_number.handle {
                    warn!("Reading information.serial_number ");
                } else if event.handle() == hap.information.model.handle {
                    warn!("Reading information.model ");
                } else if event.handle() == hap.information.name.handle {
                    warn!("Reading information.name ");
                } else if event.handle() == hap.information.manufacturer.handle {
                    warn!("Reading information.manufacturer ");
                } else if event.handle() == hap.information.firmware_revision.handle {
                    warn!("Reading information.firmware_revision ");
                } else if event.handle() == hap.information.service_instance.handle {
                    warn!("Reading information.service_instance ");
                }

                if event.handle() == hap.protocol.service_instance.handle {
                    warn!("Reading protocol.service_instance");
                } else if event.handle() == hap.protocol.service_signature.handle {
                    warn!("Reading protocol.service_signature ");
                    if self.prepared_reply.as_ref().map(|e| e.handle) == Some(event.handle()) {
                        let reply = self.prepared_reply.take().unwrap();

                        let reply = trouble_host::att::AttRsp::Read {
                            data: &self.get_response(reply.payload),
                        };
                        warn!("Replying with: {:x?}", reply);
                        // We see this print,
                        //
                        // but nothing ever ends up in the aether
                        event.into_payload().reply(reply).await?;
                        return Ok(None);
                    }
                } else if event.handle() == hap.protocol.version.handle {
                    warn!("Reading protocol.version ");
                }

                if event.handle() == hap.pairing.service_instance.handle {
                    warn!("Reading pairing.service_instance");
                } else if event.handle() == hap.pairing.pair_setup.handle {
                    warn!("Reading pairing.pair_setup ");
                } else if event.handle() == hap.pairing.pair_verify.handle {
                    warn!("Reading pairing.pair_verify ");
                } else if event.handle() == hap.pairing.features.handle {
                    warn!("Reading pairing.features ");
                } else if event.handle() == hap.pairing.pairings.handle {
                    warn!("Reading pairing.pairings ");
                }

                Ok(Some(GattEvent::Read(event)))
            }
            GattEvent::Write(event) => {
                if event.handle() == hap.information.hardware_revision.handle {
                    warn!("Writing information.hardware_revision {:?}", event.data());
                } else if event.handle() == hap.information.serial_number.handle {
                    warn!("Writing information.serial_number  {:?}", event.data());
                } else if event.handle() == hap.information.model.handle {
                    warn!("Writing information.model  {:?}", event.data());
                } else if event.handle() == hap.information.name.handle {
                    warn!("Writing information.name  {:?}", event.data());
                } else if event.handle() == hap.information.manufacturer.handle {
                    warn!("Writing information.manufacturer  {:?}", event.data());
                } else if event.handle() == hap.information.firmware_revision.handle {
                    warn!("Writing information.firmware_revision  {:?}", event.data());
                } else if event.handle() == hap.information.service_instance.handle {
                    warn!("Writing information.service_instance  {:?}", event.data());
                }

                if event.handle() == hap.protocol.service_instance.handle {
                    warn!("Writing protocol.service_instance  {:?}", event.data());
                } else if event.handle() == hap.protocol.service_signature.handle {
                    warn!("Writing protocol.service_signature  {:x?}", event.data());
                    // Writing protocol.service_signature  [0, 6, 107, 2, 0]
                    // Yes, that matches the hap service signature read

                    let header = pdu::RequestHeader::parse_pdu(event.data())?;
                    match header.opcode {
                        pdu::OpCode::CharacteristicSignatureRead => {
                            let req = pdu::ServiceSignatureReadRequest::parse_pdu(event.data())?;
                            let resp = self.service_signature_request(&req).await?;
                            self.prepared_reply = Some(Reply {
                                payload: resp,
                                handle: hap.protocol.service_signature.handle,
                            });

                            let reply = trouble_host::att::AttRsp::Write;
                            event.into_payload().reply(reply).await?;
                            return Ok(None);
                        }
                        pdu::OpCode::CharacteristicSignatureRead => {
                            // second one is on [0, 1, 44, 2, 2]
                            let char_sign_req =
                                pdu::CharacteristicSignatureReadRequest::parse_pdu(event.data())?;
                            warn!("Got req: {:?}", char_sign_req);
                            todo!();
                        }
                        _ => return Err(HapBleError::UnexpectedRequest.into()),
                    }

                    // Maybe the write request has to go through and it is followed by a read?
                } else if event.handle() == hap.protocol.version.handle {
                    warn!("Writing protocol.version  {:?}", event.data());
                }

                if event.handle() == hap.pairing.service_instance.handle {
                    warn!("Writing pairing.service_instance");
                } else if event.handle() == hap.pairing.pair_setup.handle {
                    warn!("Writing pairing.pair_setup  {:?}", event.data());
                } else if event.handle() == hap.pairing.pair_verify.handle {
                    warn!("Writing pairing.pair_verify  {:?}", event.data());
                } else if event.handle() == hap.pairing.features.handle {
                    warn!("Writing pairing.features  {:?}", event.data());
                } else if event.handle() == hap.pairing.pairings.handle {
                    warn!("Writing pairing.pairings  {:?}", event.data());
                }
                Ok(Some(GattEvent::Write(event)))
            }
            remainder => Ok(Some(remainder)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use static_cell::StaticCell;
    fn init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::max())
            .try_init();
    }
    #[gatt_server]
    struct Server {
        accessory_information: AccessoryInformationService,
        protocol: ProtocolInformationService,
        pairing: PairingService,
    }
    impl Server<'_> {
        pub fn as_hap(&self) -> HapServices<'_> {
            HapServices {
                information: &self.accessory_information,
                protocol: &self.protocol,
                pairing: &self.pairing,
            }
        }
    }

    #[tokio::test]
    async fn test_service_requests() -> Result<(), HapBleError> {
        init();
        let name = "micro_hap";
        let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
        }))
        .unwrap();

        // Setup the accessory information.
        let value = crate::AccessoryInformationStatic {
            name,
            ..Default::default()
        };
        let _ = server
            .accessory_information
            .set_information_static(&server, &value)
            .unwrap();

        let hap = server.as_hap();
        let _ = hap;

        let buffer: &mut [u8] = {
            static STATE: StaticCell<[u8; 2048]> = StaticCell::new();
            STATE.init([0u8; 2048])
        };
        let mut ctx = HapPeripheralContext::new(buffer);

        let service_signature_req = [0, 6, 0x3a, 2, 0];
        let resp = ctx
            .service_signature_request(&service_signature_req)
            .await?;
        let reply = ctx.get_response(resp);
        warn!("reply: {:?}", reply);

        let expected_req = [2, 0x3a, 0, 6, 0, 0xf, 2, 4, 0, 0x10, 0];
        assert_eq!(reply, expected_req);

        // and then it sends... which we have no clue what it is yet.
        let payload = [0x00, 0x01, 0xae, 0x02, 0x02];
        // [micro_hap::ble] Writing protocol.service_signature  [0, 1, ae, 2, 2]
        let resp = ctx.service_signature_request(&payload).await?;
        // Oh... that's a characteristic signature read request.
        // we need the PDU types, and interpret based on that.

        Ok(())
    }
}
