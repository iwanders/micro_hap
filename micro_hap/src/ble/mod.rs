use crate::AccessoryInformationStatic;
use crate::{characteristic, descriptor, service};
use trouble_host::prelude::*;
mod util;
use embassy_sync::blocking_mutex::raw::RawMutex;
use util::GattString;
mod pdu;
use crate::{BleProperties, ServiceProperties};
use bitfield_struct::bitfield;

use crate::{CharId, SvcId};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

// Todo, we should probably detach this completely from the HapServices struct
// because it would be really nice if we can keep properties per service, characteristic and property.
//

// add a lightbulb service such that we have at least one service.
// accessory information service must have instance id 1.
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAP.h#L3245-L3249
// Okay, the disconnect doesn't happen because of fragmentation now, the response on the first characteristic read
// is actually in a single packet.

// Maybe the instance ids and the like need to be monotonically increasing? Which is not explicitly stated.

pub mod sig;

#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct TId(pub u8);

#[derive(Debug, Copy, Clone)]
pub enum HapBleError {
    UnexpectedDataLength {
        expected: usize,
        actual: usize,
    },
    UnexpectedRequest,
    InvalidValue,
    /// Runtime buffer overrun.
    BufferOverrun,
    /// Overrun on allocation space
    AllocationOverrun,
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
            HapBleError::AllocationOverrun => trouble_host::Error::OutOfMemory,
        }
    }
}

// MUST have an instance id of 1
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
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAP.h#L3245-L3249
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=1u16.to_le_bytes())]
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
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::ACCESSORY_INFORMATION.into(),
            iid: SvcId(1),
            attributes: Default::default(),
            properties: Default::default(),
        };

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::HARDWARE_REVISION.into(),
                iid: CharId(u16::from_le_bytes([0x01, 0x01])),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.hardware_revision.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::SERIAL_NUMBER.into(),
                iid: CharId(u16::from_le_bytes([0x01, 0x02])),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.serial_number.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::SERVICE_INSTANCE.into(),
                iid: CharId(u16::from_le_bytes([0x01, 0x03])),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.service_instance.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::MODEL.into(),
                iid: CharId(u16::from_le_bytes([0x01, 0x04])),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.model.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::NAME.into(),
                iid: CharId(u16::from_le_bytes([0x01, 0x05])),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.name.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::MANUFACTURER.into(),
                iid: CharId(u16::from_le_bytes([0x01, 0x06])),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.manufacturer.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::FIRMWARE_REVISION.into(),
                iid: CharId(u16::from_le_bytes([0x01, 0x06])),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.firmware_revision.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::IDENTIFY.into(),
                iid: CharId(u16::from_le_bytes([0x01, 0x07])),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.identify.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}

fn make_table() {
    // from https://github.com/embassy-rs/trouble/blame/404b0f77345522764582747e0acd50a22236b59e/examples/apps/src/ble_bas_peripheral.rs
    const MAX_ATTRIBUTES: usize = 10;
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    let mut table: AttributeTable<'_, NoopRawMutex, { MAX_ATTRIBUTES }> = AttributeTable::new();
    let mut svc = table.add_service(Service {
        uuid: service::ACCESSORY_INFORMATION.into(),
    });
    let v = svc
        .add_characteristic::<FacadeDummyType, crate::uuid::HomekitUuid16>(
            characteristic::HARDWARE_REVISION,
            &[CharacteristicProp::Read, CharacteristicProp::Write],
            FacadeDummyType::default(),
            &mut [],
        )
        //.add_descriptor(uuid, props, data)
        .build();
    let handle = v.handle;

    // let server = GattServer::<C, NoopRawMutex, MAX_ATTRIBUTES, L2CAP_MTU>::new(stack, &table);
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
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x02u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x02)]
    service_instance: u16,

    /// Service signature, only two bytes.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x02, 0x52])]
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
    service_signature: FacadeDummyType,

    /// Version string.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x02, 0x03])]
    #[characteristic(uuid=characteristic::VERSION, value="2.2.0".try_into().unwrap(), read)]
    version: GattString<16>,
}
impl ProtocolInformationService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::PROTOCOL_INFORMATION.into(),
            iid: SvcId(2),
            attributes: Default::default(),
            properties: Default::default(),
        };

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::SERVICE_INSTANCE.into(),
                iid: CharId(0x02u16),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.service_instance.handle).with_format_opaque(),
                ),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::SERVICE_SIGNATURE.into(),
                iid: CharId(u16::from_le_bytes([0x02, 0x52])),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.service_signature.handle).with_format_opaque(),
                ),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::VERSION.into(),
                iid: CharId(u16::from_le_bytes([0x02, 0x03])),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.version.handle).with_format_opaque()),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}
#[gatt_service(uuid = service::PAIRING)]
pub struct PairingService {
    /// Service instance ID, must be a 16 bit unsigned integer.
    // May not be 1, value 1 is for accessory information.
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x03, 0x01])]
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

#[gatt_service(uuid = service::LIGHTBULB)]
pub struct LightbulbService {
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x04, 0x01])]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x04)]
    service_instance: u16,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x04, 0x01])]
    #[characteristic(uuid=characteristic::ON, read, write )]
    on: bool,

    /// Service signature, only two bytes.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x04, 0x02])]
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write, notify)]
    service_signature: FacadeDummyType,
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEPDU%2BTLV.c#L93
/// Properties for a characteristic
#[bitfield(u16)]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable)]
pub struct CharacteristicProperties {
    #[bits(1)]
    pub read_open: bool, // readableWithoutSecurity
    #[bits(1)]
    pub write_open: bool,
    #[bits(1)]
    pub supports_authorization: bool,
    #[bits(1)]
    pub requires_timed_write: bool,

    #[bits(1)]
    pub read: bool,

    #[bits(1)]
    pub write: bool,

    #[bits(1)]
    pub hidden: bool,

    #[bits(1)]
    pub supports_event_notification: bool,

    #[bits(1)]
    pub supports_disconnect_notification: bool,

    #[bits(1)]
    pub supports_broadcast_notification: bool,

    #[bits(6)]
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
    //protocol_service_properties: ServiceProperties,
    buffer: core::cell::RefCell<&'static mut [u8]>,
    prepared_reply: Option<Reply>,
    information_service: crate::Service,
    protocol_service: crate::Service,
}
impl HapPeripheralContext {
    pub fn get_attribute_by_char(&self, chr: CharId) -> Option<&crate::Attribute> {
        if let Some(a) = self.information_service.get_attribute_by_iid(chr) {
            Some(a)
        } else if let Some(b) = self.protocol_service.get_attribute_by_iid(chr) {
            Some(b)
        } else {
            None
        }
    }

    pub fn get_service_by_char(&self, chr: CharId) -> Option<&crate::Service> {
        if self.information_service.get_attribute_by_iid(chr).is_some() {
            Some(&self.information_service)
        } else if self.protocol_service.get_attribute_by_iid(chr).is_some() {
            Some(&self.protocol_service)
        } else {
            None
        }
    }

    pub fn get_service_by_svc(&self, srv: SvcId) -> Option<&crate::Service> {
        if self.information_service.iid == srv {
            Some(&self.information_service)
        } else if self.protocol_service.iid == srv {
            Some(&self.protocol_service)
        } else {
            None
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct BufferResponse(pub usize);

impl HapPeripheralContext {
    pub fn new(
        buffer: &'static mut [u8],
        information_service: &AccessoryInformationService,
        protocol_service: &ProtocolInformationService,
    ) -> Result<Self, HapBleError> {
        Ok(Self {
            //protocol_service_properties: Default::default(),
            buffer: buffer.into(),
            prepared_reply: None,
            information_service: information_service.populate_support()?,
            protocol_service: protocol_service.populate_support()?,
        })
    }

    pub async fn service_signature_request(
        &mut self,
        req: &pdu::ServiceSignatureReadRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L249

        let resp = req.header.to_success();

        let mut buffer = self.buffer.borrow_mut();

        let len = resp.write_into_length(*buffer)?;

        let svc = self.get_service_by_svc(req.svc_id);

        if let Some(svc) = svc {
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
            let len = BodyBuilder::new_at(*buffer, len)
                .add_u16(BleTLVType::HAPServiceProperties, svc.properties.0)
                .add_u16s(BleTLVType::HAPLinkedServices, &[])
                .end();

            Ok(BufferResponse(len))
        } else {
            // What do we return if the id is not known??
            todo!()
        }
    }
    pub async fn characteristic_signature_request(
        &mut self,
        req: &pdu::CharacteristicSignatureReadRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L289

        // To hdump  00 01  c8  11  00
        // reply:       02  c8  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  a5  00  00  00  07  02  10  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  a2  00  00  00  0a  02  10  00  0c  07  1b  00  00  27  01  00  00
        //          00, 01, 05, 02, 02
        //              02, 05, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a5, 00, 00, 00, 07, 02, 02, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a2, 00, 00, 00, 0a, 02, 10, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00
        //                  tid st <len  >
        //                                 <chr                                                                 > <svcid         ><svctype                                                               ><properties    >
        //
        // Bad:       00 01 d2 02 52
        //              02  d2  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  a5  00  00  00  07  02  02  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  a2  00  00  00  0a  02  10  00  0c  07  1b  00  00  27  01  00  00
        // from 2025_08_15_1817_homekitadk_pair_success;
        // Good:      00 01 b4 11 00
        //              02  b4  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  a5  00  00  00  07  02  10  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  a2  00  00  00  0a  02  10  00  0c  07  1b  00  00  27  01  00  00
        //                                                                                                                  ^^
        // good;
        // 07  02  10  00
        //         ^^^^^^  is the SVC id.
        //
        //
        //
        // more bad
        //              02, 21, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a5, 00, 00, 00, 07, 02, 02, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a2, 00, 00, 00, 0a, 02, 10, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00

        //

        if let Some(chr) = self.get_attribute_by_char(req.char_id) {
            let mut buffer = self.buffer.borrow_mut();
            // NONCOMPLIANCE: should drop connection when requesting characteristics on the pairing characteristics.
            let srv = self.get_service_by_char(req.char_id).unwrap();
            // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLECharacteristic%2BSignature.c#L10
            let reply = req.header.to_success();
            let len = reply.write_into_length(*buffer)?;

            let len = BodyBuilder::new_at(*buffer, len)
                .add_characteristic_uuid(&chr.uuid)
                // .add_service(SvcId(0x10)) // what is this set to?
                .add_service(srv.iid) // what is this set to?
                .add_service_uuid(&srv.uuid)
                .add_characteristic_properties(chr.ble_ref().properties)
                .add_optional_user_description(&chr.user_description)
                .add_format(&chr.ble_ref().format)
                .end();

            Ok(BufferResponse(len))
        } else {
            todo!()
        }
    }

    async fn reply_read_payload<'stack, P: trouble_host::PacketPool>(
        &self,
        event: ReadEvent<'stack, '_, P>,
        reply: Reply,
    ) -> Result<(), trouble_host::Error> {
        // let buffer = self.buffer.borrow();

        let data = self.get_response(reply.payload);
        let reply = trouble_host::att::AttRsp::Read { data: &data };
        warn!("Replying with: {:02x?}", reply);
        // We see this print,
        //
        // but nothing ever ends up in the aether
        event.into_payload().reply(reply).await?;
        Ok(())
    }

    fn get_response(&self, reply: BufferResponse) -> core::cell::Ref<'_, [u8]> {
        // self.buffer.borrow().map(|z| &z[0..reply.payload.0])
        core::cell::Ref::<'_, &'static mut [u8]>::map(self.buffer.borrow(), |z| &z[0..reply.0])
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

                        self.reply_read_payload(event, reply).await?;

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
                    warn!("Writing protocol.service_signature  {:02x?}", event.data());
                    // Writing protocol.service_signature  [0, 6, 107, 2, 0]
                    // Yes, that matches the hap service signature read

                    let header = pdu::RequestHeader::parse_pdu(event.data())?;
                    match header.opcode {
                        pdu::OpCode::ServiceSignatureRead => {
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
                            let req =
                                pdu::CharacteristicSignatureReadRequest::parse_pdu(event.data())?;
                            warn!("Got req: {:?}", req);
                            let resp = self.characteristic_signature_request(&req).await?;
                            self.prepared_reply = Some(Reply {
                                payload: resp,
                                handle: hap.protocol.service_signature.handle,
                            });

                            let reply = trouble_host::att::AttRsp::Write;
                            event.into_payload().reply(reply).await?;
                            return Ok(None);
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
        let mut ctx =
            HapPeripheralContext::new(buffer, &server.accessory_information, &server.protocol)?;

        let service_signature_req = [0, 6, 0x3a, 2, 0];
        let service_signature_req =
            pdu::ServiceSignatureReadRequest::parse_pdu(&service_signature_req)?;
        let resp = ctx
            .service_signature_request(&service_signature_req)
            .await?;
        {
            let reply = ctx.get_response(resp);
            warn!("reply: {:?}", reply);

            let expected_req = [2, 0x3a, 0, 6, 0, 0xf, 2, 4, 0, 0x10, 0];
            assert_eq!(&*reply, expected_req);
        }

        // and then it sends... which we have no clue what it is yet.
        let payload = [0x00, 0x01, 0xae, 0x02, 0x02];
        // [micro_hap::ble] Writing protocol.service_signature  [0, 1, ae, 2, 2]
        let service_signature_req = pdu::ServiceSignatureReadRequest::parse_pdu(&payload)?;
        let resp = ctx
            .service_signature_request(&service_signature_req)
            .await?;
        // Oh... that's a characteristic signature read request.
        // we need the PDU types, and interpret based on that.

        Ok(())
    }

    #[test]
    fn test_characteristics() {
        let v = CharacteristicProperties::new()
            .with_read(true)
            .with_read_open(true)
            .with_hidden(true);
        assert_eq!(v.0, 0x0001 | 0x0010 | 0x0040);
    }
}
