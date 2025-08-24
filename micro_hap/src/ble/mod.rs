use crate::AccessoryInformationStatic;
use crate::{characteristic, descriptor, service};
use trouble_host::prelude::*;
mod util;
use embassy_sync::blocking_mutex::raw::RawMutex;
use util::GattString;
mod pdu;
use crate::BleProperties;
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
// changing ids definitely fixed things.
//
// We're now on the pair verify characteristic response not being accepted.
//
// Pair verify is ONLY 'read' not open_read... so we probably need to implement a security reject, after which a pairing
// is triggered?
//
//
// For the permissions;
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L48
// seems to have the best overview?
//
// We probably have to handle this fragmentation stuff as well?
//
//
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
    /// Something went wrong with decryption or encryption.
    EncryptionError,
}

impl From<crate::tlv::TLVError> for HapBleError {
    fn from(e: crate::tlv::TLVError) -> HapBleError {
        match e {
            crate::tlv::TLVError::NotEnoughData => HapBleError::InvalidValue,
            crate::tlv::TLVError::MissingEntry => HapBleError::InvalidValue,
            crate::tlv::TLVError::UnexpectedValue => HapBleError::InvalidValue,
            crate::tlv::TLVError::BufferOverrun => HapBleError::BufferOverrun,
        }
    }
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
            HapBleError::EncryptionError => trouble_host::Error::NoPermits,
            HapBleError::AllocationOverrun => trouble_host::Error::OutOfMemory,
        }
    }
}
impl From<chacha20poly1305::Error> for HapBleError {
    fn from(_: chacha20poly1305::Error) -> HapBleError {
        HapBleError::EncryptionError
    }
}

// MUST have an instance id of 1, service 3e
#[gatt_service(uuid = service::ACCESSORY_INFORMATION)]
pub struct AccessoryInformationService {
    /// Service instance ID, must be a 16 bit unsigned integer.
    // Service instance id for accessory information must be 1, 0 is invalid.
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAP.h#L3245-L3249
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=1u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 1)]
    pub service_instance: u16,

    // 0x14
    /// Identify routine, triggers something, it does not contain data.
    #[characteristic(uuid=characteristic::IDENTIFY, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=2u16.to_le_bytes())]
    pub identify: bool,

    // 0x20
    /// Manufacturer name that created the device.
    #[characteristic(uuid=characteristic::MANUFACTURER, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=3u16.to_le_bytes())]
    pub manufacturer: GattString<64>,

    // 0x21
    /// Manufacturer specific model, length must be greater than one.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=4u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::MODEL, read, write)]
    pub model: GattString<64>,

    // 0x0023
    /// Name for the device.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=5u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::NAME, read, write)]
    pub name: GattString<64>,

    //0x0030
    /// Manufacturer serial number, length must be greater than one.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=6u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::SERIAL_NUMBER, read, write)]
    pub serial_number: GattString<64>,

    //0x0052
    /// Firmware revision string; "<major>.<minor>.<revision>"
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=7u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::FIRMWARE_REVISION, read, write)]
    pub firmware_revision: GattString<16>,

    //0x0053
    /// Describes hardware revision string; "<major>.<minor>.<revision>"
    #[characteristic(uuid=characteristic::HARDWARE_REVISION, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=8u16.to_le_bytes())]
    pub hardware_revision: GattString<16>,

    // 4ab8811-ac7f-4340-bac3-fd6a85f9943b
    /// ADK version thing from the example,
    #[characteristic(uuid=characteristic::ADK_VERSION, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=9u16.to_le_bytes())]
    pub adk_version: GattString<16>,
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
                uuid: characteristic::SERVICE_INSTANCE.into(),
                iid: CharId(2),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.service_instance.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::IDENTIFY.into(),
                iid: CharId(2),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.identify.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::MANUFACTURER.into(),
                iid: CharId(3),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.manufacturer.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::MODEL.into(),
                iid: CharId(4),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.model.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::NAME.into(),
                iid: CharId(5),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.name.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::SERIAL_NUMBER.into(),
                iid: CharId(6),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.serial_number.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::FIRMWARE_REVISION.into(),
                iid: CharId(7),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.firmware_revision.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::HARDWARE_REVISION.into(),
                iid: CharId(8),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.hardware_revision.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::ADK_VERSION.into(),
                iid: CharId(9),
                user_description: None,
                ble: Some(BleProperties::from_handle(self.adk_version.handle)),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}
/*
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
}*/

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

// 0xA2
#[gatt_service(uuid = service::PROTOCOL_INFORMATION)]
pub struct ProtocolInformationService {
    /// Service instance ID, must be a 16 bit unsigned integer.
    // May not be 1, value 1 is for accessory information.
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x02u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x10)]
    service_instance: u16,

    /// Service signature, only two bytes.
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=0x11u16.to_le_bytes())]
    service_signature: FacadeDummyType,

    /// Version string.
    #[characteristic(uuid=characteristic::VERSION, value="2.2.0".try_into().unwrap(), read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x12u16.to_le_bytes())]
    version: GattString<16>,
}
impl ProtocolInformationService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::PROTOCOL_INFORMATION.into(),
            iid: SvcId(0x10),
            attributes: Default::default(),
            properties: crate::ServiceProperties::new().with_configurable(true),
        };

        /*
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::SERVICE_INSTANCE.into(),
                iid: CharId(0x14),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.service_instance.handle).with_format_opaque(),
                ),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
            */

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::SERVICE_SIGNATURE.into(),
                iid: CharId(0x11),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.service_signature.handle)
                        .with_format_opaque()
                        .with_properties(CharacteristicProperties::new().with_read(true)),
                ),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::VERSION.into(),
                iid: CharId(0x12),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.version.handle)
                        .with_format_opaque()
                        .with_properties(CharacteristicProperties::new().with_read(true)),
                ),
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
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x20)]
    service_instance: u16,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x22u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::PAIRING_PAIR_SETUP, read, write)]
    pair_setup: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x23u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::PAIRING_PAIR_VERIFY, read, write)]
    pair_verify: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x24u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::PAIRING_FEATURES, read, write)]
    features: FacadeDummyType,

    // Paired read and write only.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x25u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::PAIRING_PAIRINGS, read, write)]
    pairings: FacadeDummyType,
}

impl PairingService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::PAIRING.into(),
            iid: SvcId(0x20),
            attributes: Default::default(),
            properties: Default::default(),
        };

        /*
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::SERVICE_INSTANCE.into(),
                iid: CharId(0x20),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.service_instance.handle).with_format_opaque(),
                ),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
            */

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::PAIRING_PAIR_SETUP.into(),
                iid: CharId(0x22),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.pair_setup.handle)
                        .with_format_opaque()
                        .with_properties(CharacteristicProperties::new().with_open_rw(true)),
                ),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::PAIRING_PAIR_VERIFY.into(),
                iid: CharId(0x23),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.pair_verify.handle)
                        .with_format_opaque()
                        .with_properties(CharacteristicProperties::new().with_open_rw(true)),
                ),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::PAIRING_FEATURES.into(),
                iid: CharId(0x24),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.features.handle)
                        .with_format_opaque()
                        .with_properties(CharacteristicProperties::new().with_read_open(true)),
                ),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .attributes
            .push(crate::Attribute {
                uuid: characteristic::PAIRING_PAIRINGS.into(),
                iid: CharId(0x25),
                user_description: None,
                ble: Some(
                    BleProperties::from_handle(self.pairings.handle)
                        .with_format_opaque()
                        .with_properties(CharacteristicProperties::new().with_rw(true)),
                ),
            })
            .map_err(|_| HapBleError::AllocationOverrun)?;
        Ok(service)
    }
}

#[gatt_service(uuid = service::LIGHTBULB)]
pub struct LightbulbService {
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x04, 0x01])]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x30)]
    service_instance: u16,

    /// Service signature, only two bytes.
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=0x31u16.to_le_bytes())]
    service_signature: FacadeDummyType,

    // 0x0023
    /// Name for the device.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x32u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::NAME, read, write )]
    pub name: GattString<64>,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x33u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::ON, read, write )]
    on: bool,
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
impl CharacteristicProperties {
    pub fn with_open_rw(self, state: bool) -> Self {
        self.with_read_open(state).with_write_open(state)
    }
    pub fn with_rw(self, state: bool) -> Self {
        self.with_read(state).with_write(state)
    }
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
    pair_ctx: core::cell::RefCell<&'static mut crate::pairing::PairContext>,

    prepared_reply: Option<Reply>,

    information_service: crate::Service,
    protocol_service: crate::Service,
    pairing_service: crate::Service,
    // pair_ctx: crate::pairing::PairContext<'static, 'static, 'static, 'static>,
}
impl HapPeripheralContext {
    fn services(&self) -> [&crate::Service; 3] {
        [
            &self.information_service,
            &self.protocol_service,
            &self.pairing_service,
        ]
    }

    pub fn get_attribute_by_char(&self, chr: CharId) -> Option<&crate::Attribute> {
        for s in self.services() {
            if let Some(a) = s.get_attribute_by_iid(chr) {
                return Some(a);
            }
        }
        None
    }

    pub fn get_service_by_char(&self, chr: CharId) -> Option<&crate::Service> {
        for s in self.services() {
            if let Some(_attribute) = s.get_attribute_by_iid(chr) {
                return Some(s);
            }
        }
        None
    }

    pub fn get_service_by_svc(&self, srv: SvcId) -> Option<&crate::Service> {
        for s in self.services() {
            if s.iid == srv {
                return Some(s);
            }
        }
        None
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct BufferResponse(pub usize);

impl HapPeripheralContext {
    pub fn new(
        buffer: &'static mut [u8],
        pair_ctx: &'static mut crate::pairing::PairContext,
        information_service: &AccessoryInformationService,
        protocol_service: &ProtocolInformationService,
        pairing_service: &PairingService,
    ) -> Result<Self, HapBleError> {
        Ok(Self {
            //protocol_service_properties: Default::default(),
            buffer: buffer.into(),
            pair_ctx: pair_ctx.into(),
            prepared_reply: None,
            information_service: information_service.populate_support()?,
            protocol_service: protocol_service.populate_support()?,
            pairing_service: pairing_service.populate_support()?,
        })
    }

    pub async fn service_signature_request(
        &mut self,
        req: &pdu::ServiceSignatureReadRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L249

        info!("service signature req: {:?}", req);
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
            //
            // protocol.service signature;
            // good: 02  5b  00  06  00  0f  02  04  00  10  00
            // ours: 02, cd, 00, 06, 00, 0f, 02, 00, 00, 10, 00
            // now   02, 43, 00, 06, 00, 0f, 02, 00, 00, 10, 00
            //       02, 69, 00, 06, 00, 0f, 02, 00, 00, 10, 00
            // now   02, 4d, 00, 06, 00, 0f, 02, 04, 00, 10, 00
            // check!
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
        //
        // On pair-verify;
        // good: 02  6d  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  4e  00  00  00  07  02  20  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  55  00  00  00  0a  02  03  00  0c  07  1b  00  00  27  01  00  00
        // bad:  02, f8, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 4e, 00, 00, 00, 07, 02, 20, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 55, 00, 00, 00, 0a, 02, 10, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00
        //       02, 84, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 4e, 00, 00, 00, 07, 02, 20, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 55, 00, 00, 00, 0a, 02, 03, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00
        //      [02, 84, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 4e, 00, 00, 00, 07, 02, 20, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 55, 00, 00, 00, 0a, 02, 03, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00]
        //       02, ed, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 4e, 00, 00, 00, 07, 02, 20, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 55, 00, 00, 00, 0a, 02, 03, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00
        // bad:
        //  [2025-08-16T20:50:24Z WARN  micro_hap::ble] Writing pairing.pair_verify  [0, 1, 132, 35, 0] 0x:  00 01 84 23 00
        //  [2025-08-16T20:50:24Z WARN  micro_hap::ble] Replying with: Read { data: [02, 84, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 4e, 00, 00, 00, 07, 02, 20, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 55, 00, 00, 00, 0a, 02, 03, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00] }
        // good:
        //
        //
        // Pair setup reply good is:
        //
        // 02  de  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  4c  00  00  00  07  02  20  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  55  00  00  00  0a  02  03  00  0c  07  1b  00  00  27  01  00  00
        // Our pair setup reply is:
        //[02, c6, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 4c, 00, 00, 00, 07, 02, 20, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 55, 00, 00, 00, 0a, 02, 00, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00]
        //[02, 5e, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 4c, 00, 00, 00, 07, 02, 20, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 55, 00, 00, 00, 0a, 02, 03, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00]
        //                                                                                                                                                                                         ^^^^^^
        //
        // Version ours:
        //  02, 96, 00, 35, 00, 04, 10, 3b, 94, f9, 85, 6a, fd, c3, ba, 40, 43, 7f, ac, 11, 88, ab, 34, 07, 02, 01, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 3e, 00, 00, 00, 0a, 02, 00, 00, 0c, 07, 04, 00, 00, 27, 01, 00, 00
        // version theirs
        //  02  39  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  37  00  00  00  07  02  10  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  a2  00  00  00  0a  02  10  00  0c  07  19  00  00  27  01  00  00
        //
        //
        // --
        // protocol.service signature.
        // [2025-08-16T22:20:56Z WARN  micro_hap::ble] Writing protocol.service_signature  0x[00, 01, 80, 11, 00]
        // [2025-08-16T22:20:56Z WARN  micro_hap::ble] Replying with: Read { data: [
        // 02, 80, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a5, 00, 00, 00, 07, 02, 10, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a2, 00, 00, 00, 0a, 02, 00, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00] }
        // 02, 80, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a5, 00, 00, 00, 07, 02, 10, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a2, 00, 00, 00, 0a, 02, 10, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00
        // Actual:
        //    00 01 b4 11 00
        // 02  b4  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  a5  00  00  00  07  02  10  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  a2  00  00  00  0a  02  10  00  0c  07  1b  00  00  27  01  00  00
        // --                                                                                                                                                                                          ^^
        // That one is good now.
        //
        //
        // ==== With fixed service permissions
        // [2025-08-16T23:04:21Z WARN  micro_hap::ble] Writing protocol.service_signature  0x[00, 01, 2a, 11, 00]
        // [2025-08-16T23:04:21Z WARN  micro_hap::ble] Replying with: Read { data:
        // [02, 2a, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a5, 00, 00, 00, 07, 02, 10, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a2, 00, 00, 00, 0a, 02, 10, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00] }
        // truth:
        //                                                                                    00  01  b4  11  00
        //  02  b4  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  a5  00  00  00  07  02  10  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  a2  00  00  00  0a  02  10  00  0c  07  1b  00  00  27  01  00  00
        // Checks out.
        //
        // Writing protocol.version  [0, 1, 174, 18, 0]
        // [2025-08-16T23:04:21Z WARN  micro_hap::ble] Replying with: Read { data: [
        //  02, ae, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 37, 00, 00, 00, 07, 02, 10, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a2, 00, 00, 00, 0a, 02, 00, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00] }
        // truth:
        //  02  39  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  37  00  00  00  07  02  10  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  a2  00  00  00  0a  02  10  00  0c  07  19  00  00  27  01  00  00
        // -->                                                                                                                                                                                          ^^
        // now:
        // [02, 94, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 37, 00, 00, 00, 07, 02, 10, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, a2, 00, 00, 00, 0a, 02, 10, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00]
        // Checks out.
        //
        //
        //
        //
        // Writing pairing.pair_setup  [0, 1, 21, 34, 0]
        // [2025-08-16T23:10:08Z WARN  micro_hap::ble] Replying with: Read { data:
        // [02, 15, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 4c, 00, 00, 00, 07, 02, 20, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 55, 00, 00, 00, 0a, 02, 03, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00] }
        // truth:
        // Does pair verify first! Not pair setup??
        //  02  de  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  4c  00  00  00  07  02  20  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  55  00  00  00  0a  02  03  00  0c  07  1b  00  00  27  01  00  00
        // Checks out though.
        //
        // Writing pairing.pair_verify  [0, 1, 62, 35, 0]
        //
        // [2025-08-16T23:10:08Z WARN  micro_hap::ble] Replying with: Read { data:
        // [02, 3e, 00, 35, 00, 04, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 4e, 00, 00, 00, 07, 02, 20, 00, 06, 10, 91, 52, 76, bb, 26, 00, 00, 80, 00, 10, 00, 00, 55, 00, 00, 00, 0a, 02, 03, 00, 0c, 07, 1b, 00, 00, 27, 01, 00, 00] }
        // Truth:
        //  02  6d  00  35  00  04  10  91  52  76  bb  26  00  00  80  00  10  00  00  4e  00  00  00  07  02  20  00  06  10  91  52  76  bb  26  00  00  80  00  10  00  00  55  00  00  00  0a  02  03  00  0c  07  1b  00  00  27  01  00  00
        // checks out.
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

    pub async fn characteristic_read_request(
        &mut self,
        req: &pdu::CharacteristicReadRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // Well ehm, what do we do here?
        let char_id = req.char_id; // its unaligned, so copy it before we use it.
        if let Some(chr) = self.get_attribute_by_char(char_id) {
            if chr.uuid == crate::characteristic::VERSION.into() {
                // Hardcode this for now, we'll make something smarter later.
                let mut buffer = self.buffer.borrow_mut();
                let reply = req.header.to_success();
                let len = reply.write_into_length(*buffer)?;

                let len = BodyBuilder::new_at(*buffer, len)
                    // Something here that writes "2.2.0"
                    .add_value(&"2.2.0".as_bytes())
                    .end();
                Ok(BufferResponse(len))
            } else if chr.uuid == crate::characteristic::PAIRING_FEATURES.into() {
                let mut buffer = self.buffer.borrow_mut();
                let reply = req.header.to_success();
                let len = reply.write_into_length(*buffer)?;
                // Software authentication is 0x2, this is non-const in the reference implementation though.
                let len = BodyBuilder::new_at(*buffer, len)
                    .add_value(&2u8.as_bytes())
                    .end();
                Ok(BufferResponse(len))
            } else {
                error!(
                    "Got read for characteristic that is not yet handled: {:?}",
                    char_id
                );
                todo!();
            }
        } else {
            error!("Got read for unknown characteristic: {:?}", char_id);
            todo!();
        }
    }

    pub async fn info_request(
        &mut self,
        req: &pdu::InfoRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessory%2BInfo.c#L71
        let char_id = req.char_id; // its unaligned, so copy it before we use it.
        if let Some(chr) = self.get_attribute_by_char(char_id) {
            if chr.uuid == crate::characteristic::SERVICE_SIGNATURE.into() {
                // Hardcode this for now, we'll make something smarter later.
                let mut buffer = self.buffer.borrow_mut();
                let reply = req.header.to_success();
                let len = reply.write_into_length(*buffer)?;

                let pair_ctx = self.pair_ctx.borrow();
                let setup_hash = crate::adv::calculate_setup_hash(
                    &pair_ctx.accessory.device_id,
                    &pair_ctx.accessory.setup_id,
                );
                let len = BodyBuilder::new_at(*buffer, len)
                    // 1 is good enough for the ip side, probably also for bluetooth?
                    .add_u16(pdu::InfoResponseTLVType::StateNumber, 1)
                    // Config number, we should increment this every reconfiguration I think? Ignore for now.
                    .add_u16(pdu::InfoResponseTLVType::ConfigNumber, 1)
                    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessory%2BInfo.c#L136
                    .add_info_device_id(&pair_ctx.accessory.device_id)
                    // Feature flags, 2 is software authentication only.
                    .add_u8(pdu::InfoResponseTLVType::FeatureFlags, 2)
                    // Next is param-model. is that always a string?
                    .add_slice(
                        pdu::InfoResponseTLVType::ModelName,
                        pair_ctx.accessory.model.as_bytes(),
                    )
                    // And then protocol version.
                    .add_slice(
                        pdu::InfoResponseTLVType::ProtocolVersion,
                        "2.2.0".as_bytes(),
                    )
                    // Status flag... https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessoryServer.c#L924
                    // Lets just report not paired all the time: 1.
                    // Lets try paired now, since we're in a secure session? 0
                    .add_u8(pdu::InfoResponseTLVType::StatusFlag, 1)
                    // Category
                    .add_u16(
                        pdu::InfoResponseTLVType::CategoryIdentifier,
                        pair_ctx.accessory.category,
                    )
                    // Finally, the setup hash... Does this value matter?
                    .add_slice(pdu::InfoResponseTLVType::SetupHash, &setup_hash)
                    .end();
                Ok(BufferResponse(len))
            } else {
                error!(
                    "Got info for characteristic that is not yet handled: {:?}",
                    char_id
                );
                todo!();
            }
        } else {
            error!("Got info read for unknown characteristic: {:?}", char_id);
            todo!();
        }
    }

    async fn reply_read_payload<'stack, P: trouble_host::PacketPool>(
        //&self,
        data: &[u8],
        event: ReadEvent<'stack, '_, P>,
    ) -> Result<(), trouble_host::Error> {
        // let buffer = self.buffer.borrow();

        //let data = self.get_response(reply.payload);
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
    pub async fn handle_read_outgoing(
        &mut self,
        handle: u16,
    ) -> Result<Option<core::cell::Ref<'_, [u8]>>, HapBleError> {
        if self.prepared_reply.as_ref().map(|e| e.handle) == Some(handle) {
            let reply = self.prepared_reply.take().unwrap();
            Ok(Some(self.get_response(reply.payload)))
        } else {
            Ok(None)
        }
    }

    pub async fn handle_write_incoming<'hap, 'support>(
        &mut self,
        hap: &HapServices<'hap>,
        support: &crate::pairing::PairSupport<'support>,
        data: &[u8],
        handle: u16,
    ) -> Result<Option<BufferResponse>, HapBleError> {
        let security_active = self.pair_ctx.borrow().session.security_active;
        let mut tmp_buffer = [0u8; 1024];
        let data = if security_active {
            warn!("handle_write_incoming raw {:0>2x?}", data);
            // Raw write data [49, f0, c7, b1, 91, d4, d9, f9, 44, b9, 50, f0, c4, 67, a6, 6, c8, 6d, f9, fe, dc]
            // Raw write data [ed, 4c, 8a, f4, 7e, ca, bf, 1a, 1, 9, 55, 6e, 95, 24, dc, a, 7a, 7d, 83, 3d, 30]
            // Yes, these are encrypted.
            //
            // Collect the context
            let buffer = &mut tmp_buffer;
            let mut pair_ctx = self.pair_ctx.borrow_mut();

            // Copy the payload into the buffer
            buffer.fill(0);
            // parsed.copy_body(&mut *buffer)?;
            buffer[0..data.len()].copy_from_slice(data);

            pair_ctx
                .session
                .c_to_a
                .decrypt(&mut buffer[0..data.len()])?
        } else {
            data
        };
        warn!("handle_write_incoming {:0>2x?}", data);

        let header = pdu::RequestHeader::parse_pdu(data)?;
        warn!("Write header {:x?}", header);

        #[allow(unreachable_code)]
        let resp = match header.opcode {
            pdu::OpCode::ServiceSignatureRead => {
                let req = pdu::ServiceSignatureReadRequest::parse_pdu(data)?;
                self.service_signature_request(&req).await?
            }
            pdu::OpCode::CharacteristicSignatureRead => {
                // second one is on [0, 1, 44, 2, 2]
                let req = pdu::CharacteristicSignatureReadRequest::parse_pdu(data)?;
                warn!("Got req: {:?}", req);
                self.characteristic_signature_request(&req).await?
            }
            pdu::OpCode::CharacteristicRead => {
                let req = pdu::CharacteristicReadRequest::parse_pdu(data)?;
                warn!("Got req: {:?}", req);
                self.characteristic_read_request(&req).await?
            }
            pdu::OpCode::CharacteristicWrite => {
                if handle == hap.pairing.pair_setup.handle {
                    info!("write raw req event data: {:02x?}", data);
                    let parsed = pdu::CharacteristicWriteRequest::parse_pdu(data)?;
                    info!("got write on pair setup with: {:?}", parsed);

                    // Write the body to our internal buffer here.
                    let mut buffer = self.buffer.borrow_mut();
                    buffer.fill(0);
                    parsed.copy_body(&mut *buffer)?;
                    let mut pair_ctx = self.pair_ctx.borrow_mut();
                    crate::pairing::pair_setup_handle_incoming(&mut **pair_ctx, support, &*buffer)
                        .map_err(|_| HapBleError::InvalidValue)?;

                    // So now we craft the reply.

                    // let resp = parsed.header.header.to_success();
                    // let len = resp.write_into_length(*buffer)?;

                    let full_len = buffer.len();
                    let (first_half, mut second_half) = buffer.split_at_mut(full_len / 2);

                    // Put the reply in the second half.
                    let outgoing_len = crate::pairing::pair_setup_handle_outgoing(
                        &mut **pair_ctx,
                        support,
                        &mut second_half,
                    )
                    .map_err(|_| HapBleError::InvalidValue)?;

                    let reply = parsed.header.header.to_success();
                    let len = reply.write_into_length(first_half)?;

                    let len = BodyBuilder::new_at(first_half, len)
                        .add_value(&second_half[0..outgoing_len])
                        .end();

                    BufferResponse(len)
                } else {
                    todo!("Need dispatch to correct method");
                }
            }
            pdu::OpCode::Info => {
                // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L623
                // we don't have this in the recording?!?
                if !security_active {
                    return Err(HapBleError::EncryptionError);
                }
                let req = pdu::InfoRequest::parse_pdu(data)?;
                info!("Info req: {:?}", req);
                self.info_request(&req).await?
            }
            _ => {
                return {
                    error!("Failed to handle: {:?}", header);
                    Err(HapBleError::UnexpectedRequest.into())
                };
            }
        };
        Ok(Some(resp))
    }

    pub async fn process_gatt_event<'stack, 'server, 'hap, 'support, P: PacketPool>(
        &mut self,
        hap: &HapServices<'hap>,
        support: &crate::pairing::PairSupport<'support>,
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

                if let Some(buffer_thing) = self.handle_read_outgoing(event.handle()).await? {
                    Self::reply_read_payload(&*buffer_thing, event).await?;

                    return Ok(None);
                }

                Ok(Some(GattEvent::Read(event)))
            }
            GattEvent::Write(event) => {
                warn!("Raw write data {:0>2x?}", event.data());

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
                    warn!(
                        "Writing protocol.service_signature  0x{:02x?}",
                        event.data()
                    );
                    // Writing protocol.service_signature  [0, 6, 107, 2, 0]
                    // Yes, that matches the hap service signature read

                    // Maybe the write request has to go through and it is followed by a read?
                } else if event.handle() == hap.protocol.version.handle {
                    warn!("Writing protocol.version  {:?}", event.data());
                }

                if event.handle() == hap.pairing.service_instance.handle {
                    warn!("Writing pairing.service_instance");
                } else if event.handle() == hap.pairing.pair_setup.handle {
                    warn!("Writing pairing.pair_setup  {:?}", event.data());
                    // [0, 1, 62, 0, 34]
                } else if event.handle() == hap.pairing.pair_verify.handle {
                    warn!("Writing pairing.pair_verify  {:?}", event.data());
                } else if event.handle() == hap.pairing.features.handle {
                    warn!("Writing pairing.features  {:?}", event.data());
                } else if event.handle() == hap.pairing.pairings.handle {
                    warn!("Writing pairing.pairings  {:?}", event.data());
                }

                let resp = self.handle_write_incoming(hap, support, &event.data(), event.handle());
                if let Some(resp) = resp.await? {
                    self.prepared_reply = Some(Reply {
                        payload: resp,
                        handle: event.handle(),
                    });

                    let reply = trouble_host::att::AttRsp::Write;
                    event.into_payload().reply(reply).await?;
                    return Ok(None);
                } else {
                    todo!("unhandled event");
                }
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

        let pair_ctx = {
            static STATE: StaticCell<crate::pairing::PairContext> = StaticCell::new();
            STATE.init_with(crate::pairing::PairContext::default)
        };
        // We need real commissioning for this.
        pair_ctx.info.salt[0] = 1;
        pair_ctx.info.salt[1] = 3;
        pair_ctx.info.verifier[0] = 1;
        pair_ctx.info.verifier[1] = 3;

        let mut ctx = HapPeripheralContext::new(
            buffer,
            pair_ctx,
            &server.accessory_information,
            &server.protocol,
            &server.pairing,
        )?;

        let service_signature_req = [0, 6, 0x3a, 0x10, 0];
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
        let payload = [0x00, 0x01, 0xae, 0x20, 0x00];
        // [micro_hap::ble] Writing protocol.service_signature  [0, 1, ae, 2, 2]
        let service_signature_req = pdu::ServiceSignatureReadRequest::parse_pdu(&payload)?;
        let resp = ctx
            .service_signature_request(&service_signature_req)
            .await?;
        // Oh... that's a characteristic signature read request.
        // we need the PDU types, and interpret based on that.
        let _ = resp;

        Ok(())
    }

    #[test]
    fn test_characteristics() {
        init();
        let v = CharacteristicProperties::new()
            .with_read(true)
            .with_read_open(true)
            .with_hidden(true);
        assert_eq!(v.0, 0x0001 | 0x0010 | 0x0040);

        let z = CharacteristicProperties::from_bits(0x03);
        info!("0x03: {z:#?}");
        let z = CharacteristicProperties::from_bits(0x10);
        info!("0x10: {z:#?}");
    }
}
