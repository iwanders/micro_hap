use crate::AccessoryInformationStatic;
use crate::PlatformSupport;
use crate::{characteristic, descriptor, service};
use trouble_host::prelude::*;

pub mod broadcast;
mod pdu;
use crate::{BleProperties, CharacteristicProperties, CharacteristicResponse, DataSource};

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
// changing ids definitely fixed things. Do they need to be 16 aligned on the service start??
// That's what the reference does:
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L18
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

pub mod sig;

use thiserror::Error;

#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct TId(pub u8);

/// Error type representing errors originating from micro_hap's ble interface, these do result in an Err type being
/// propagated to outside of this module.
#[derive(Error, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HapBleError {
    /// Unexpected data length was encountered.
    #[error("unexpected data length encountered")]
    UnexpectedDataLength { expected: usize, actual: usize },
    /// Unexpected request encountered.
    #[error("unexpected request")]
    UnexpectedRequest,
    /// Invalid value
    #[error("invalid value encountered")]
    InvalidValue,
    /// Runtime buffer overrun.
    #[error("runtime buffer overrun")]
    BufferOverrun,
    /// Overrun on allocation space.
    #[error("overrun on allocation space")]
    AllocationOverrun,
    /// Something went wrong with decryption or encryption.
    #[error("encryption or decryption error")]
    EncryptionError,

    // This is less than ideal, we can't put the error in this without losing copy and clone.
    /// A trouble error occured.
    #[error("a trouble error occured")]
    TroubleError(#[from] SimpleTroubleError),
}

#[derive(Error, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SimpleTroubleError {
    /// Out of memory
    #[error("out of memory")]
    OutOfMemory,

    /// Insufficient space in the buffer
    #[error("insufficient space in the buffer")]
    InsufficientSpace,

    /// Some other trouble error that we type erased.
    #[error("catch all for trouble errors")]
    ErasedTroubleError,
}

impl From<trouble_host::Error> for HapBleError {
    fn from(e: trouble_host::Error) -> HapBleError {
        HapBleError::TroubleError(e.into())
    }
}

impl From<trouble_host::Error> for SimpleTroubleError {
    fn from(e: trouble_host::Error) -> SimpleTroubleError {
        match e {
            trouble_host::Error::OutOfMemory => SimpleTroubleError::OutOfMemory,
            trouble_host::Error::InsufficientSpace => SimpleTroubleError::InsufficientSpace,
            _ => SimpleTroubleError::ErasedTroubleError,
        }
    }
}

/// Error type to represent errors encountered because of the client communication. These are translated to
/// a PDU status response and do NOT result in an Err type being propagated.
#[derive(Error, PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum HapBleStatusError {
    /// Unsupported-PDU.
    #[error("unsupported pdu 0x{0:0>2x} encountered")]
    UnsupportedPDU(u8),

    /// Max-Procedures.
    #[error("maximum number of concurrent procedures exceeded")]
    MaxProcedures,

    /// Insufficient Authorization.
    #[error("insufficient authorization")]
    InsufficientAuthorization,

    /// Invalid instance ID.
    #[error("invalid instance id provided 0x{0:0>4x}")]
    InvalidInstanceID(u16),

    /// Insufficient Authentication.
    #[error("insufficient authentication")]
    InsufficientAuthentication,

    /// Invalid Request.
    #[error("invalid request")]
    InvalidRequest,
}

impl From<crate::tlv::TLVError> for HapBleError {
    fn from(e: crate::tlv::TLVError) -> HapBleError {
        match e {
            crate::tlv::TLVError::NotEnoughData => HapBleError::InvalidValue,
            crate::tlv::TLVError::MissingEntry(_) => HapBleError::InvalidValue,
            crate::tlv::TLVError::UnexpectedValue => HapBleError::InvalidValue,
            crate::tlv::TLVError::BufferOverrun => HapBleError::BufferOverrun,
        }
    }
}

impl From<chacha20poly1305::Error> for HapBleError {
    fn from(_: chacha20poly1305::Error) -> HapBleError {
        HapBleError::EncryptionError
    }
}

pub trait HapBleService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError>;
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
    pub manufacturer: FacadeDummyType,

    // 0x21
    /// Manufacturer specific model, length must be greater than one.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=4u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::MODEL, read, write)]
    pub model: FacadeDummyType,

    // 0x0023
    /// Name for the device.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=5u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::NAME, read, write)]
    pub name: FacadeDummyType,

    //0x0030
    /// Manufacturer serial number, length must be greater than one.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=6u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::SERIAL_NUMBER, read, write)]
    pub serial_number: FacadeDummyType,

    //0x0052
    /// Firmware revision string; `<major>.<minor>.<revision>`
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=7u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::FIRMWARE_REVISION, read, write)]
    pub firmware_revision: FacadeDummyType,

    //0x0053
    /// Describes hardware revision string; `<major>.<minor>.<revision>`
    #[characteristic(uuid=characteristic::HARDWARE_REVISION, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=8u16.to_le_bytes())]
    pub hardware_revision: FacadeDummyType,

    // 4ab8811-ac7f-4340-bac3-fd6a85f9943b
    /// ADK version thing from the example,
    #[characteristic(uuid=characteristic::ADK_VERSION, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=9u16.to_le_bytes())]
    pub adk_version: FacadeDummyType,
}

impl HapBleService for AccessoryInformationService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::ACCESSORY_INFORMATION.into(),
            iid: SvcId(1),
            characteristics: Default::default(),
            properties: Default::default(),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::SERVICE_INSTANCE.into(), CharId(1))
                    .with_ble_properties(BleProperties::from_handle(self.service_instance.handle)),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::IDENTIFY.into(), CharId(2))
                    .with_properties(CharacteristicProperties::new().with_write(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.identify.handle)
                            .with_format(sig::Format::Boolean),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::MANUFACTURER.into(), CharId(3))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.manufacturer.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::MODEL.into(), CharId(4))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.model.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::NAME.into(), CharId(5))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.name.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::SERIAL_NUMBER.into(), CharId(6))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.serial_number.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::FIRMWARE_REVISION.into(), CharId(7))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.firmware_revision.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::HARDWARE_REVISION.into(), CharId(8))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.hardware_revision.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::ADK_VERSION.into(), CharId(9))
                    .with_properties(
                        CharacteristicProperties::new()
                            .with_read(true)
                            .with_hidden(true),
                    )
                    .with_ble_properties(
                        BleProperties::from_handle(self.adk_version.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}

pub type FacadeDummyType = [u8; 0];

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
    #[characteristic(uuid=characteristic::VERSION, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x12u16.to_le_bytes())]
    version: FacadeDummyType,
}
impl HapBleService for ProtocolInformationService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::PROTOCOL_INFORMATION.into(),
            iid: SvcId(0x10),
            characteristics: Default::default(),
            properties: crate::ServiceProperties::new().with_configurable(true),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::SERVICE_SIGNATURE.into(), CharId(0x11))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.service_signature.handle)
                            .with_format_opaque(),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::VERSION.into(), CharId(0x12))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.version.handle)
                            .with_format(sig::Format::StringUtf8),
                    )
                    .with_data(crate::DataSource::Constant("2.2.0".as_bytes())),
            )
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

impl HapBleService for PairingService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::PAIRING.into(),
            iid: SvcId(0x20),
            characteristics: Default::default(),
            properties: Default::default(),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::PAIRING_PAIR_SETUP.into(), CharId(0x22))
                    .with_properties(CharacteristicProperties::new().with_open_rw(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.pair_setup.handle).with_format_opaque(),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::PAIRING_PAIR_VERIFY.into(),
                    CharId(0x23),
                )
                .with_properties(CharacteristicProperties::new().with_open_rw(true))
                .with_ble_properties(
                    BleProperties::from_handle(self.pair_verify.handle).with_format_opaque(),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::PAIRING_FEATURES.into(), CharId(0x24))
                    .with_properties(CharacteristicProperties::new().with_read_open(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.features.handle)
                            .with_format(crate::ble::sig::Format::U8),
                    )
                    .with_data(crate::DataSource::Constant(&[0])),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::PAIRING_PAIRINGS.into(), CharId(0x25))
                    .with_properties(CharacteristicProperties::new().with_rw(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.pairings.handle).with_format_opaque(),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
        Ok(service)
    }
}

pub const CHAR_ID_LIGHTBULB_NAME: CharId = CharId(0x32);
pub const CHAR_ID_LIGHTBULB_ON: CharId = CharId(0x33);
#[gatt_service(uuid = service::LIGHTBULB)]
pub struct LightbulbService {
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x04, 0x01])]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x30)]
    pub service_instance: u16,

    /// Service signature, only two bytes.
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=0x31u16.to_le_bytes())]
    pub service_signature: FacadeDummyType,

    // 0x0023
    /// Name for the device.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_LIGHTBULB_NAME.0.to_le_bytes())]
    #[characteristic(uuid=characteristic::NAME, read, write )]
    pub name: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_LIGHTBULB_ON.0.to_le_bytes())]
    #[characteristic(uuid=characteristic::ON, read, write )]
    pub on: FacadeDummyType,
}
impl HapBleService for LightbulbService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::LIGHTBULB.into(),
            iid: SvcId(0x30),
            characteristics: Default::default(),
            properties: crate::ServiceProperties::new().with_primary(true),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::SERVICE_SIGNATURE.into(),
                    CharId(0x31u16),
                )
                .with_properties(CharacteristicProperties::new().with_read(true))
                .with_ble_properties(
                    BleProperties::from_handle(self.service_signature.handle).with_format_opaque(),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::NAME.into(), CharId(0x32u16))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.name.handle)
                            .with_format(sig::Format::StringUtf8),
                    )
                    .with_data(DataSource::AccessoryInterface),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::ON.into(), CharId(0x33u16))
                    .with_properties(
                        CharacteristicProperties::new()
                            .with_rw(true)
                            .with_supports_event_notification(true)
                            .with_supports_disconnect_notification(true)
                            .with_supports_broadcast_notification(true),
                    )
                    .with_ble_properties(
                        BleProperties::from_handle(self.on.handle)
                            .with_format(sig::Format::Boolean),
                    )
                    .with_data(DataSource::AccessoryInterface),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}

/// Simple helper struct that's used to capture input to the gatt event handler.
pub struct HapServices<'a> {
    pub information: &'a AccessoryInformationService,
    pub protocol: &'a ProtocolInformationService,
    pub pairing: &'a PairingService,
}

use pdu::{BleTLVType, BodyBuilder, ParsePdu, WriteIntoLength};

#[derive(Debug)]
struct Reply {
    payload: BufferResponse,
    handle: u16,
}
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct BufferResponse(pub usize);

#[derive(Debug)]
pub struct HapPeripheralContext {
    //protocol_service_properties: ServiceProperties,
    buffer: core::cell::RefCell<&'static mut [u8]>,
    pair_ctx: core::cell::RefCell<&'static mut crate::pairing::PairContext>,

    prepared_reply: Option<Reply>,
    should_encrypt_reply: bool,

    information_service: crate::Service,
    protocol_service: crate::Service,
    pairing_service: crate::Service,

    user_services: heapless::Vec<crate::Service, 8>,
}
impl HapPeripheralContext {
    fn services(&self) -> impl Iterator<Item = &crate::Service> {
        [
            &self.information_service,
            &self.protocol_service,
            &self.pairing_service,
        ]
        .into_iter()
        .chain(self.user_services.iter())
    }
    fn services_mut(&mut self) -> impl Iterator<Item = &mut crate::Service> {
        [
            &mut self.information_service,
            &mut self.protocol_service,
            &mut self.pairing_service,
        ]
        .into_iter()
        .chain(self.user_services.iter_mut())
    }

    pub fn get_attribute_by_char(&self, chr: CharId) -> Option<&crate::Characteristic> {
        for s in self.services() {
            if let Some(a) = s.get_characteristic_by_iid(chr) {
                return Some(a);
            }
        }
        None
    }

    pub fn get_service_by_char(&self, chr: CharId) -> Option<&crate::Service> {
        for s in self.services() {
            if let Some(_attribute) = s.get_characteristic_by_iid(chr) {
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
    pub fn get_service_by_uuid_mut(
        &mut self,
        srv: &crate::uuid::Uuid,
    ) -> Option<&mut crate::Service> {
        for s in self.services_mut() {
            if &s.uuid == srv {
                return Some(s);
            }
        }
        None
    }

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
            should_encrypt_reply: false,
            information_service: information_service.populate_support()?,
            protocol_service: protocol_service.populate_support()?,
            pairing_service: pairing_service.populate_support()?,
            user_services: Default::default(),
        })
    }

    pub fn assign_static_data(&mut self, data: &AccessoryInformationStatic) {
        use crate::{characteristic, service};

        if let Some(ref mut svc) =
            self.get_service_by_uuid_mut(&service::ACCESSORY_INFORMATION.into())
        {
            svc.get_characteristic_by_uuid_mut(&characteristic::FIRMWARE_REVISION.into())
                .unwrap()
                .set_data(DataSource::Constant(data.firmware_revision.as_bytes()));
            svc.get_characteristic_by_uuid_mut(&characteristic::HARDWARE_REVISION.into())
                .unwrap()
                .set_data(DataSource::Constant(data.hardware_revision.as_bytes()));
            svc.get_characteristic_by_uuid_mut(&characteristic::MANUFACTURER.into())
                .unwrap()
                .set_data(DataSource::Constant(data.manufacturer.as_bytes()));
            svc.get_characteristic_by_uuid_mut(&characteristic::MODEL.into())
                .unwrap()
                .set_data(DataSource::Constant(data.model.as_bytes()));
            svc.get_characteristic_by_uuid_mut(&characteristic::SERIAL_NUMBER.into())
                .unwrap()
                .set_data(DataSource::Constant(data.serial_number.as_bytes()));
            svc.get_characteristic_by_uuid_mut(&characteristic::NAME.into())
                .unwrap()
                .set_data(DataSource::Constant(data.name.as_bytes()));
        }
    }

    pub fn add_service(&mut self, srv: &impl HapBleService) -> Result<(), HapBleError> {
        self.user_services
            .push(srv.populate_support()?)
            .map_err(|_| HapBleError::AllocationOverrun)?;
        Ok(())
    }

    pub fn print_handles(&self) {
        for k in self.services() {
            for a in k.characteristics.iter() {
                let attr_id = a.iid;
                let handle = a.ble_ref().handle;
                let uuid = &a.uuid;
                info!("iid  {:?}, handle:  {:?}  uid: {:?}", attr_id, handle, uuid);
            }
        }
    }

    pub async fn service_signature_request(
        &mut self,
        req: &pdu::ServiceSignatureReadRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L249

        info!("service signature req: {:?}", req);
        let resp = req.header.to_success();

        let req_svc = req.svc_id;

        let mut buffer = self.buffer.borrow_mut();

        let len = resp.write_into_length(*buffer)?;

        let svc = self.get_service_by_svc(req_svc);

        if let Some(svc) = svc {
            let len = BodyBuilder::new_at(*buffer, len)
                .add_u16(BleTLVType::HAPServiceProperties, svc.properties.0)
                .add_u16s(BleTLVType::HAPLinkedServices, &[])
                .end();

            Ok(BufferResponse(len))
        } else {
            // What do we return if the id is not known??
            error!("Could not find service for req.svc_id: 0x{:02?}", req_svc);
            todo!()
        }
    }
    pub async fn characteristic_signature_request(
        &mut self,
        req: &pdu::CharacteristicSignatureReadRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L289

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
                .add_characteristic_properties(chr.properties)
                // .add_optional_user_description(&chr.user_description)
                .add_format(&chr.ble_ref().format)
                .add_range(&chr.range)
                .add_step(&chr.step)
                // NONCOMPLIANCE: valid values.
                .end();

            Ok(BufferResponse(len))
        } else {
            todo!()
        }
    }

    pub async fn characteristic_read_request(
        &mut self,
        accessory: &impl crate::AccessoryInterface,
        req: &pdu::CharacteristicReadRequest,
    ) -> Result<BufferResponse, HapBleError> {
        // Well ehm, what do we do here?
        let char_id = req.char_id; // its unaligned, so copy it before we use it.
        use crate::DataSource;
        if let Some(chr) = self.get_attribute_by_char(char_id) {
            match chr.data_source {
                DataSource::Nop => {
                    error!("Got NOP data on char_id: {:?}", char_id);
                    Ok(BufferResponse(0))
                }
                DataSource::AccessoryInterface => {
                    if let Some(data) = accessory.read_characteristic(char_id).await {
                        let mut buffer = self.buffer.borrow_mut();
                        let reply = req.header.to_success();
                        let len = reply.write_into_length(*buffer)?;
                        let len = BodyBuilder::new_at(*buffer, len)
                            .add_value(data.into())
                            .end();
                        Ok(BufferResponse(len))
                    } else {
                        error!(
                            "Characteristic is using interface data source, but it returned None; {:?}",
                            char_id
                        );
                        Ok(BufferResponse(0))
                    }
                }
                DataSource::Constant(data) => {
                    let mut buffer = self.buffer.borrow_mut();
                    let reply = req.header.to_success();
                    let len = reply.write_into_length(*buffer)?;
                    let len = BodyBuilder::new_at(*buffer, len).add_value(data).end();
                    Ok(BufferResponse(len))
                }
            }
        } else {
            error!("Got read for unknown characteristic: {:?}", char_id);
            todo!();
        }
    }

    pub async fn characteristic_write_request(
        &mut self,
        pair_support: &mut impl PlatformSupport,
        accessory: &mut impl crate::AccessoryInterface,
        req: &pdu::CharacteristicWriteRequest<'_>,
    ) -> Result<BufferResponse, HapBleError> {
        let parsed = req;
        // Write the body to our internal buffer here.
        let mut buffer = self.buffer.borrow_mut();
        buffer.fill(0);

        let halfway = buffer.len() / 2;
        let (left_buffer, outgoing) = buffer.split_at_mut(halfway);
        let body_length = parsed.copy_body(left_buffer)?;
        let mut pair_ctx = self.pair_ctx.borrow_mut();

        // So now we craft the reply, technically this could happen on the read... should it happen on the read?
        //
        let char_id = req.header.char_id;
        if let Some(chr) = self.get_attribute_by_char(char_id) {
            let is_pair_setup = chr.uuid == characteristic::PAIRING_PAIR_SETUP.into();
            let is_pair_verify = chr.uuid == characteristic::PAIRING_PAIR_VERIFY.into();
            let incoming_data = &left_buffer[0..body_length];
            // let (first_half, mut second_half) = buffer.split_at_mut(full_len / 2);
            if is_pair_setup {
                info!("pair setup at incoming");
                crate::pairing::pair_setup_handle_incoming(
                    &mut **pair_ctx,
                    pair_support,
                    incoming_data,
                )
                .await
                .map_err(|_| HapBleError::InvalidValue)?;

                info!("pair setup at outgoing");
                // Put the reply in the second half.
                let outgoing_len = crate::pairing::pair_setup_handle_outgoing(
                    &mut **pair_ctx,
                    pair_support,
                    outgoing,
                )
                .await
                .map_err(|_| HapBleError::InvalidValue)?;

                info!("Populatig the body.");

                let reply = parsed.header.header.to_success();
                let len = reply.write_into_length(left_buffer)?;

                let len = BodyBuilder::new_at(left_buffer, len)
                    .add_value(&outgoing[0..outgoing_len])
                    .end();

                info!("Done, len: {}", len);
                Ok(BufferResponse(len))
            } else if is_pair_verify {
                crate::pair_verify::handle_incoming(&mut **pair_ctx, pair_support, incoming_data)
                    .await
                    .map_err(|_| HapBleError::InvalidValue)?;

                // Put the reply in the second half.
                let outgoing_len =
                    crate::pair_verify::handle_outgoing(&mut **pair_ctx, pair_support, outgoing)
                        .await
                        .map_err(|_| HapBleError::InvalidValue)?;

                let reply = parsed.header.header.to_success();
                let len = reply.write_into_length(left_buffer)?;

                let len = BodyBuilder::new_at(left_buffer, len)
                    .add_value(&outgoing[0..outgoing_len])
                    .end();

                Ok(BufferResponse(len))
            } else {
                match chr.data_source {
                    DataSource::Nop => {
                        let reply = parsed.header.header.to_success();
                        let len = reply.write_into_length(left_buffer)?;
                        Ok(BufferResponse(len))
                    }
                    DataSource::AccessoryInterface => {
                        let r = accessory
                            .write_characteristic(char_id, incoming_data)
                            .await
                            .map_err(|_| HapBleError::UnexpectedRequest)?;

                        if r == CharacteristicResponse::Modified {
                            // Do things to this characteristic to mark it dirty.
                            error!(
                                "Should mark the characteristic dirty and advance the global state number, and notify!"
                            );
                            let _ = pair_support
                                .advance_global_state_number()
                                .await
                                .map_err(|_| HapBleError::InvalidValue)?;
                        }

                        let reply = parsed.header.header.to_success();
                        let len = reply.write_into_length(left_buffer)?;
                        Ok(BufferResponse(len))
                    }
                    DataSource::Constant(_data) => {
                        unimplemented!("a constant data source should not be writable")
                    }
                }
            }
        } else {
            // Unknown characteristic, how do we handle this?
            todo!()
        }
    }

    #[allow(unreachable_code)]
    pub async fn info_request(
        &mut self,
        req: &pdu::InfoRequest,
    ) -> Result<BufferResponse, HapBleError> {
        let _ = req;
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessory%2BInfo.c#L71
        // This is a blind attempt at implementing this request based on the reference.
        // I needed this when I set the software authentication bit, but it seems that the reference doesn't actually
        // use that code path, so putting a todo here to ensure we fail hard.
        todo!("this needs checking against the reference");
        let char_id = req.char_id; // its unaligned, so copy it before we use it.
        if let Some(chr) = self.get_attribute_by_char(char_id) {
            if chr.uuid == crate::characteristic::SERVICE_SIGNATURE.into() {
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
                    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessoryServer.c#L1058
                    .add_u8(pdu::InfoResponseTLVType::ConfigNumber, 1)
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
                    .add_u8(pdu::InfoResponseTLVType::StatusFlag, 0)
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

    // https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEProtocol%2BConfiguration.c#L29
    pub async fn protocol_configure_request(
        &mut self,
        pair_support: &mut impl PlatformSupport,
        req: &pdu::ProtocolConfigurationRequestHeader,
        payload: &[u8],
    ) -> Result<BufferResponse, HapBleError> {
        let _ = req;
        let svc_id = req.svc_id; // its unaligned, so copy it before we use it.
        if let Some(svc) = self.get_service_by_svc(svc_id) {
            if !svc.properties.configurable() {
                return Err(HapBleError::UnexpectedRequest);
            }

            let mut buffer = self.buffer.borrow_mut();
            let reply = req.header.to_success();
            let len = reply.write_into_length(*buffer)?;

            let mut generate_key: bool = false;
            let mut get_all: bool = false;
            let mut have_advertising_id: bool = false;

            // This TLV stuff has zero lengths, which the reader (AND the reference?) considers invalid.
            let mut reader = crate::tlv::TLVReader::new(&payload);
            while let Some(z) = reader.next_segment_allow_zero() {
                let z = z?;
                if z.type_id == pdu::ProtocolConfigurationRequestTLVType::GetAllParams as u8 {
                    get_all = true;
                } else if z.type_id
                    == pdu::ProtocolConfigurationRequestTLVType::GenerateBroadcastEncryptionKey
                        as u8
                {
                    generate_key = true;
                } else if z.type_id
                    == pdu::ProtocolConfigurationRequestTLVType::SetAccessoryAdvertisingIdentifier
                        as u8
                {
                    have_advertising_id = true;
                } else {
                    todo!("unhandled protocol configuration type id: {}", z.type_id);
                }
            }

            if have_advertising_id {
                todo!();
            }
            if generate_key {
                // https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEAccessoryServer%2BBroadcast.c#L98-L100
                let mut ctx = self.pair_ctx.borrow_mut();
                broadcast::broadcast_generate_key(&mut *ctx, pair_support)
                    .await
                    .map_err(|_| HapBleError::InvalidValue)?;
            }

            if !get_all {
                // https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEProcedure.c#L155
                error!("untested, seems this just returns success?");
                return Ok(BufferResponse(len));
            }

            // That was the request... next is creating the response.
            // https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEProtocol%2BConfiguration.c#L132

            // Basically, we just write values here.
            //
            let global_state_number = pair_support
                .get_global_state_number()
                .await
                .map_err(|_e| HapBleError::InvalidValue)?;

            // This is odd, they write the configuration number as a single byte!
            let config_number = pair_support
                .get_config_number()
                .await
                .map_err(|_e| HapBleError::InvalidValue)? as u8;
            let parameters = pair_support
                .get_ble_broadcast_parameters()
                .await
                .map_err(|_e| HapBleError::InvalidValue)?;

            let mut builder = BodyBuilder::new_at(*buffer, len)
                .add_slice(
                    pdu::ProtocolConfigurationTLVType::CurrentStateNumber,
                    &global_state_number.to_le_bytes(),
                )
                .add_slice(
                    pdu::ProtocolConfigurationTLVType::CurrentConfigNumber,
                    &config_number.to_le_bytes(),
                );
            if let Some(advertising_id) = parameters.advertising_id {
                builder = builder.add_slice(
                    pdu::ProtocolConfigurationTLVType::AccessoryAdvertisingIdentifier,
                    &advertising_id.0,
                );
            }
            builder = builder.add_slice(
                pdu::ProtocolConfigurationTLVType::BroadcastEncryptionKey,
                parameters.key.as_ref().as_bytes(),
            );
            let len = builder.end();
            Ok(BufferResponse(len))
        } else {
            error!("Got protocol configure on unknown service: {:?}", svc_id);
            return Err(HapBleError::UnexpectedRequest);
        }
    }

    async fn reply_read_payload<'stack, P: trouble_host::PacketPool>(
        data: &[u8],
        event: ReadEvent<'stack, '_, P>,
    ) -> Result<(), trouble_host::Error> {
        let reply = trouble_host::att::AttRsp::Read { data: &data };

        event.into_payload().reply(reply).await?;
        Ok(())
    }

    fn get_response(&self, reply: BufferResponse) -> core::cell::Ref<'_, [u8]> {
        core::cell::Ref::<'_, &'static mut [u8]>::map(self.buffer.borrow(), |z| &z[0..reply.0])
    }

    pub fn encrypted_reply(
        &mut self,
        value: BufferResponse,
    ) -> Result<BufferResponse, HapBleError> {
        let should_encrypt = self.should_encrypt_reply;
        if should_encrypt {
            // Perform the encryption, then respond with the buffer that is encrypted.
            let mut ctx = self.pair_ctx.borrow_mut();
            let mut buff = self.buffer.borrow_mut();
            info!("Encrypting reply: {:?}", &buff[0..value.0]);

            let res = ctx.session.a_to_c.encrypt(&mut **buff, value.0)?;
            info!("Encrypted reply: {:?}", &res);

            Ok(BufferResponse(res.len()))
        } else {
            Ok(value)
        }
    }

    pub async fn handle_read_outgoing(
        &mut self,
        handle: u16,
    ) -> Result<Option<core::cell::Ref<'_, [u8]>>, HapBleError> {
        if self.prepared_reply.as_ref().map(|e| e.handle) == Some(handle) {
            let reply = self.prepared_reply.take().unwrap();
            // Ensure that we send the encrypted data!
            let buffered_response = self.encrypted_reply(reply.payload)?;
            Ok(Some(self.get_response(buffered_response)))
        } else {
            Ok(None)
        }
    }

    pub async fn handle_write_incoming<'hap, 'support>(
        &mut self,
        hap: &HapServices<'hap>,
        pair_support: &mut impl PlatformSupport,
        accessory: &mut impl crate::AccessoryInterface,
        data: &[u8],
        handle: u16,
    ) -> Result<Option<BufferResponse>, HapBleError> {
        let security_active = self.pair_ctx.borrow().session.security_active;
        self.should_encrypt_reply = security_active;
        let mut tmp_buffer = [0u8; 1024];
        let data = if security_active {
            if handle == hap.pairing.pair_verify.handle {
                // pair verify is always plaintext!
                self.should_encrypt_reply = false;
                data
            } else {
                warn!("handle_write_incoming raw {:?}", data);
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
            }
        } else {
            data
        };
        warn!("handle_write_incoming {:?}", data);

        let header = pdu::RequestHeader::parse_pdu(data)?;
        warn!("Write header {:?}", header);

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
                self.characteristic_read_request(accessory, &req).await?
            }
            pdu::OpCode::CharacteristicWrite => {
                info!("handle is: {}", handle);
                info!("pair setup handle is {}", hap.pairing.pair_setup.handle);
                info!("write raw req event data: {:?}", data);
                let parsed = pdu::CharacteristicWriteRequest::parse_pdu(data)?;
                info!("got write on pair setup with: {:?}", parsed);

                self.characteristic_write_request(pair_support, accessory, &parsed)
                    .await?
            }
            pdu::OpCode::Info => {
                // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L623
                // we don't have this in the recording?!?
                if !security_active {
                    //return Err(HapBleError::EncryptionError);
                }
                let req = pdu::InfoRequest::parse_pdu(data)?;
                info!("Info req: {:?}", req);
                self.info_request(&req).await?
            }
            pdu::OpCode::ProtocolConfiguration => {
                // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L404
                if !security_active {
                    // Nope...
                    return Err(HapBleError::EncryptionError);
                }
                // Well ehm, what do we do here?
                let (req, payload) =
                    pdu::ProtocolConfigurationRequestHeader::parse_pdu_with_remainder(data)?;
                // let remainder = data[req.body_length];
                info!("Info req: {:?}", req);
                self.protocol_configure_request(pair_support, &req, payload)
                    .await?
            }
            pdu::OpCode::CharacteristicConfiguration => {
                // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L336
                info!("CharacteristicConfiguration req: {:?}", data);
                if !security_active {
                    // Nope...
                    return Err(HapBleError::EncryptionError);
                }

                let req = pdu::CharacteristicConfigurationRequest::parse_pdu(data)?;
                info!("CharacteristicConfiguration req: {:?}", req);

                let interval = req.broadcast_interval.unwrap_or_default();

                let broadcast_enabled = if let Some(broadcast_value) = req.broadcast_enabled {
                    // Enabled broadcasts at the provided interval.
                    {
                        let chr = self
                            .get_attribute_by_char(req.char_id)
                            .ok_or(HapBleError::InvalidValue)?;
                        if !chr.properties.supports_broadcast_notification() {
                            error!(
                                "setting broadcast for something that doesn't support broadcast notify"
                            );
                            return Err(HapBleError::InvalidValue);
                        }
                    }

                    broadcast::configure_broadcast_notification(
                        broadcast_value,
                        interval,
                        req.char_id,
                    )?;
                    broadcast_value
                } else {
                    // Do nothing?

                    broadcast::configure_broadcast_notification(
                        false,
                        Default::default(),
                        req.char_id,
                    )?;
                    false
                };
                // HAPBLECharacteristicGetConfigurationResponse
                // https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLECharacteristic%2BConfiguration.c#L172C10-L172C54
                let _attr = self
                    .get_attribute_by_char(req.char_id)
                    .ok_or(HapBleError::InvalidValue)?;
                // NONCOMPLIANCE; probably need to store the interval & properties into the attribute?

                let mut buffer = self.buffer.borrow_mut();
                let reply = req.header.to_success();
                let len = reply.write_into_length(*buffer)?;

                let len = BodyBuilder::new_at(&mut buffer, len)
                    .add_slice(
                        pdu::BleBroadcastTLV::BroadcastInterval as u8,
                        interval.as_bytes(),
                    )
                    .add_slice(
                        pdu::BleBroadcastTLV::Properties as u8,
                        (broadcast_enabled as u16).as_bytes(),
                    )
                    .end();

                BufferResponse(len)
            }
            _ => {
                return {
                    error!("Failed to handle: {:?}", header);
                    todo!("need to implement this request type")
                    //Err(HapBleError::UnexpectedRequest.into())
                };
            }
        };
        Ok(Some(resp))
    }

    #[cfg(test)]
    // helper function to store the reply into the prepared reply.
    async fn handle_write_incoming_test<'hap, 'support>(
        &mut self,
        hap: &HapServices<'hap>,
        pair_support: &mut impl crate::PlatformSupport,
        accessory: &mut impl crate::AccessoryInterface,
        data: &[u8],
        handle: u16,
    ) -> Result<Option<BufferResponse>, HapBleError> {
        let resp = self.handle_write_incoming(hap, pair_support, accessory, &data, handle);

        info!("pair verify handle: {:?}", hap.pairing.pair_verify.handle());
        if let Some(resp) = resp.await? {
            self.prepared_reply = Some(Reply {
                payload: resp,
                handle: handle,
            });
            Ok(Some(resp))
        } else {
            panic!("testing something unhandled?")
        }
    }

    pub async fn process_gatt_event<'stack, 'server, 'hap, 'support, P: PacketPool>(
        &mut self,
        hap: &HapServices<'hap>,
        pair_support: &mut impl crate::PlatformSupport,
        accessory: &mut impl crate::AccessoryInterface,
        event: trouble_host::gatt::GattEvent<'stack, 'server, P>,
    ) -> Result<Option<trouble_host::gatt::GattEvent<'stack, 'server, P>>, HapBleError> {
        // we seem to miss 'read by type' requests on handlex 0x0010 - 0x0012

        match event {
            GattEvent::Read(event) => {
                /*
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
                */

                let outgoing = self.handle_read_outgoing(event.handle()).await;
                match outgoing {
                    Ok(v) => {
                        if let Some(buffer_thing) = v {
                            Self::reply_read_payload(&*buffer_thing, event).await?;

                            return Ok(None);
                        } else {
                            Ok(Some(GattEvent::Read(event)))
                        }
                    }
                    Err(e) => {
                        warn!("Error reading outgoing, dropping request: {:?}", e);
                        return Ok(None);
                    }
                }
            }
            GattEvent::Write(event) => {
                /*
                warn!("Raw write data {:?}", event.data());

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
                    warn!("Writing protocol.service_signature  {:?}", event.data());
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
                */

                let resp = self
                    .handle_write_incoming(
                        hap,
                        pair_support,
                        accessory,
                        &event.data(),
                        event.handle(),
                    )
                    .await;

                match resp {
                    Ok(v) => {
                        if let Some(v) = v {
                            self.prepared_reply = Some(Reply {
                                payload: v,
                                handle: event.handle(),
                            });

                            let reply = trouble_host::att::AttRsp::Write;
                            event.into_payload().reply(reply).await?;
                            return Ok(None);
                        } else {
                            todo!("unhandled event");
                        }
                    }
                    Err(e) => {
                        warn!("Error handling incoming, dropping request: {:?}", e);
                        return Ok(None);
                    }
                }
            }
            remainder => Ok(Some(remainder)),
        }
    }
}

#[cfg(test)]
mod test;
