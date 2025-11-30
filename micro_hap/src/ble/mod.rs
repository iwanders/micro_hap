use crate::AccessoryInformationStatic;
use crate::HapEvent;
use crate::InterfaceError;
use crate::PlatformSupport;
use crate::characteristic;
use embassy_sync::blocking_mutex::raw::RawMutex;
use trouble_host::prelude::*;

pub mod advertisement;
pub mod broadcast;
mod pdu;
use crate::{CharacteristicProperties, CharacteristicResponse, DataSource};

use crate::pairing::PairingError;
use crate::{AccessoryContext, CharId, SvcId};
use embassy_futures::select::select;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

pub use pdu::BleBroadcastInterval;
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

pub mod services;
pub mod sig;
pub use services::*;
use thiserror::Error;
mod advertise_manager;
use pdu::{BleTLVType, BodyBuilder, ParsePdu, WriteIntoLength};

#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct TId(pub u8);

/// Time To Live, expressed in multiples of 100ms.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, Default)]
pub struct Ttl(u8);
impl Ttl {
    pub fn to_millis(&self) -> u64 {
        self.0 as u64 * 100
    }
}

/// Error type representing errors originating from micro_hap's ble interface, these do result in an Err type being
/// propagated to outside of this module.
#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HapBleError {
    /// Runtime buffer overrun, this happens if the request and reply did not fit into the internal buffer.
    #[error("runtime buffer overrun")]
    BufferOverrun,
    /// Overrun on allocation space, this happens if the fixed size arrays can't hold the information passed to it
    /// usually a start-up situation.
    #[error("overrun on allocation space")]
    AllocationOverrun,

    /// The accessory interface created an error that should be propagated.
    #[error("an error from the accessory interface")]
    InterfaceError(#[from] InterfaceError),

    // This is less than ideal, we can't put the error in this without losing Copy and clone.
    /// A trouble error occured.
    #[error("a trouble error occured")]
    TroubleError(#[from] SimpleTroubleError),

    /// A special handle was not populated, like pair_verify.
    #[error("a special handle was not populated")]
    SpecialHandleError,
}

/// Limited simplified trouble errors that are copy/clone.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
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

    /// Something went wrong while advertising.
    #[error("a failure occured in the advertise call")]
    FailureInAdvertise,
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
enum HapBleStatusError {
    /// Unsupported-PDU.
    #[error("unsupported pdu  encountered")]
    UnsupportedPDU,

    #[allow(dead_code)]
    // This one is currently unused... how do we get this? Is it when we do two requests without a read?
    // NONCOMPLIANCE
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
impl HapBleStatusError {
    pub fn invalid_iid_to_hap_ble_error(self) -> HapBleError {
        match self {
            HapBleStatusError::InvalidInstanceID(z) => {
                HapBleError::InterfaceError(InterfaceError::CharacteristicUnknown(CharId(z)))
            }
            _ => todo!(),
        }
    }
}

/// A enum to capture all errors possibly encountered internally. This is used to provide high quality logging
/// but does not actually end up in the public api of the crate.
#[derive(Error, PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
enum InternalError {
    #[error("tlv error encountered")]
    TLVError(#[from] crate::tlv::TLVError),
    #[error("status error")]
    StatusError(#[from] HapBleStatusError),
    #[error("pairing error")]
    PairError(#[from] PairingError),
    /// An error occured that should be propagated through to the callsite.
    #[error("a to be propagated error")]
    HapBleError(#[from] HapBleError),
}

impl InternalError {
    fn to_status_error(&self) -> HapBleStatusError {
        match self {
            InternalError::TLVError(_tlverror) => HapBleStatusError::InvalidRequest,
            InternalError::StatusError(hap_ble_status_error) => *hap_ble_status_error,
            InternalError::PairError(pairing_error) => match pairing_error {
                // NONCOMPLIANCE No idea if this is the correct mapping... should go through the C code.
                crate::pairing::PairingError::TLVError(_) => HapBleStatusError::InvalidRequest,
                crate::pairing::PairingError::IncorrectMethodCombination => {
                    HapBleStatusError::InvalidRequest
                }
                crate::pairing::PairingError::IncorrectState => HapBleStatusError::InvalidRequest,
                crate::pairing::PairingError::IncorrectLength => HapBleStatusError::InvalidRequest,
                crate::pairing::PairingError::BadPublicKey => HapBleStatusError::InvalidRequest,
                crate::pairing::PairingError::BadProof => HapBleStatusError::InvalidRequest,
                crate::pairing::PairingError::BadDecryption => {
                    HapBleStatusError::InsufficientAuthorization
                }
                crate::pairing::PairingError::BadSignature => HapBleStatusError::InvalidRequest,
                crate::pairing::PairingError::UuidError => HapBleStatusError::InvalidRequest,
                crate::pairing::PairingError::UnknownPairing => {
                    HapBleStatusError::InsufficientAuthorization
                }
                crate::pairing::PairingError::InterfaceError(_) => {
                    unimplemented!()
                }
                // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/PAL/Darwin/HAPPlatformBLEPeripheralManager.m#L446
                crate::pairing::PairingError::InvalidData => HapBleStatusError::UnsupportedPDU,
                crate::pairing::PairingError::AuthenticationError => {
                    HapBleStatusError::InsufficientAuthentication
                }
            },
            InternalError::HapBleError(_hap_ble_error) => unimplemented!(),
        }
    }
}

impl From<InterfaceError> for InternalError {
    fn from(e: InterfaceError) -> InternalError {
        InternalError::HapBleError(e.into())
    }
}
pub trait HapBleService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError>;
}

/// Simple helper struct that's used to capture input to the gatt event handler.
pub struct HapServices<'a> {
    pub pairing: &'a PairingService,
}

#[derive(Debug)]
struct Reply {
    payload: BufferResponse,
    handle: u16,
}
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct BufferResponse(pub usize);

#[derive(Debug, Copy, Clone)]
pub struct TimedWrite {
    pub char_id: CharId,
    pub time_start: embassy_time::Instant,
    pub ttl: Ttl,
    pub data_length: usize,
    // Not putting data here because that makes the initialisation of an array of this type very hard.
    // pub data: &'static mut [u8],
}

#[derive(Debug, Copy, Clone)]
struct TimedWriteSlot(usize);

#[derive(Debug)]
pub struct HapPeripheralContext<'c> {
    //protocol_service_properties: ServiceProperties,
    out_buffer: core::cell::RefCell<&'static mut [u8]>,
    in_buffer: core::cell::RefCell<&'static mut [u8]>,
    pair_ctx: core::cell::RefCell<&'static mut AccessoryContext>,

    timed_write_slot_buffer: usize,
    timed_write_data: core::cell::RefCell<&'static mut [u8]>,
    timed_write: core::cell::RefCell<&'static mut [Option<TimedWrite>]>,

    prepared_reply: Option<Reply>,
    should_encrypt_reply: core::cell::Cell<bool>,

    services: heapless::Vec<crate::Service, 8>,

    control_receiver: crate::HapInterfaceReceiver<'c>,

    /// Track if the HAP session went active, this mirrors the session's security_active boolean, but is used for the handling
    /// of state and resetting the advanced_gsn flag.
    session_active: core::cell::Cell<bool>,

    advertise_manager: core::cell::RefCell<advertise_manager::AdvertiseManager>,
}
impl<'c> HapPeripheralContext<'c> {
    fn services(&self) -> impl Iterator<Item = &crate::Service> {
        self.services.iter()
    }
    fn services_mut(&mut self) -> impl Iterator<Item = &mut crate::Service> {
        self.services.iter_mut()
    }

    fn get_attribute_by_char(
        &self,
        chr: CharId,
    ) -> Result<&crate::Characteristic, HapBleStatusError> {
        for s in self.services() {
            if let Some(a) = s.get_characteristic_by_iid(chr) {
                return Ok(a);
            }
        }
        Err(HapBleStatusError::InvalidInstanceID(chr.0))
    }

    // TODO; migrate all the services to something nice that collects the actual gatt characteristics.
    pub fn ugly_todo_inject_trouble_characteristic(
        &mut self,
        chr: CharId,
        character: Characteristic<FacadeDummyType>,
    ) {
        for s in self.services_mut() {
            if let Some(a) = s.get_characteristic_by_iid_mut(chr) {
                a.ble_mut().characteristic = Some(character);
                return;
            }
        }
        panic!("could not find iid to inject into");
    }

    fn get_service_by_char(&self, chr: CharId) -> Result<&crate::Service, HapBleStatusError> {
        for s in self.services() {
            if let Some(_attribute) = s.get_characteristic_by_iid(chr) {
                return Ok(s);
            }
        }
        Err(HapBleStatusError::InvalidInstanceID(chr.0))
    }

    fn get_service_by_svc(&self, srv: SvcId) -> Result<&crate::Service, HapBleStatusError> {
        for s in self.services() {
            if s.iid == srv {
                return Ok(s);
            }
        }
        Err(HapBleStatusError::InvalidInstanceID(srv.0))
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
    pub fn get_service_by_uuid(&self, srv: &crate::uuid::Uuid) -> Option<&crate::Service> {
        for s in self.services() {
            if &s.uuid == srv {
                return Some(s);
            }
        }
        None
    }

    fn should_reply_to_ble_handle(&self, handle: u16) -> bool {
        for s in self.services() {
            if Some(handle) == s.ble_handle {
                return true;
            }
            for c in s.characteristics.iter() {
                if let Some(prop) = c.ble.as_ref() {
                    if prop.handle == handle {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn get_timed_write_slot_index(&self, key: Option<CharId>) -> Option<TimedWriteSlot> {
        let v = self.timed_write.borrow();
        v.iter()
            .position(|s| {
                if let Some(search_char) = &key {
                    if let Some(s) = s {
                        s.char_id == *search_char
                    } else {
                        false
                    }
                } else {
                    // Searching for an empty slot
                    s.is_none()
                }
            })
            .map(|v| TimedWriteSlot(v))
    }
    fn get_timed_write_slot(
        &self,
        slot: TimedWriteSlot,
    ) -> core::cell::RefMut<'_, Option<TimedWrite>> {
        core::cell::RefMut::<'_, &'static mut [Option<TimedWrite>]>::map(
            self.timed_write.borrow_mut(),
            |z| z.get_mut(slot.0).unwrap(),
        )
    }

    fn get_timed_write_data(&self, slot: TimedWriteSlot) -> core::cell::RefMut<'_, [u8]> {
        let start = self.timed_write_slot_buffer * slot.0;
        let end = self.timed_write_slot_buffer * (slot.0 + 1);
        core::cell::RefMut::<'_, &'static mut [u8]>::map(self.timed_write_data.borrow_mut(), |z| {
            &mut z[start..end]
        })
    }
    fn timed_write_prune(&self, current_time: embassy_time::Instant) {
        let mut prune_index = None;
        loop {
            for (i, v) in self.timed_write.borrow().iter().enumerate() {
                if let Some(v) = v {
                    let expire_time =
                        v.time_start + embassy_time::Duration::from_millis(v.ttl.to_millis());
                    if current_time > expire_time {
                        prune_index = Some(i)
                    }
                }
            }

            if let Some(to_remove) = prune_index.take() {
                for (i, v) in self.timed_write.borrow_mut().iter_mut().enumerate() {
                    if to_remove == i {
                        *v = None;
                    }
                }
            }

            break;
        }
    }

    pub fn new(
        out_buffer: &'static mut [u8],
        in_buffer: &'static mut [u8],
        pair_ctx: &'static mut AccessoryContext,
        timed_write_data: &'static mut [u8],
        timed_write: &'static mut [Option<TimedWrite>],
        control_receiver: crate::HapInterfaceReceiver<'c>,
    ) -> Result<Self, HapBleError> {
        let timed_write_slot_buffer = timed_write_data.len() / timed_write.len();
        let advertise_manager = advertise_manager::AdvertiseManager::startup();
        Ok(Self {
            //protocol_service_properties: Default::default(),
            out_buffer: out_buffer.into(),
            in_buffer: in_buffer.into(),
            pair_ctx: pair_ctx.into(),
            timed_write_slot_buffer,
            timed_write_data: timed_write_data.into(),
            timed_write: timed_write.into(),
            prepared_reply: None,
            should_encrypt_reply: false.into(),
            services: Default::default(),

            advertise_manager: advertise_manager.into(),
            session_active: false.into(),
            control_receiver,
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

    pub fn add_service(&mut self, srv: crate::Service) -> Result<(), HapBleError> {
        self.services
            .push(srv)
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

    async fn service_signature_request(
        &self,
        req: &pdu::ServiceSignatureReadRequest,
    ) -> Result<BufferResponse, InternalError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L249

        info!("service signature req: {:?}", req);
        let resp = req.header.to_success();

        let req_svc = req.svc_id;

        let mut buffer = self.out_buffer.borrow_mut();

        let len = resp.write_into_length(*buffer)?;

        let svc = self.get_service_by_svc(req_svc)?;

        let len = BodyBuilder::new_at(*buffer, len)
            .add_u16(BleTLVType::HAPServiceProperties, svc.properties.0)
            .add_u16s(BleTLVType::HAPLinkedServices, &[])
            .end();

        Ok(BufferResponse(len))
    }
    async fn characteristic_signature_request(
        &self,
        req: &pdu::CharacteristicSignatureReadRequest,
    ) -> Result<BufferResponse, InternalError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L289
        let chr = self.get_attribute_by_char(req.char_id)?;

        let mut buffer = self.out_buffer.borrow_mut();
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
    }

    async fn characteristic_read_request(
        &self,
        accessory: &mut impl crate::AccessoryInterface,
        req: &pdu::CharacteristicReadRequest,
    ) -> Result<BufferResponse, InternalError> {
        // Well ehm, what do we do here?
        let char_id = req.char_id; // its unaligned, so copy it before we use it.
        use crate::DataSource;
        let chr = self.get_attribute_by_char(req.char_id)?;

        match chr.data_source {
            DataSource::Nop => {
                error!("Got NOP data on char_id: {:?}", char_id);
                Ok(BufferResponse(0))
            }
            DataSource::AccessoryInterface => {
                // This is a bit wasteful, splitting the entire buffer, for a payload that's likely 8 bytes.
                // Maybe we should just do two calls, one to get the length, then another one to do the split?
                let mut buffer = self.out_buffer.borrow_mut();
                let len = buffer.len();
                let (mut left, mut right) = buffer.split_at_mut(len / 2);
                let data = accessory.read_characteristic(char_id, &mut right).await?;
                let reply = req.header.to_success();
                let len = reply.write_into_length(&mut left)?;
                let len = BodyBuilder::new_at(&mut left, len)
                    .add_value(data.into())
                    .end();
                Ok(BufferResponse(len))
            }
            DataSource::Constant(data) => {
                let mut buffer = self.out_buffer.borrow_mut();
                let reply = req.header.to_success();
                let len = reply.write_into_length(*buffer)?;
                let len = BodyBuilder::new_at(*buffer, len).add_value(data).end();
                Ok(BufferResponse(len))
            }
        }
    }

    async fn characteristic_write_request(
        &self,
        pair_support: &mut impl PlatformSupport,
        accessory: &mut impl crate::AccessoryInterface,
        req: &pdu::CharacteristicWriteRequest<'_>,
    ) -> Result<BufferResponse, InternalError> {
        let parsed = req;
        // Write the body to our internal buffer here.
        let mut buffer = self.out_buffer.borrow_mut();
        buffer.fill(0);

        let halfway = buffer.len() / 2;
        let (left_buffer, outgoing) = buffer.split_at_mut(halfway);
        let body_length = parsed.copy_body(left_buffer)?;

        // So now we craft the reply, technically this could happen on the read... should it happen on the read?
        let char_id = req.header.char_id;
        let chr = self.get_attribute_by_char(char_id)?;

        let is_pair_setup = chr.uuid == characteristic::PAIRING_PAIR_SETUP.into();
        let is_pair_verify = chr.uuid == characteristic::PAIRING_PAIR_VERIFY.into();
        let is_pair_pairings = chr.uuid == characteristic::PAIRING_PAIRINGS.into();
        let is_pair_features = chr.uuid == characteristic::PAIRING_FEATURES.into();
        let incoming_data = &left_buffer[0..body_length];

        // Pair setup, pair verify and pairing features drop the session.
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLECharacteristic.c#L21-L23
        if is_pair_setup || is_pair_verify || is_pair_features {
            {
                let mut pair_ctx = self.pair_ctx.borrow_mut();
                pair_ctx.reset_secure_session();
            }
            self.check_session_state().await; // Check at the start, because the session may be dropped.
        }

        if is_pair_setup {
            let mut pair_ctx = self.pair_ctx.borrow_mut();

            info!("pair setup at incoming");
            crate::pairing::pair_setup::pair_setup_handle_incoming(
                &mut **pair_ctx,
                pair_support,
                incoming_data,
            )
            .await?;

            info!("pair setup at outgoing");
            // Put the reply in the second half.
            let outgoing_len = crate::pairing::pair_setup::pair_setup_handle_outgoing(
                &mut **pair_ctx,
                pair_support,
                outgoing,
            )
            .await?;

            info!("Populating the body.");

            let reply = parsed.header.header.to_success();
            let len = reply.write_into_length(left_buffer)?;

            let len = BodyBuilder::new_at(left_buffer, len)
                .add_value(&outgoing[0..outgoing_len])
                .end();

            info!("Done, len: {}", len);
            Ok(BufferResponse(len))
        } else if is_pair_verify {
            let mut pair_ctx = self.pair_ctx.borrow_mut();
            self.should_encrypt_reply.set(false);
            crate::pairing::pair_verify::handle_incoming(
                &mut **pair_ctx,
                pair_support,
                incoming_data,
            )
            .await?;

            // Put the reply in the second half.
            let outgoing_len = crate::pairing::pair_verify::handle_outgoing(
                &mut **pair_ctx,
                pair_support,
                outgoing,
            )
            .await?;

            let reply = parsed.header.header.to_success();
            let len = reply.write_into_length(left_buffer)?;

            let len = BodyBuilder::new_at(left_buffer, len)
                .add_value(&outgoing[0..outgoing_len])
                .end();

            // Check session state here, this is where it is first enabled.
            drop(pair_ctx);
            self.check_session_state().await;

            Ok(BufferResponse(len))
        } else if is_pair_pairings {
            let mut pair_ctx = self.pair_ctx.borrow_mut();
            // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingPairings.c#L351
            info!("pairing_pairing incoming");
            let _ = crate::pairing::pair_pairing::pairing_pairing_handle_incoming(
                &mut **pair_ctx,
                pair_support,
                incoming_data,
            )
            .await?;

            // Put the reply in the second half.
            let outgoing_len = crate::pairing::pair_pairing::handle_outgoing(
                &mut **pair_ctx,
                pair_support,
                outgoing,
            )
            .await?;

            let reply = parsed.header.header.to_success();
            let len = reply.write_into_length(left_buffer)?;

            let len = BodyBuilder::new_at(left_buffer, len)
                .add_value(&outgoing[0..outgoing_len])
                .end();

            Ok(BufferResponse(len))
        } else if is_pair_features {
            unreachable!();
            // This is handled by the Pairing Feature having a DataSource::Constant value.
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
                        .await?;

                    let characteristic_written = match r {
                        CharacteristicResponse::Modified => {
                            // Do things to this characteristic to mark it dirty.
                            error!(
                                "Should mark the characteristic dirty and advance the global state number, and notify!"
                            );
                            true
                        }
                        CharacteristicResponse::Unmodified => false,
                    };

                    let reply = parsed.header.header.to_success();
                    let len = reply.write_into_length(left_buffer)?;
                    if characteristic_written {
                        drop(buffer);
                        self.advertise_manager
                            .borrow_mut()
                            .characteristic_changed(chr, accessory, pair_support)
                            .await?;
                    }

                    Ok(BufferResponse(len))
                }
                DataSource::Constant(_data) => {
                    unimplemented!("a constant data source should not be writable")
                }
            }
        }
    }

    #[allow(unreachable_code)]
    async fn info_request(&self, req: &pdu::InfoRequest) -> Result<BufferResponse, InternalError> {
        let _ = req;
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessory%2BInfo.c#L71
        // This is a blind attempt at implementing this request based on the reference.
        // I needed this when I set the software authentication bit, but it seems that the reference doesn't actually
        // use that code path, so putting a todo here to ensure we fail hard.
        todo!("this needs checking against the reference");
        let char_id = req.char_id; // its unaligned, so copy it before we use it.
        let chr = self.get_attribute_by_char(char_id)?;

        if chr.uuid == crate::characteristic::SERVICE_SIGNATURE.into() {
            let mut buffer = self.out_buffer.borrow_mut();
            let reply = req.header.to_success();
            let len = reply.write_into_length(*buffer)?;

            let pair_ctx = self.pair_ctx.borrow();
            let setup_hash = advertisement::calculate_setup_hash(
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
    }

    // https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEProtocol%2BConfiguration.c#L29
    async fn protocol_configure_request(
        &self,
        pair_support: &mut impl PlatformSupport,
        req: &pdu::ProtocolConfigurationRequestHeader,
        payload: &[u8],
    ) -> Result<BufferResponse, InternalError> {
        let _ = req;
        let svc_id = req.svc_id; // its unaligned, so copy it before we use it.
        let svc = self.get_service_by_svc(svc_id)?;
        if !svc.properties.configurable() {
            return Err(HapBleStatusError::InvalidRequest.into());
            //return Err(HapBleError::UnexpectedRequest.into());
        }

        let mut buffer = self.out_buffer.borrow_mut();
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
                == pdu::ProtocolConfigurationRequestTLVType::GenerateBroadcastEncryptionKey as u8
            {
                generate_key = true;
            } else if z.type_id
                == pdu::ProtocolConfigurationRequestTLVType::SetAccessoryAdvertisingIdentifier as u8
            {
                have_advertising_id = true;
            } else {
                todo!("unhandled protocol configuration type id: {}", z.type_id);
            }
        }

        if have_advertising_id {
            // NONCOMPLIANCE when is this true, did not encounter a single request with this true.
            todo!();
        }
        if generate_key {
            // https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEAccessoryServer%2BBroadcast.c#L98-L100
            let mut ctx = self.pair_ctx.borrow_mut();
            broadcast::broadcast_generate_key(&mut *ctx, pair_support).await?;
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
        let global_state_number = pair_support.get_global_state_number().await?;

        // This is odd, they write the configuration number as a single byte!
        let config_number = pair_support.get_config_number().await? as u8;
        let parameters = pair_support.get_ble_broadcast_parameters().await?;

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
        core::cell::Ref::<'_, &'static mut [u8]>::map(self.out_buffer.borrow(), |z| &z[0..reply.0])
    }

    pub fn encrypted_reply(
        &mut self,
        value: BufferResponse,
    ) -> Result<BufferResponse, HapBleError> {
        let should_encrypt = self.should_encrypt_reply.get();
        if should_encrypt {
            // Perform the encryption, then respond with the buffer that is encrypted.
            let mut ctx = self.pair_ctx.borrow_mut();
            let mut buff = self.out_buffer.borrow_mut();
            info!("Encrypting reply: {:?}", &buff[0..value.0]);

            // This encrypt can ONLY fail if there's a buffer overrun.
            let res = ctx.session.a_to_c.encrypt(&mut **buff, value.0);
            match res {
                Ok(res) => Ok(BufferResponse(res.len())),
                Err(_) => {
                    error!(
                        "Error encrypting buffer, payload length {:?}, buffer len: {:?}",
                        value.0,
                        buff.len()
                    );
                    Err(HapBleError::BufferOverrun)
                }
            }
        } else {
            let buff = self.out_buffer.borrow();
            info!("Plaintext reply: {:?}", &buff[0..value.0]);
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

    async fn handle_write_incoming<'hap, 'support>(
        &self,
        pair_support: &mut impl PlatformSupport,
        accessory: &mut impl crate::AccessoryInterface,
        data: &[u8],
        handle: u16,
    ) -> Result<Option<BufferResponse>, InternalError> {
        let security_active = self.pair_ctx.borrow().session.security_active;
        self.should_encrypt_reply.set(security_active);
        let mut tmp_buffer = self.in_buffer.borrow_mut();
        let data = if security_active {
            let pair_verify_handle = self
                .get_service_by_uuid(&crate::service::PAIRING.into())
                .ok_or(HapBleError::SpecialHandleError)?
                .get_characteristic_by_uuid(&crate::characteristic::PAIRING_PAIR_VERIFY.into())
                .ok_or(HapBleError::SpecialHandleError)?
                .ble_ref()
                .handle;
            if handle == pair_verify_handle {
                // pair verify is always plaintext!
                self.should_encrypt_reply.set(false);
                data
            } else {
                trace!("handle_write_incoming raw {:?}", data);
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
                    .decrypt(&mut buffer[0..data.len()])
                    .map_err(|_e| HapBleStatusError::InsufficientAuthentication)?
            }
        } else {
            data
        };
        trace!("handle_write_incoming {:?}", data);

        let header = pdu::RequestHeader::parse_pdu(data)?;
        info!("Write header {:?}", header);

        #[allow(unreachable_code)]
        let resp = match header.opcode {
            pdu::OpCode::ServiceSignatureRead => {
                let req = pdu::ServiceSignatureReadRequest::parse_pdu(data)?;
                self.service_signature_request(&req).await?
            }
            pdu::OpCode::CharacteristicSignatureRead => {
                // second one is on [0, 1, 44, 2, 2]
                let req = pdu::CharacteristicSignatureReadRequest::parse_pdu(data)?;
                info!("CharacteristicSignatureRead: {:?}", req);
                self.characteristic_signature_request(&req).await?
            }
            pdu::OpCode::CharacteristicRead => {
                // Check if this characteristic requires security.
                let req = pdu::CharacteristicReadRequest::parse_pdu(data)?;

                let chr = self.get_attribute_by_char(req.char_id)?;
                if !chr.properties.read_open() && !security_active {
                    // Nope...
                    return Err(HapBleStatusError::InsufficientAuthentication.into());
                }

                info!("CharacteristicRead: {:?}", req);
                self.characteristic_read_request(accessory, &req).await?
            }
            pdu::OpCode::CharacteristicWrite => {
                // Check if this characteristic requires security.
                let parsed_header = pdu::CharacteristicWriteRequestHeader::parse_pdu(data)?;
                let chr = self.get_attribute_by_char(parsed_header.char_id)?;
                if !chr.properties.write_open() && !security_active {
                    // Nope...
                    return Err(HapBleStatusError::InsufficientAuthentication.into());
                }

                info!("handle is: {}", handle);
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
                    return Err(HapBleStatusError::InsufficientAuthentication.into());
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
                // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLECharacteristic%2BConfiguration.c#L37
                info!("CharacteristicConfiguration req: {:?}", data);
                if !security_active {
                    // Nope...
                    return Err(HapBleStatusError::InsufficientAuthentication.into());
                }

                let req = pdu::CharacteristicConfigurationRequest::parse_pdu(data)?;
                info!("CharacteristicConfiguration req: {:?}", req);

                let interval = req
                    .broadcast_interval
                    .unwrap_or(pdu::BleBroadcastInterval::Interval20ms);

                let broadcast_enabled = if let Some(broadcast_value) = req.broadcast_enabled {
                    // Enabled broadcasts at the provided interval.
                    {
                        let chr = self.get_attribute_by_char(req.char_id)?;

                        if !chr.properties.supports_broadcast_notification() {
                            error!(
                                "setting broadcast for something that doesn't support broadcast notification"
                            );
                            return Err(HapBleStatusError::InvalidRequest.into());
                        }

                        let _ = pair_support
                            .set_ble_broadcast_configuration(req.char_id, interval)
                            .await?;
                    }

                    broadcast_value
                } else {
                    // Disable broadcasts.
                    let _ = pair_support
                        .set_ble_broadcast_configuration(
                            req.char_id,
                            pdu::BleBroadcastInterval::Disabled,
                        )
                        .await?;
                    false
                };
                // HAPBLECharacteristicGetConfigurationResponse
                // https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLECharacteristic%2BConfiguration.c#L172C10-L172C54
                let _attr = self.get_attribute_by_char(req.char_id)?;

                let mut buffer = self.out_buffer.borrow_mut();
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
            pdu::OpCode::CharacteristicTimedWrite => {
                // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L683
                // Check if this characteristic requires security.
                // NONCOMPLIANCE checks if the bleProcedure is None.
                //
                let t = pair_support.get_time();
                self.timed_write_prune(t);
                let parsed_header = pdu::CharacteristicWriteRequestHeader::parse_pdu(data)?;
                warn!("timed write, h; {:?}", parsed_header);
                let chr = self.get_attribute_by_char(parsed_header.char_id)?;
                if !chr.properties.write_open() && !security_active {
                    // Nope...
                    return Err(HapBleStatusError::InsufficientAuthentication.into());
                }

                // We can piggyback off the CharacteristicWriteRequestHeader struct here.
                let parsed = pdu::CharacteristicWriteRequest::parse_pdu(data)?;
                info!("got a timed write with: {:?}", parsed);

                info!("handle is: {}", handle);
                info!("write raw req event data: {:?}", data);
                // Get a free slot for the timed writes.
                let index = self
                    .get_timed_write_slot_index(None)
                    .ok_or(HapBleStatusError::MaxProcedures)?;

                // Store the data.
                let mut slot = self.get_timed_write_slot(index);
                let mut slot_data = self.get_timed_write_data(index);
                *slot = Some(TimedWrite {
                    char_id: parsed.header.char_id,
                    time_start: pair_support.get_time(),
                    ttl: parsed.ttl.expect("timed write must have a ttl"),
                    data_length: parsed.len(),
                });

                // Copy the entire reques,t not just the payload.
                slot_data[0..data.len()].copy_from_slice(data);

                // Write the success statement.
                let mut buffer = self.out_buffer.borrow_mut();
                let reply = header.to_success();
                let len = reply.write_into_length(*buffer)?;
                BufferResponse(len)
            }
            pdu::OpCode::CharacteristicExecuteWrite => {
                // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEProcedure.c#L725
                // CharacteristicExecuteWrite
                let parsed = pdu::CharacteristicExecuteWrite::parse_pdu(data)?;
                let char_id = parsed.char_id;
                // Check if this characteristic requires security.
                let chr = self.get_attribute_by_char(char_id)?;
                if !chr.properties.write_open() && !security_active {
                    // Nope...
                    return Err(HapBleStatusError::InsufficientAuthentication.into());
                }

                let index = self
                    .get_timed_write_slot_index(Some(parsed.char_id))
                    .ok_or(HapBleStatusError::InvalidRequest)?;
                let data_length = self
                    .get_timed_write_slot(index)
                    .map(|z| z.data_length)
                    .unwrap();

                let payload = {
                    let req_data = self.get_timed_write_data(index);
                    let req_data = &*req_data;
                    let orig_header = parsed.header.as_bytes();
                    let orig_header = [orig_header[0], orig_header[1], orig_header[2]];

                    tmp_buffer[0..data_length].copy_from_slice(&req_data[0..data_length]);
                    // Replace the request header...
                    tmp_buffer[0..orig_header.len()].copy_from_slice(&orig_header);
                    &tmp_buffer[0..data_length]
                };

                // Now, wipe the slot.
                *self.get_timed_write_slot(index) = None;

                // In the C code this is a fallthrough.

                info!("handle is: {}", handle);
                info!("{} write raw req event data: {:?}", line!(), &payload);
                let parsed = pdu::CharacteristicWriteRequest::parse_pdu(&payload)?;
                info!("got write on pair setup with: {:?}", parsed);

                self.characteristic_write_request(pair_support, accessory, &parsed)
                    .await?
            }
            _ => {
                return {
                    error!("Failed to handle: {:?}", header);
                    todo!("need to implement this request type")
                };
            }
        };
        Ok(Some(resp))
    }

    async fn handle_write_incoming_entry<'hap, 'support>(
        &mut self,
        pair_support: &mut impl PlatformSupport,
        accessory: &mut impl crate::AccessoryInterface,
        data: &[u8],
        handle: u16,
    ) -> Result<Option<BufferResponse>, HapBleError> {
        let r = self
            .handle_write_incoming(pair_support, accessory, data, handle)
            .await;
        match r {
            Ok(v) => Ok(v),
            Err(e) => {
                warn!("Processing returned exception: {:?}", e);

                match e {
                    InternalError::HapBleError(hap_ble_error) => Err(hap_ble_error),
                    InternalError::PairError(crate::pairing::PairingError::InterfaceError(e)) => {
                        Err(HapBleError::InterfaceError(e))
                    }
                    other => {
                        let status_error = other.to_status_error();
                        // Write the appropriate response.
                        let reply = pdu::ResponseHeader::from_header(data, status_error.into());
                        let mut buffer = self.out_buffer.borrow_mut();
                        let len = reply.write_into_length(*buffer)?;

                        return Ok(Some(BufferResponse(len)));
                    }
                }
            }
        }
    }

    #[cfg(test)]
    // helper function to store the reply into the prepared reply.
    async fn handle_write_incoming_test<'support>(
        &mut self,
        pair_support: &mut impl crate::PlatformSupport,
        accessory: &mut impl crate::AccessoryInterface,
        data: &[u8],
        handle: u16,
    ) -> Result<Option<BufferResponse>, InternalError> {
        let resp = self.handle_write_incoming_entry(pair_support, accessory, &data, handle);

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

    pub async fn handle_disconnect(&mut self) {
        let mut l = self.pair_ctx.borrow_mut();
        l.reset_secure_session();
        l.disconnect();
        self.handle_session_stop();
    }

    /// May not be called while the pair_ctx is borrowed!
    async fn check_session_state(&self) {
        let ctx_session_active = self.pair_ctx.borrow_mut().session.security_active;
        let session_active = self.session_active.get();
        if session_active != ctx_session_active {
            if ctx_session_active {
                self.handle_session_start();
            } else {
                self.handle_session_stop();
            }
        }
        self.session_active.set(ctx_session_active);
    }

    fn handle_session_start(&self) {
        info!("HAP secure session started");
        self.advertise_manager.borrow_mut().state_connected(true);
    }
    fn handle_session_stop(&self) {
        info!("HAP secure session stopped");
        self.advertise_manager.borrow_mut().state_connected(false);
    }

    pub async fn process_gatt_event<'stack, 'server, 'support, P: PacketPool>(
        &mut self,
        pair_support: &mut impl crate::PlatformSupport,
        accessory: &mut impl crate::AccessoryInterface,
        event: trouble_host::gatt::GattEvent<'stack, 'server, P>,
    ) -> Result<Option<trouble_host::gatt::GattEvent<'stack, 'server, P>>, HapBleError> {
        match event {
            GattEvent::Read(event) => {
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
                let resp = self
                    .handle_write_incoming_entry(
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

    /// Takes a connection when it is established and loops to handle events on the gatt server.
    ///
    /// This loops on events from the connection and hands them off to `Self::process_gatt_event` for processing.
    pub async fn gatt_events_task<P: PacketPool>(
        &mut self,
        accessory: &mut impl crate::AccessoryInterface,
        support: &mut impl PlatformSupport,
        conn: &GattConnection<'_, '_, P>,
    ) -> Result<(), HapBleError> {
        const SUPER_VERBOSE: bool = false;

        let reason = loop {
            let v = select(self.control_receiver.get_event(), conn.next()).await;

            match v {
                embassy_futures::select::Either::First(event) => match event {
                    crate::HapEvent::CharacteristicChanged(char_id) => {
                        // TODO / NOTE: Is this a bug in my implementation or in the reference?
                        // This here will notify over the bluetooth connection even if the connectee is not yet engaged
                        // in an active HAP session, and this would inhibit the broadcast of the value.
                        // It DOES result in a GSN increase, so the proper iOS controller will still retrieve the
                        // correct values later on.

                        // This changed modification should technically happen after the get attribute, but that's a
                        // borrow.

                        let attr = self.get_attribute_by_char(char_id).map_err(|_e| {
                            HapBleError::InterfaceError(InterfaceError::CharacteristicUnknown(
                                char_id,
                            ))
                        })?;
                        self.advertise_manager
                            .borrow_mut()
                            .characteristic_changed(attr, accessory, support)
                            .await?;

                        // Iff we support event notification, sent one out.
                        if attr.properties.supports_event_notification() {
                            attr.ble
                                .as_ref()
                                .unwrap()
                                .characteristic
                                .as_ref()
                                .ok_or(InterfaceError::CharacteristicObjectNotProvided(char_id))?
                                .indicate(conn, &[]) // Indicate with empty payload, iOS will retrieve.
                                .await
                                .map_err(|_e| InterfaceError::CharacteristicNoIndicate(char_id))?
                        }
                    }
                },
                embassy_futures::select::Either::Second(event) => {
                    match event {
                        GattConnectionEvent::Disconnected { reason } => {
                            info!("[gatt] disconnected: {:?}", reason);
                            let _ = self.handle_disconnect().await;
                            break reason;
                        }
                        GattConnectionEvent::Gatt { event } => {
                            // We need this for now to prevent the security from gobbling up the cccd write!
                            let mut should_skip = false;

                            let h = event.payload().handle();
                            if let Some(h) = h {
                                should_skip = !self.should_reply_to_ble_handle(h);
                            }
                            match &event {
                                GattEvent::Read(event) => {
                                    if SUPER_VERBOSE {
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
                                }
                                GattEvent::Write(event) => {
                                    if SUPER_VERBOSE {
                                        info!(
                                            "[gatt] Write Event to Level Characteristic: {:?}",
                                            event.data()
                                        );
                                    }
                                }
                                GattEvent::Other(t) => {
                                    if SUPER_VERBOSE {
                                        let peek = t.payload();
                                        if let Some(handle) = peek.handle() {
                                            info!("[gatt] other event on handle: {}", handle);
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
                                        info!("[gatt] other event {:?}", peek.incoming());
                                    }
                                } //_ => {}
                            };
                            // This step is also performed at drop(), but writing it explicitly is necessary
                            // in order to ensure reply is sent.
                            //
                            if should_skip {
                            } else {
                                let fallthrough_event =
                                    self.process_gatt_event(support, accessory, event).await?;

                                if let Some(event) = fallthrough_event {
                                    match event.accept() {
                                        Ok(reply) => reply.send().await,
                                        Err(e) => warn!("[gatt] error sending response: {:?}", e),
                                    };
                                } else {
                                    warn!("Omitted processing for event because it was handled");
                                }
                            }
                        }
                        _ => {} // ignore other Gatt Connection Events
                    }
                }
            }
        };
        info!("[gatt] disconnected: {:?}", reason);
        Ok(())
    }

    /// Create an advertiser to use to connect to a BLE Central, and wait for it to connect.
    pub async fn advertise<'values, C: Controller>(
        &self,
        accessory: &mut impl crate::AccessoryInterface,
        support: &mut impl PlatformSupport,
        peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    ) -> Result<Connection<'values, DefaultPacketPool>, HapBleError> {
        let _ = accessory;
        let z = self.pair_ctx.borrow();
        let static_info = z.accessory;
        let info = advertise_manager::AdvertiseInfo {
            device_id: &static_info.device_id,
            setup_id: &static_info.setup_id,
            name: &static_info.name,
            category: &static_info.category,
        };

        loop {
            let flow = self
                .advertise_manager
                .borrow_mut()
                .create_advertisement(&info, support)
                .await?;

            let interval_min = embassy_time::Duration::from_millis(flow.advertise_interval_ms);
            // Not sure if it matters that min == max, perhaps it doesn't send if the channel is occupied?, lets add 20%?
            let interval_max = embassy_time::Duration::from_millis(
                flow.advertise_interval_ms + flow.advertise_interval_ms / 5,
            );
            let params = AdvertisementParameters {
                interval_min,
                interval_max,
                tx_power: trouble_host::advertise::TxPower::Plus20dBm, // lets send with oomph.
                ..Default::default()
            };
            let advertiser = peripheral
                .advertise(
                    &params,
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &flow.advertise_data,
                        scan_data: &flow.scan_data,
                    },
                )
                .await
                .map_err(|_e| HapBleError::TroubleError(SimpleTroubleError::FailureInAdvertise))?;
            // TODO:: There's something funky going on here... if this delay is too long, we never exit the select.
            // Too long is like... 3 seconds :/
            const USE_PROPER_TIMES: bool = false;
            let re_consider_timer = if USE_PROPER_TIMES {
                if let Some(t) = flow.until.as_ref() {
                    embassy_time::Timer::at(*t)
                } else {
                    // embassy_time::Instant::MAX ideally.
                    embassy_time::Timer::at(embassy_time::Instant::MAX)
                }
            } else {
                // Workaround, just delay for 1 second, then reconsider.
                embassy_time::Timer::after_secs(1)
            };

            let v = select(advertiser.accept(), re_consider_timer).await;

            match v {
                embassy_futures::select::Either::First(accept_res) => {
                    info!("[adv] connection established");
                    match accept_res {
                        Ok(c) => {
                            return Ok(c);
                        }
                        Err(_) => continue, // This is a timeout event.
                    }
                }
                embassy_futures::select::Either::Second(_) => {
                    // info!("[adv] reconsidering our duration.");
                    continue;
                }
            }
        }
    }

    async fn handle_hap_event_unconnected(
        &mut self,
        event: HapEvent,
        accessory: &mut impl crate::AccessoryInterface,
        support: &mut impl PlatformSupport,
    ) -> Result<(), HapBleError> {
        info!("got hap event: {:?}", event);

        match event {
            HapEvent::CharacteristicChanged(char_id) => {
                info!("updating broadcast payload for {:?}", char_id);

                // Check that this characteristic supports broadcast advertisements.
                let attr = self
                    .get_attribute_by_char(char_id)
                    .map_err(|e| e.invalid_iid_to_hap_ble_error())?;
                self.advertise_manager
                    .borrow_mut()
                    .characteristic_changed(attr, accessory, support)
                    .await?;
                if !attr.properties.supports_broadcast_notification() {
                    info!(
                        "Not doing anything with characteristic changed, no broadcast notify char: {:?}",
                        char_id
                    );
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    async fn test_process_event(
        &mut self,
        accessory: &mut impl crate::AccessoryInterface,
        support: &mut impl PlatformSupport,
    ) -> Result<(), HapBleError> {
        let r = self
            .handle_hap_event_unconnected(
                self.control_receiver.get_event().await,
                accessory,
                support,
            )
            .await;
        if let Err(e) = r {
            info!("e: {:?}", e);
            panic!();
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    async fn test_get_broadcast_payload(
        &self,
        accessory: &mut impl crate::AccessoryInterface,
        support: &mut impl PlatformSupport,
    ) -> Result<advertise_manager::AdvertiseFlow, InterfaceError> {
        let _ = accessory;
        let z = self.pair_ctx.borrow();
        let static_info = z.accessory;
        let info = advertise_manager::AdvertiseInfo {
            device_id: &static_info.device_id,
            setup_id: &static_info.setup_id,
            name: &static_info.name,
            category: &static_info.category,
        };

        self.advertise_manager
            .borrow_mut()
            .create_advertisement(&info, support)
            .await
    }
    pub async fn service<
        'values,
        'peripheral,
        'server,
        C: Controller,
        M: RawMutex,
        const ATT_MAX: usize,
        const CCCD_MAX: usize,
        const CONN_MAX: usize,
    >(
        &mut self,
        accessory: &mut impl crate::AccessoryInterface,
        support: &mut impl PlatformSupport,
        server: &'server AttributeServer<
            'values,
            M,
            DefaultPacketPool,
            ATT_MAX,
            CCCD_MAX,
            CONN_MAX,
        >,
        peripheral: &mut Peripheral<'peripheral, C, DefaultPacketPool>,
        hap_services: &'server crate::ble::HapServices<'_>,
    ) -> Result<(), HapBleError> {
        async {
            loop {
                info!("Falling into advertise & receive event");

                // Does this actually work? Technically we should keep advertising while handling the event...
                let v = select(
                    self.advertise(accessory, support, peripheral),
                    self.control_receiver.get_event(),
                )
                .await;
                match v {
                    embassy_futures::select::Either::First(firstres) => {
                        match firstres {
                            Ok(conn) => {
                                // Increase the data length to 251 bytes per package, default is like 27.
                                // conn.update_data_length(&stack, 251, 2120)
                                //     .await
                                //     .expect("Failed to set data length");
                                let conn = conn
                                    .with_attribute_server(server)
                                    .expect("Failed to create attribute server");

                                // set up tasks when the connection is established to a central, so they don't run when no one is connected.
                                let a = self.gatt_events_task(accessory, support, &conn);

                                // run until any task ends (usually because the connection has been closed),
                                // then return to advertising state.
                                if let Err(e) = a.await {
                                    error!("Error occured in processing: {:?}", e);
                                }
                            }
                            Err(e) => {
                                panic!("[adv] error: {:?}", e);
                            }
                        }
                    }
                    embassy_futures::select::Either::Second(v) => {
                        self.handle_hap_event_unconnected(v, accessory, support)
                            .await?;
                        info!("v: {:?}", v);
                        continue;
                    }
                }
            }
        }
        .await
    }
}

#[cfg(test)]
mod test;
