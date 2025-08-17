#![allow(dead_code)]

use super::HapBleError;
use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

use super::{CharacteristicProperties, TId, sig};
use crate::{CharId, SvcId};

// PDU? Protocol Data Unit?

// PDU looks like:
// control field | some fixed params | body length | TLV
// Some fixed params varies per request.
//
pub trait MemSizeOf {
    fn mem_size() -> usize;
}
impl<T> MemSizeOf for T {
    fn mem_size() -> usize {
        core::mem::size_of::<T>()
    }
}

pub trait ParsePdu {
    type Output;
    fn parse_pdu(b: &[u8]) -> Result<&Self::Output, HapBleError>;
}

impl<T: TryFromBytes + KnownLayout + MemSizeOf + Immutable> ParsePdu for T {
    type Output = T;

    fn parse_pdu(data: &[u8]) -> Result<&Self::Output, HapBleError> {
        let exp = T::mem_size();
        if data.len() < exp {
            return Err(HapBleError::UnexpectedDataLength {
                expected: exp,
                actual: data.len(),
            });
        }
        T::try_ref_from_bytes(&data[0..exp]).map_err(|_| HapBleError::InvalidValue)
    }
}

pub trait WriteIntoLength {
    fn write_into_length(&self, buffer: &mut [u8]) -> Result<usize, HapBleError>;
}
impl<T: IntoBytes + Immutable> WriteIntoLength for T {
    fn write_into_length(&self, buffer: &mut [u8]) -> Result<usize, HapBleError> {
        let as_bytes = self.as_bytes();
        let l = as_bytes.len();
        if l <= buffer.len() {
            buffer[0..l].copy_from_slice(as_bytes);
            Ok(l)
        } else {
            Err(HapBleError::BufferOverrun)
        }
    }
}

#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(u8)]
pub enum Status {
    // Success.
    Success = 0x00,

    // Unsupported-PDU.
    UnsupportedPDU = 0x01,

    // Max-Procedures.
    MaxProcedures = 0x02,

    // Insufficient Authorization.
    InsufficientAuthorization = 0x03,

    // Invalid instance ID.
    InvalidInstanceID = 0x04,

    // Insufficient Authentication.
    InsufficientAuthentication = 0x05,

    // Invalid Request.
    InvalidRequest = 0x06,
}

#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(u8)]
pub enum PduType {
    Request = 0,
    Response = 1,
    Invalid = 2,
}
impl PduType {
    const fn into_bits(self) -> u8 {
        self as _
    }
    const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::Request,
            1 => Self::Response,
            _ => Self::Invalid,
        }
    }
}

#[bitfield(u8)]
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable)]
pub struct ControlField {
    #[bits(1)]
    __: u8, // 1 is reserved, so always zero.

    #[bits(3)]
    pdu_type: PduType,

    #[bits(1)]
    extended_iid: bool,

    // 5 and 6, reserved.
    #[bits(2)]
    __: u8,

    // bit 7
    #[bits(1)]
    continuation: bool,
}
impl ControlField {
    pub fn response() -> Self {
        let mut v = Self::default();
        v.set_pdu_type(PduType::Response);
        v
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPDU.h#L26
#[derive(Debug, Copy, Clone, TryFromBytes, KnownLayout, IntoBytes, Immutable, PartialEq)]
#[repr(u8)]
pub enum OpCode {
    CharacteristicSignatureRead = 0x01,
    CharacteristicWrite = 0x02,
    CharacteristicRead = 0x03,
    CharacteristicTimedWrite = 0x04,
    CharacteristicExecuteWrite = 0x05,
    ServiceSignatureRead = 0x06,
    CharacteristicConfiguration = 0x07,
    ProtocolConfiguration = 0x08,
    Token = 0x10,
    TokenUpdate = 0x11,
    Info = 0x12,
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct RequestHeader {
    pub control: ControlField,
    pub opcode: OpCode,
    pub tid: TId,
}
impl RequestHeader {
    pub fn to_success(&self) -> ResponseHeader {
        ResponseHeader {
            control: self.control.with_pdu_type(PduType::Response),
            tid: self.tid,
            status: Status::Success,
        }
    }
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct ResponseHeader {
    pub control: ControlField,
    pub tid: TId,
    pub status: Status,
}

#[derive(Debug, Copy, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C, packed)]
pub struct CharacteristicSignatureReadRequest {
    pub header: RequestHeader,
    pub char_id: CharId,
}

//https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLETransaction.h#L120
#[derive(Debug, Copy, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C, packed)]
pub struct ServiceSignatureReadRequest {
    pub header: RequestHeader,
    pub svc_id: SvcId,
}

#[derive(Debug, Copy, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C, packed)]
pub struct CharacteristicReadRequest {
    pub header: RequestHeader,
    pub char_id: CharId,
}

#[derive(Debug, Copy, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(u8)]
enum WriteRequestBodyValue {
    Value = BleTLVType::Value as u8,
}

#[derive(Debug, Copy, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C, packed)]
pub struct CharacteristicWriteRequestHeader {
    pub header: RequestHeader,
    pub char_id: CharId,
    pub body_length: u16,
    //tlv: WriteRequestBodyValue,
    //pub inner_length: u8,
}

#[derive(Debug, Copy, Clone)]
pub struct CharacteristicWriteRequest<'a> {
    /// The header as it was read.
    pub header: &'a CharacteristicWriteRequestHeader,
    /// The payload of the write.
    pub body: &'a [u8],
    /// The return response flag.
    pub return_response: bool,
}

impl<'a> CharacteristicWriteRequest<'a> {
    fn parse_pdu(data: &'a [u8]) -> Result<CharacteristicWriteRequest<'a>, HapBleError> {
        let header = CharacteristicWriteRequestHeader::parse_pdu(data)?;

        let mut res = CharacteristicWriteRequest {
            header,
            body: &data[0..0],
            // Probably defaults to false?s
            return_response: false,
        };
        let aft = &data[CharacteristicWriteRequestHeader::mem_size()..];

        let reader = crate::tlv::TLVReader::new(aft);
        for entry in reader {
            let entry = entry?;
            if entry.type_id == BleTLVType::Value as u8 {
                res.body = entry.data;
            } else if entry.type_id == BleTLVType::ReturnResponse as u8 {
                res.return_response = entry.data.len() == 1 && entry.data[0] == 1;
            } else {
                todo!("unhandled entry type: 0x{:0>2x}", entry.type_id);
            }
        }
        Ok(res)
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEPDU%2BTLV.h#L22-L26
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, Debug)]
#[repr(u8)]
pub enum BleTLVType {
    /// HAP-Param-Value.
    Value = 0x01,

    /// HAP-Param-Additional-Authorization-Data.
    AdditionalAuthorizationData = 0x02,

    /// HAP-Param-Origin (local vs remote).
    Origin = 0x03,

    /// HAP-Param-Characteristic-Type.
    CharacteristicType = 0x04,

    /// HAP-Param-Characteristic-Instance-ID.
    CharacteristicInstanceID = 0x05,

    /// HAP-Param-Service-Type.
    ServiceType = 0x06,

    /// HAP-Param-Service-Instance-ID.
    ServiceInstanceID = 0x07,

    /// HAP-Param-TTL.
    Ttl = 0x08,

    /// HAP-Param-Return-Response.
    ReturnResponse = 0x09,

    /// HAP-Param-HAP-Characteristic-Properties-Descriptor.
    HAPCharacteristicPropertiesDescriptor = 0x0A,

    /// HAP-Param-GATT-User-Description-Descriptor.
    GATTUserDescriptionDescriptor = 0x0B,

    /// HAP-Param-GATT-Presentation-Format-Descriptor.
    GATTPresentationFormatDescriptor = 0x0C,

    /// HAP-Param-GATT-Valid-Range.
    GATTValidRange = 0x0D,

    /// HAP-Param-HAP-Step-Value-Descriptor.
    HAPStepValueDescriptor = 0x0E,

    /// HAP-Param-HAP-Service-Properties.
    HAPServiceProperties = 0x0F,

    /// HAP-Param-HAP-Linked-Services.
    HAPLinkedServices = 0x10,

    /// HAP-Param-HAP-Valid-Values-Descriptor.
    HAPValidValuesDescriptor = 0x11,

    /// HAP-Param-HAP-Valid-Values-Range-Descriptor
    HAPValidValuesRangeDescriptor = 0x12,
}

// heh
pub struct BodyBuilder<'a> {
    start: usize, // this is where the body length always goes.
    position: usize,
    buffer: &'a mut [u8],
}
impl<'a> BodyBuilder<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self::new_at(buffer, 0)
    }
    pub fn new_at(buffer: &'a mut [u8], start: usize) -> Self {
        buffer[start..start + 2].fill(0);
        Self {
            start,
            position: start + 2,
            buffer,
        }
    }

    pub fn end(&self) -> usize {
        self.position
    }
    pub fn add_u16(mut self, t: BleTLVType, value: u16) -> Self {
        self.push_internal(&t);
        self.push_slice(&[value]);
        self
    }
    pub fn add_u16s(mut self, t: BleTLVType, value: &[u16]) -> Self {
        self.push_internal(&t);
        self.push_slice(value);
        self
    }

    pub fn add_service(mut self, id: SvcId) -> Self {
        self.push_internal(&(BleTLVType::ServiceInstanceID as u8));
        self.push_slice(&[id.0]);
        self
    }

    pub fn add_service_uuid(mut self, uid: &crate::uuid::Uuid) -> Self {
        self.push_internal(&(BleTLVType::ServiceType as u8));
        self.push_slice(uid.as_raw());
        self
    }

    pub fn add_characteristic_uuid(mut self, uid: &crate::uuid::Uuid) -> Self {
        self.push_internal(&(BleTLVType::CharacteristicType as u8));
        self.push_slice(uid.as_raw());
        self
    }

    pub fn add_characteristic_properties(mut self, properties: CharacteristicProperties) -> Self {
        self.push_internal(&(BleTLVType::HAPCharacteristicPropertiesDescriptor as u8));
        self.push_slice(&[properties.0]);
        self
    }

    pub fn add_format(mut self, format: &sig::CharacteristicRepresentation) -> Self {
        self.push_internal(&(BleTLVType::GATTPresentationFormatDescriptor as u8));
        self.push_slice(format.as_bytes());

        self
    }

    pub fn add_optional_user_description<const N: usize>(
        mut self,
        user_description: &Option<heapless::String<N>>,
    ) -> Self {
        if let Some(str) = user_description {
            self.push_internal(&(BleTLVType::GATTUserDescriptionDescriptor as u8));
            self.push_slice(str.as_bytes());
        }
        self
    }
    pub fn add_value(mut self, value: &[u8]) -> Self {
        self.push_internal(&(BleTLVType::Value as u8));
        self.push_slice(value);
        self
    }

    fn add_to_length(&mut self, value: usize) {
        *u16::mut_from_bytes(&mut self.buffer[self.start..self.start + 2]).unwrap() += value as u16;
    }

    fn push_internal<T: IntoBytes + Immutable>(&mut self, value: &T) {
        let as_bytes = value.as_bytes();
        self.buffer[self.position..self.position + as_bytes.len()].copy_from_slice(as_bytes);
        self.position += as_bytes.len();
        self.add_to_length(T::mem_size());
    }

    fn push_slice<T: IntoBytes + Immutable + MemSizeOf>(&mut self, values: &[T]) {
        self.push_internal(&((values.len() * T::mem_size()) as u8));
        for value in values {
            let as_bytes = value.as_bytes();
            self.buffer[self.position..self.position + as_bytes.len()].copy_from_slice(as_bytes);
            self.position += as_bytes.len();
        }
        self.add_to_length(values.len() * T::mem_size());
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::max())
            .try_init();
    }

    #[test]
    fn test_controlfield_bitfield() {
        init();
        let mut v = ControlField::new();
        v.set_continuation(true);

        assert_eq!(v.0, 0b1000_0000);
        v.set_pdu_type(PduType::Response);
        assert_eq!(v.0, 0b1000_0010);
    }

    #[test]
    fn test_parse_service_signature_req() {
        init();
        let b = [0, 6, 107, 2, 0u8];
        let parsed = ServiceSignatureReadRequest::try_ref_from_bytes(&b);
        info!("parsed: {parsed:?}");
        let back = parsed.unwrap().as_bytes();
        assert_eq!(b, back);

        let b = [0, 1, 44, 2, 2];
        let parsed = RequestHeader::try_ref_from_prefix(&b);
        info!("parsed: {parsed:?}");
        assert!(parsed.is_ok());

        let payload = [0, 6, 0x3d, 2, 0];
        let parsed = ServiceSignatureReadRequest::parse_pdu(&payload);
        info!("parsed: {parsed:?}");
        assert!(parsed.is_ok());

        // Write to protocol version;
        let payload = [0, 1, 140, 18, 0];
        let header = RequestHeader::parse_pdu(&payload);
        info!("header: {payload:0>2x?} {header:?}");

        // On pair setup; [0, 1, 62, 0, 34]
        let payload = [0, 1, 62, 0, 34];
        let header = RequestHeader::parse_pdu(&payload);
        info!("header: {payload:0>2x?} {header:?}");

        let payload = [0, 1, 248, 35, 0];
        let header = RequestHeader::parse_pdu(&payload);
        info!("header: {payload:0>2x?} {header:?}");

        let parsed = CharacteristicSignatureReadRequest::parse_pdu(&payload);
        info!("parsed: {parsed:?}");

        let payload = [0, 3, 62, 36, 0];
        let header = RequestHeader::parse_pdu(&payload);
        info!("header: {payload:0>2x?} {header:?}");
        let parsed = CharacteristicReadRequest::parse_pdu(&payload);
        info!("parsed: {parsed:?}");
    }

    #[test]
    fn test_parse_pair_setup_write() -> Result<(), HapBleError> {
        init();

        let payload = [
            0x00, 0x02, 0x3D, 0x22, 0x00, 0x11, 0x00, 0x01, 0x0C, 0x00, 0x01, 0x00, 0x06, 0x01,
            0x01, 0x13, 0x04, 0x10, 0x80, 0x00, 0x01, 0x09, 0x01,
            0x01, //   tid  chr    bodylen   ^^ tlv payload?
        ];
        // Ours:
        //   00    02    cf    22    00    0b    00    01    06    00    01    00    06    01    01    09    01    01
        // Reference:
        // 0x00, 0x02, 0x3D, 0x22, 0x00, 0x11, 0x00, 0x01, 0x0C, 0x00, 0x01, 0x00, 0x06, 0x01, 0x01, 0x13, 0x04, 0x10, 0x80, 0x00, 0x01, 0x09, 0x01, 0x01,
        let header = RequestHeader::parse_pdu(&payload);
        info!("header: {payload:0>2x?} {header:?}");
        let parsed = CharacteristicWriteRequest::parse_pdu(&payload)?;
        info!("parsed: {parsed:?}  ");
        // What's the 09 01 01 at the end!?
        // Oh... maybe ReturnResponse??
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLECharacteristicParseAndWriteValue.c#L67-L70
        // yes..?

        assert_eq!(parsed.return_response, true);
        assert_eq!(
            parsed.body,
            &[
                0x00, 0x01, 0x00, 0x06, 0x01, 0x01, 0x13, 0x04, 0x10, 0x80, 0x00, 0x01
            ]
        );

        // let tlv_payload = [
        //     0x00, 0x01, 0x00, 0x06, 0x01, 0x01, 0x13, 0x04, 0x10, 0x80, 0x00, 0x01, 0x09, 0x01,
        //     0x01,
        // ];
        // assert_eq!(body, tlv_payload);

        Ok(())
    }

    #[test]
    fn test_body_builder() {
        init();
        let mut buffer = [0u8; 32];
        // 06 00 0f 02 04 00 10 00
        let b = BodyBuilder::new(&mut buffer)
            .add_u16(BleTLVType::HAPServiceProperties, 0x04)
            .add_u16s(BleTLVType::HAPLinkedServices, &[])
            .end();
        let expected = [0x06, 0x00, 0x0f, 0x02, 0x04, 0x00, 0x10, 0x00];
        assert_eq!(buffer[0..b], expected);
        let c = BodyBuilder::new_at(&mut buffer, b)
            .add_u16(BleTLVType::HAPServiceProperties, 0x05)
            .add_u16s(BleTLVType::HAPLinkedServices, &[0x18])
            .end();
        let expected = [0x08, 0x00, 0x0f, 0x02, 0x05, 0x00, 0x10, 0x02, 0x18, 0x0];
        assert_eq!(buffer[b..c], expected);
    }
}
