#![allow(dead_code)]

use super::HapBleError;
use bitfield_struct::bitfield;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

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
    pub fn parse_pdu(data: &'a [u8]) -> Result<CharacteristicWriteRequest<'a>, HapBleError> {
        let header = CharacteristicWriteRequestHeader::parse_pdu(data)?;

        let mut res = CharacteristicWriteRequest {
            header,
            body: &data[0..0],
            // Probably defaults to false?
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
        self.push_slice(t as u8, &[value]);
        self
    }
    pub fn add_u16s(mut self, t: BleTLVType, value: &[u16]) -> Self {
        self.push_slice(t as u8, value);
        self
    }

    pub fn add_service(mut self, id: SvcId) -> Self {
        self.push_slice(BleTLVType::ServiceInstanceID as u8, &[id.0]);
        self
    }

    pub fn add_service_uuid(mut self, uid: &crate::uuid::Uuid) -> Self {
        self.push_slice(BleTLVType::ServiceType as u8, uid.as_raw());
        self
    }

    pub fn add_characteristic_uuid(mut self, uid: &crate::uuid::Uuid) -> Self {
        self.push_slice(BleTLVType::CharacteristicType as u8, uid.as_raw());
        self
    }

    pub fn add_characteristic_properties(mut self, properties: CharacteristicProperties) -> Self {
        self.push_slice(
            BleTLVType::HAPCharacteristicPropertiesDescriptor as u8,
            &[properties.0],
        );
        self
    }

    pub fn add_format(mut self, format: &sig::CharacteristicRepresentation) -> Self {
        self.push_slice(
            BleTLVType::GATTPresentationFormatDescriptor as u8,
            format.as_bytes(),
        );

        self
    }

    pub fn add_optional_user_description<const N: usize>(
        mut self,
        user_description: &Option<heapless::String<N>>,
    ) -> Self {
        if let Some(str) = user_description {
            self.push_slice(
                BleTLVType::GATTUserDescriptionDescriptor as u8,
                str.as_bytes(),
            );
        }
        self
    }
    pub fn add_value(mut self, value: &[u8]) -> Self {
        self.push_slice(BleTLVType::Value as u8, value);
        self
    }

    fn add_to_length(&mut self, value: usize) {
        let position_buffer = &mut self.buffer[self.start..self.start + 2];
        let previous = u16::from_le_bytes([position_buffer[0], position_buffer[1]]);
        position_buffer.copy_from_slice(&((previous + value as u16).to_le_bytes()));
    }

    fn push_internal<T: IntoBytes + Immutable>(&mut self, value: &T) {
        let as_bytes = value.as_bytes();
        if self.position + as_bytes.len() >= self.buffer.len() {
            panic!();
        }
        self.buffer[self.position..self.position + as_bytes.len()].copy_from_slice(as_bytes);
        self.position += as_bytes.len();
        self.add_to_length(as_bytes.len());
    }

    fn push_slice<T: IntoBytes + Immutable + MemSizeOf>(&mut self, tt: u8, values: &[T]) {
        let as_bytes = values.as_bytes();
        self.write_u8s(tt, as_bytes);
    }

    fn write_u8s(&mut self, tt: u8, mut values: &[u8]) {
        let mut first = true;
        while !values.is_empty() || first {
            let this_length = values.len().min(255);
            self.push_internal(&tt);
            self.push_internal(&((this_length) as u8));

            if self.position + this_length >= self.buffer.len() {
                panic!();
            }
            self.buffer[self.position..self.position + this_length]
                .copy_from_slice(&values[0..this_length]);
            self.position += this_length;
            self.add_to_length(this_length);
            values = &values[this_length..];
            first = false;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_controlfield_bitfield() {
        crate::test::init();
        let mut v = ControlField::new();
        v.set_continuation(true);

        assert_eq!(v.0, 0b1000_0000);
        v.set_pdu_type(PduType::Response);
        assert_eq!(v.0, 0b1000_0010);
    }

    #[test]
    fn test_parse_service_signature_req() {
        crate::test::init();
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
        crate::test::init();

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
        crate::test::init();
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

        // Test very long.

        #[rustfmt::skip]
        let payload = [
            /*0x01, 0xff,*/ 0x4b, 0x20, 0x6a, 0x23, 0x3c, 0x2b, 0x33, 0xf0, 0x29, 0xf1, 0xd2, 0x82, 0xa4, 0xe1, 0x4c, 0xb9,
            0x39, 0x96, 0x24, 0x99, 0x48, 0x3f, 0x48, 0xdb, 0xd7, 0x51, 0x3c, 0xb4, 0x3f, 0x9d, 0xcd, 0x73, 0x32, 0x61,
            0x2e, 0xaf, 0x0f, 0xca, 0x70, 0x6d, 0xd1, 0x15, 0x93, 0xa5, 0x69, 0x81, 0xe1, 0xcd, 0x21, 0x09, 0x5c, 0x09,
            0x38, 0x84, 0x96, 0x19, 0xbc, 0xcb, 0xd7, 0x1d, 0xf6, 0x5b, 0x2e, 0xe5, 0xe3, 0x74, 0x81, 0x78, 0xb7, 0x43,
            0x14, 0x7f, 0x53, 0xad, 0x86, 0x5c, 0x19, 0xf0, 0x5f, 0xb7, 0x73, 0x10, 0x5b, 0xf4, 0xcb, 0x5a, 0x4a, 0x09,
            0x84, 0xda, 0x4b, 0xaa, 0x63, 0x08, 0xc3, 0xd0, 0x46, 0xff, 0x3e, 0x24, 0xd6, 0xcf, 0xaa, 0xaf, 0xd8, 0x44,
            0x76, 0xa9, 0x1d, 0x24, 0x0e, 0x5c, 0x58, 0xa4, 0x96, 0xf4, 0x85, 0x87, 0x94, 0x42, 0xc3, 0xb9, 0xd8, 0x1d,
            0xe8, 0xb8, 0x14, 0x0d, 0x36, 0x8e, 0xc0, 0x0e, 0x67, 0x8e, 0xce, 0xb8, 0x0d, 0x1f, 0x22, 0x9c, 0xb5, 0x4d,
            0x30, 0x9b, 0x81, 0x09, 0x23, 0xac, 0xcd, 0xc9, 0x8f, 0x89, 0x14, 0xb0, 0x74, 0x75, 0xd1, 0xfb, 0xee, 0x69,
            0xb9, 0x2f, 0xaa, 0x6f, 0xce, 0x83, 0xfe, 0xbe, 0xae, 0xd1, 0x52, 0x8d, 0x21, 0x1b, 0x9e, 0x2b, 0xb2, 0xe1,
            0x88, 0x2f, 0x0f, 0xfc, 0x2d, 0xf2, 0x0b, 0xe2, 0x51, 0x0d, 0xb4, 0xf4, 0xd9, 0x0e, 0x25, 0xce, 0x99, 0x6d,
            0x42, 0x76, 0x50, 0xb3, 0x75, 0xcc, 0x98, 0x31, 0xc3, 0x4d, 0x50, 0x90, 0xd1, 0x2e, 0x3c, 0x3f, 0x94, 0x23,
            0xef, 0xc6, 0x99, 0xf7, 0x60, 0x7a, 0x97, 0x30, 0x61, 0x43, 0xeb, 0x7a, 0x4d, 0x56, 0xfd, 0x26, 0x27, 0x88,
            0x8b, 0xf4, 0xa7, 0x4d, 0x28, 0x94, 0x1e, 0x9a, 0xbf, 0xe2, 0x48, 0x19, 0xb7, 0x29, 0x96, 0xda, 0x3e, 0x4d,
            0x84, 0xee, 0xcf, 0xe3, 0x82,

            /*0x01, 0x81,*/ 0x1f, 0x03, 0x9d, 0x75, 0x26, 0x37, 0xfd, 0x60, 0xbb, 0xbc, 0x47, 0xbd, 0x2e, 0x9a, 0xc8, 0xa0,
            0x7d, 0x6e, 0x00, 0x09, 0x05, 0xe3, 0xc5, 0x78, 0x7b, 0x8d, 0x34, 0x1b, 0x4c, 0x1a, 0x02, 0xef, 0x3a, 0xcc,
            0xf1, 0x34, 0xf2, 0x4a, 0x28, 0x9d, 0xc9, 0xa4, 0xdd, 0x0a, 0x2b, 0xee, 0xd3, 0x5c, 0x4e, 0x66, 0x18, 0xa2,
            0x27, 0x00, 0x09, 0xb7, 0x32, 0x8e, 0x8a, 0x0b, 0x4a, 0x15, 0x04, 0xf9, 0x5e, 0x88, 0xf0, 0x6a, 0xf0, 0x02,
            0x5b, 0xb4, 0x89, 0xfb, 0x3b, 0xc5, 0xdd, 0x36, 0xe4, 0xdd, 0xa7, 0x4f, 0xb7, 0xdf, 0x22, 0xbb, 0x03, 0x3c,
            0xd7, 0xcd, 0xe1, 0x39, 0x17, 0x6f, 0x1d, 0xfa, 0xfd, 0xa1, 0x23, 0x3a, 0xf3, 0x15, 0x56, 0x08, 0xda, 0x57,
            0x19, 0xd8, 0x10, 0x78, 0xd3, 0x89, 0xe1, 0x97, 0xa4, 0x0f, 0x77, 0x48, 0xae, 0x10, 0xf0, 0xcd, 0xd3, 0xb2,
            0x71, 0xdb, 0x84, 0x23, 0x8f,
        ];
        let mut buffer = [0u8; 512];
        let length = BodyBuilder::new(&mut buffer).add_value(&payload).end();
        assert_eq!(length, 388 + 2);
        let buffer = &buffer[2..];
        assert_eq!(&buffer[0..2], &[BleTLVType::Value as u8, 0xff]);
        assert_eq!(&buffer[255 + 2..255 + 4], &[BleTLVType::Value as u8, 0x81]);
        assert_eq!(
            &buffer[255..255 + 6],
            &[0xe3, 0x82, BleTLVType::Value as u8, 0x81, 0x1f, 0x03]
        );
    }
}
