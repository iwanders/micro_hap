#![allow(dead_code)]

use super::HapBleError;
use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

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
        T::try_ref_from_bytes(data).map_err(|_| HapBleError::InvalidValue)
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

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Debug, Copy, Clone)]
#[repr(u8)]
pub enum HapPduServiceSignatureRead {
    Only = 0x06,
}

//https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLETransaction.h#L120
#[derive(Debug, Copy, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C, packed)]
pub struct ServiceSignatureReadRequest {
    pub control: ControlField,
    pub hap_pdu: HapPduServiceSignatureRead,
    pub tid: u8,
    pub svc_id: u16,
}

#[derive(Debug, Copy, Clone, Immutable, IntoBytes, TryFromBytes, KnownLayout)]
#[repr(C, packed)]
pub struct ServiceSignatureReadResponseHeader {
    pub control: ControlField,
    pub tid: u8,
    pub status: Status,
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
