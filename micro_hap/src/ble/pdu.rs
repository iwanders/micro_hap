use super::OpCode;
use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

// PDU? Protocol Data Unit?

// PDU looks like:
// control field | some fixed params | body length | TLV
// Some fixed params varies per request.
//

#[derive(Debug, Copy, Clone)]
pub enum HapBleError {
    UnexpectedDataLength { expected: usize, actual: usize },
    UnexpectedRequest,
    InvalidValue,
}

impl From<HapBleError> for trouble_host::Error {
    fn from(e: HapBleError) -> trouble_host::Error {
        match e {
            HapBleError::UnexpectedDataLength { expected, actual } => {
                trouble_host::Error::UnexpectedDataLength { expected, actual }
            }
            HapBleError::UnexpectedRequest => trouble_host::Error::Other,
            HapBleError::InvalidValue => trouble_host::Error::InvalidValue,
        }
    }
}

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

#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, Debug)]
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
    pub status: u8,
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
}
