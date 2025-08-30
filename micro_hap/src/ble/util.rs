use heapless::String;
use trouble_host::prelude::{AsGatt, FromGatt};

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Default, Eq, PartialEq, Clone, Debug)]
#[repr(transparent)]
pub struct GattString<const N: usize>(pub String<N>);

impl<const N: usize> AsGatt for GattString<N> {
    const MIN_SIZE: usize = 0;

    const MAX_SIZE: usize = N;

    fn as_gatt(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl<const N: usize> FromGatt for GattString<N> {
    fn from_gatt(data: &[u8]) -> Result<Self, trouble_host::types::gatt_traits::FromGattError> {
        let s: &str = core::str::from_utf8(data)
            .map_err(|_e| trouble_host::types::gatt_traits::FromGattError::InvalidCharacter)?;
        Ok(Self(String::try_from(s).map_err(|_| {
            trouble_host::types::gatt_traits::FromGattError::InvalidLength
        })?))
    }
}

impl<'a, const N: usize> TryFrom<&'a str> for GattString<N> {
    type Error = heapless::CapacityError;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let mut new = String::new();
        new.push_str(s)?;
        Ok(GattString(new))
    }
}
