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
        Ok(Self(String::from(s)))
    }
}

// Define `From`
impl<T: Into<String<N>>, const N: usize> From<T> for GattString<N> {
    fn from(item: T) -> Self {
        Self(item.into())
    }
}
