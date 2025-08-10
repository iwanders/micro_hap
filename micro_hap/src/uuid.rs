pub const HOMEKIT_BASE_UUID_BYTES: [u8; 16] = [
    0x91, 0x52, 0x76, 0xbb, 0x26, 0x0, 0x0, 0x80, 0x0, 0x10, 0x0, 0x0, // First block.
    0x0, 0x0, 0x0, 0x0,
];

pub const HOMEKIT_BASE_UUID: Uuid = Uuid::new_long(HOMEKIT_BASE_UUID_BYTES);

/// Bluetooth UUID.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HomekitUuid16(u16);

impl HomekitUuid16 {
    /// Create a new `BluetoothUuid16`.
    pub const fn new(uuid: u16) -> Self {
        Self(uuid)
    }
    /// Convert the `BluetoothUuid16` to a byte array as a const function.
    pub const fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
    /// Convert from a byte array to a `BluetoothUuid16`.
    pub const fn from_le_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_le_bytes(bytes))
    }
    pub const fn to_le_bytes_long(&self) -> [u8; 16] {
        let mut raw_bytes = HOMEKIT_BASE_UUID_BYTES;
        let [high, low] = self.to_le_bytes();
        raw_bytes[12] = high;
        raw_bytes[13] = low;
        raw_bytes
    }
}

impl From<HomekitUuid16> for u16 {
    fn from(uuid: HomekitUuid16) -> u16 {
        uuid.0
    }
}

impl From<HomekitUuid16> for [u8; 2] {
    fn from(uuid: HomekitUuid16) -> [u8; 2] {
        uuid.0.to_le_bytes()
    }
}

impl core::fmt::Debug for HomekitUuid16 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "HomekitUuid16(0x{:04X})", self.0)
    }
}

impl core::fmt::Display for HomekitUuid16 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "0x{:04X}", self.0)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for HomekitUuid16 {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "BluetoothUuid16(0x{:04X})", self.0)
    }
}

use trouble_host::attribute::Uuid;
impl From<HomekitUuid16> for Uuid {
    fn from(uuid: HomekitUuid16) -> Uuid {
        // "0000xxxx-0000-1000-8000-0026BB765291"
        Uuid::new_long(uuid.to_le_bytes_long())
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
    fn test_ble_uuid() {
        init();
        const SERVICE_UUID: HomekitUuid16 = HomekitUuid16::new(0x003E);
        assert_eq!(u16::from(SERVICE_UUID), 0x003E);
        let uuid: u16 = SERVICE_UUID.into();
        assert_eq!(uuid, 0x003E);
        const UUID: [u8; 2] = SERVICE_UUID.to_le_bytes();
        assert_eq!(UUID, [0x3E, 0x00]);
        let full_uuid: Uuid = SERVICE_UUID.into();
        info!("full uiid: {:?}", full_uuid);
        if let Uuid::Uuid128(z) = full_uuid {
            assert_eq!(z[12], 0x3e);
        }
    }
}
