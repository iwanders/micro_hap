const COMPANY_IDENTIFIER_CODE: u16 = 0x004c;
use heapless::String;
use sha2::{Digest, Sha512};
use trouble_host::prelude::AdStructure;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Copy, Clone, Debug, Default)]
pub struct DeviceId(pub [u8; 6]);

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct AdvertisementConfig {
    /// True if the device is already paired.
    pub is_paired: bool,

    /// Device id that's advertised.
    pub device_id: DeviceId,

    /// Accessory category from the list of ids, Other is 0x01.
    pub accessory_category: u16,

    /// Global state number.
    pub global_state: u16,

    /// Configuration number, default starts with 1, must increment with firmware update.
    pub config_number: u8,

    /// The setup id, made up of four alphanumeric characters.
    pub setup_id: String<4>,
}

impl Default for AdvertisementConfig {
    fn default() -> Self {
        Self {
            is_paired: false,
            device_id: Default::default(),
            accessory_category: 1,
            config_number: 1,
            global_state: 1,
            setup_id: "ABCD".into(),
        }
    }
}

fn u8_to_uppercase_hex(v: u8) -> [u8; 2] {
    const LOOKUP: &[u8; 16] = b"0123456789ABCDEF";

    let low = v & 0xF;
    let high = (v >> 4) & 0xF;
    [LOOKUP[high as usize], LOOKUP[low as usize]]
}

pub struct HapAdvertisement {
    // Trouble adds the LEN, ADT and CoID bytes.
    data: [u8; 23 - 1 - 1 - 2],
}
impl AdvertisementConfig {
    pub fn calculate_setup_hash(&self) -> [u8; 4] {
        // E1:91:1A:70:85:AA
        // Well... yikes, they want the colons.
        // Concatenate the Setup Id and the Device ID.
        let mut concat: [u8; 4 + 6 * 2 + 5] = Default::default();
        concat[0..4].copy_from_slice(&self.setup_id.as_bytes());

        for (i, v) in self.device_id.0.iter().enumerate() {
            let [h, l] = u8_to_uppercase_hex(*v);
            concat[4 + i * 3] = h;
            concat[4 + i * 3 + 1] = l;
            if i != 5 {
                concat[4 + i * 3 + 2] = b':';
            }
        }

        let res = Sha512::digest(&concat);
        [res[0], res[1], res[2], res[3]]
    }

    pub fn to_advertisement(&self) -> HapAdvertisement {
        let config = &self;
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEAccessoryServer%2BAdvertising.c#L284
        let mut data = [0u8; 23 - 1 - 1 - 2];
        data[0] = 0x06; // type, set to 0x06
        // subtype and length, 0x31?
        // First 3 bits specify subtype, set to 1;
        // 0b001x_xxxx
        // Remaining 15 bits is length of remaining bytes, which is 17.
        // 0b0011_0001
        data[1] = 0x31; // so yes. this.
        //data[1] = 0x2d; // so yes. this.
        data[2] = if config.is_paired { 0b0 } else { 0b1 }; // Pairing status flag
        // 48 bit device id.
        data[3..(3 + 6)].copy_from_slice(&config.device_id.0);
        // 16 bit LE ACID.
        data[9..11].copy_from_slice(&config.accessory_category.to_le_bytes());
        // Global state number.
        data[11..13].copy_from_slice(&config.global_state.to_le_bytes());
        data[13] = config.config_number;
        data[14] = 0x02; // compatible version.
        data[15..19].copy_from_slice(&config.calculate_setup_hash());
        HapAdvertisement { data }
    }
}

impl HapAdvertisement {
    pub fn as_advertisement(&self) -> AdStructure {
        AdStructure::ManufacturerSpecificData {
            company_identifier: COMPANY_IDENTIFIER_CODE,
            payload: &self.data,
        }
    }
}

#[cfg(test)]
mod test {

    fn init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::max())
            .try_init();
    }
    use super::*;
    #[test]
    fn test_setup_hash() {
        init();
        let device_id = [0xE1, 0x91, 0x1A, 0x70, 0x85, 0xAA];
        let config = AdvertisementConfig {
            setup_id: "7OSX".into(),
            device_id: DeviceId(device_id),
            ..Default::default()
        };
        let hash = config.calculate_setup_hash();
        assert_eq!(hash, [0xc9, 0xFE, 0x1b, 0xcf]);

        let device_id = [0xC8, 0xD8, 0x58, 0xC6, 0x63, 0xF5];
        let config = AdvertisementConfig {
            setup_id: "7OSX".into(),
            device_id: DeviceId(device_id),
            ..Default::default()
        };
        let hash = config.calculate_setup_hash();
        assert_eq!(hash, [0xEF, 0x5D, 0x8E, 0x9B]);
    }
}
