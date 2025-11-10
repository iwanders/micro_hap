#![cfg_attr(not(test), no_std)]

// This mod MUST go first, so that the others see its macros.
// pub(crate) mod fmt;
pub mod fmt;

#[cfg(test)]
extern crate std;

pub mod adv;
pub mod characteristic;
pub mod descriptor;
pub mod service;
pub mod uuid;
use thiserror::Error;

pub mod ble;

use bitfield_struct::bitfield;

pub mod pairing;
pub mod tlv;

pub mod crypto;
use crate::pairing::{ED25519_LTSK, Pairing, PairingId};
use crypto::aead::ControlChannel;

use core::future::Future;

// We probably should handle some gatt reads manually with:
// https://github.com/embassy-rs/trouble/pull/311
//

// Hmm, maybe this does what we need;
// https://github.com/sysgrok/rs-matter-embassy/blob/79a2a7786ad28e2ae186e4136e22c93a2c343599/rs-matter-embassy/src/ble.rs#L301
// it creates a service with 'External' types.
// It puts context and resources in a a struct; https://github.com/sysgrok/rs-matter-embassy/blob/ca6cef42001fb208875504eac7ab3cb9f22b7149/rs-matter-embassy/src/ble.rs#L148-L158
// That struct then has a handle_indications and handle_events method, that actually services the endpoints.
// Maybe it is okay if we define the server in this module, the
// https://github.com/embassy-rs/trouble/issues/391 issue mentions re-using a specific server?

// Descriptor!? dc46f0fe-81d2-4616-b5d9-6abdd796939a
// Ooh this characteristic instance id descriptor must be EACH characteristic.
// (uuid = \"1234\", value = 42, read, write, notify, indicate)
//
// server.table().find_characteristic_by_value_handle(handle);
// exists, but there doesn't appear to be a way to set the descriptor values besides in the host-macro

// Todo:
// - Figure out how to dynamically assignthe descriptors?
// - Each characteristic is 7.3.5.1; HAP Characteristic Signature Read Procedure
//   - Presentation format is _also_ required, see 7.4.5

// How are we going to test this?
// Home assistant
// https://github.com/home-assistant/core/blob/b481aaba772960810fc6b2c5bb1d331729d91660/requirements_all.txt#L19
// uses
//  https://github.com/Jc2k/aiohomekit/  which does both bluetooth and wifi
//  It links to https://github.com/jlusiardi/homekit_python/
//  that may have support for peripheral and controller??
//  and doesn't build, swap ed25519; https://github.com/warner/python-ed25519/issues/20
//
// The majority of logic will actually not be on the BLE interface.
// Could even test against https://github.com/ewilken/hap-rs
// if we also had tcp.
//
// Http transport seems to just use the same underlying bytes as the ble side?
//
//
// Accessory may only expose a single primary interface. Linked services display as a group in the ui.
// Primary service is optional,
//
// Ah, well we can't have Arc<dyn Foo> with heapless arc... it needs https://rust-lang.github.io/rfcs/2580-ptr-meta.html I think?

use heapless::String;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

pub use pairing::PairCode;

/// Helper to set all accessory information from static values in bulk.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Copy, Clone, Debug)]
pub struct AccessoryInformationStatic {
    pub hardware_revision: &'static str, // "x.y.z" with u32.
    pub serial_number: &'static str,     // String at least 1, max 64
    //pub service_instance: u16,
    pub model: &'static str,             // String at least 1, max 64
    pub name: &'static str,              // String at least 1, max 64
    pub manufacturer: &'static str,      // String at least 1, max 64
    pub firmware_revision: &'static str, // "x.y.z" with u32.
    pub category: u16,

    pub device_id: DeviceId,

    /// Setup code made up of four uppercase letters. This is constant even across factory reset.
    pub setup_id: SetupId,
}
impl Default for AccessoryInformationStatic {
    fn default() -> Self {
        Self {
            hardware_revision: "0.0.1",
            serial_number: "1234567890ABC",
            //service_instance: 0,
            model: "AmazingDevice",
            name: "MicroHap",
            manufacturer: "TestManufacturer",
            firmware_revision: "0.0.1",
            category: 7,
            device_id: DeviceId([1, 2, 3, 4, 5, 6]),
            setup_id: Default::default(),
        }
    }
}

pub struct SetupPayloadProperties {
    pub paired: bool,
    pub support_ip: bool,
    pub support_ble: bool,
    pub category: u8,
}
impl From<u8> for SetupPayloadProperties {
    fn from(category: u8) -> Self {
        Self {
            paired: false,
            support_ip: false,
            support_ble: true,
            category,
        }
    }
}

pub const SETUP_PAYLOAD_URI_LEN: usize = 9 + "X-HM://".len() + 100;
/// Calculate the setup payload, this is an URL for use in a QR code for easy setup.
pub fn setup_payload(
    pair_code: &PairCode,
    setup_id: &SetupId,
    properties: SetupPayloadProperties,
) -> String<SETUP_PAYLOAD_URI_LEN> {
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Tests/HAPAccessorySetupGetSetupPayloadTest.c#L9-L14
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessorySetup.c#L102

    let mut result: String<SETUP_PAYLOAD_URI_LEN> = String::new();
    result.push_str(&"X-HM://").unwrap();

    // 46 bit value holding setup code concatenated with the setup id.
    let mut left: u64 = 0;
    left |= 0 << 43; // version
    left |= 0 << 39; // reserved
    left |= (properties.category as u64) << 31;
    left |= (if properties.support_ble { 1 } else { 0 }) << 29;
    left |= (if properties.support_ip { 1 } else { 0 }) << 28;
    left |= (if properties.paired { 1 } else { 0 }) << 27;

    let digits = pair_code.to_digits();
    left |= (digits[0] as u64) * 10_000_000+
    (digits[1] as u64) * 1_000_000 +
    (digits[2] as u64) * 100_000 +
    (digits[3] as u64) * 10_000 +
    (digits[4] as u64) * 1_000 +
    (digits[5] as u64) * 100 +
    (digits[6] as u64) * 10 +
     (digits[7] as u64) * 1;

    info!("left: {:b}", left);
    info!("left: {:b}", 2467727686u64 );

    // Base36 encode.
    fn value_to_b36(x: u8) -> u8 {
        if x < 10 {
            x + '0' as u8
        } else {
            x - 10 + 'A' as u8
        }
    }
    // Okay, well... manually implementing this missed zero's, so we'll just copy the C code here.
    let mut code = left;
    let mut other_dir = [0u8; 9];
    for i in 0..9 {
        // Divide code by 36 and get remainder.

        let x = code  ;
        let mut q = x - (x >> 3);

        q = q + (q >> 6);
        q = q + (q >> 12);
        q = q + (q >> 24);
        q = q + (q >> 48); // not needed for x < 2^48
        /* q = x * 8/9 +0/-5 */
        q = q >> 5;
        /* q = x / 36 +0/-1 */
        //let r = (x as u32) - ( q as u32).overflowing_mul(36).0;
        let r = (x as u32) - (q * 36) as u32;
        /* 0 <= r < 72 */
        let d = (r + 28) >> 6;
        /* d = 1 if r > 35 */
        code = q + d as u64;
        let c = ((r - d * 36)) as u8;
        assert!(c < 36);
        other_dir[i] = c;
    }
    for c in other_dir.iter().rev() {
        result.push(value_to_b36(*c) as char).unwrap();
    }
    for b in setup_id.as_bytes() {
        result.push(*b as char).unwrap();
    }
    result
}

/// A characteristic id.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct CharId(pub u16);

#[cfg(feature = "defmt")]
impl defmt::Format for CharId {
    fn format(&self, f: defmt::Formatter) {
        let v = self.0;
        defmt::write!(f, "CharId(0x{:04X})", v)
    }
}

/// A service id.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct SvcId(pub u16);

#[cfg(feature = "defmt")]
impl defmt::Format for SvcId {
    fn format(&self, f: defmt::Formatter) {
        let v = self.0;
        defmt::write!(f, "SvcId(0x{:04X})", v)
    }
}

/// A device id, could be the MAC address.
/// This changes when a factory reset happens, but should be constant in all other cases.
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPDeviceID.h#L23
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct DeviceId(pub [u8; 6]);
impl Default for DeviceId {
    fn default() -> Self {
        DeviceId([1, 2, 3, 4, 5, 6])
    }
}
impl DeviceId {
    // These functions are tested in the advertisement setup hash.
    fn u8_to_uppercase_hex(v: u8) -> [u8; 2] {
        const LOOKUP: &[u8; 16] = b"0123456789ABCDEF";
        let low = v & 0xF;
        let high = (v >> 4) & 0xF;
        [LOOKUP[high as usize], LOOKUP[low as usize]]
    }

    pub fn to_device_id_string(&self) -> DeviceIdString {
        let mut concat = [0u8; 6 * 2 + 5];
        for (i, v) in self.0.iter().enumerate() {
            let [h, l] = Self::u8_to_uppercase_hex(*v);
            concat[0 + i * 3] = h;
            concat[0 + i * 3 + 1] = l;
            if i != 5 {
                concat[0 + i * 3 + 2] = b':';
            }
        }
        DeviceIdString(concat)
    }
}

/// The device id as a ':' delimited hexadecimal string; "11:22:33:44:55:66"
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceIdString(pub [u8; 6 * 2 + 5]);
impl DeviceIdString {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The setup id, always 4 alphanumeric uppercase letters, like "ABCD", or "7OSX".
/// Constant event across factory resets.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(transparent)]
pub struct SetupId(pub [u8; 4]);
impl Default for SetupId {
    fn default() -> Self {
        SetupId([b'A', b'B', b'C', b'D'])
    }
}
impl SetupId {
    /// Create a setup id from four bytes, roundtrips if they are valid, otherwise modulo's appropriately.
    pub fn from(four_bytes: &[u8; 4]) -> Self {
        fn shift(v: u8) -> u8 {
            if v.is_ascii_alphanumeric() {
                v.to_ascii_uppercase()
            } else {
                // Pick out of the letters and alphabet.
                let x = v.rem_euclid(26 + 10);
                if x < 10 {
                    x + '0' as u8
                } else {
                    x.to_ascii_uppercase()
                }
            }
        }
        SetupId([
            shift(four_bytes[0]),
            shift(four_bytes[1]),
            shift(four_bytes[2]),
            shift(four_bytes[3]),
        ])
    }
}

/// Properties for a service.
#[bitfield(u16)]
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable)]
pub struct ServiceProperties {
    #[bits(1)]
    pub primary: bool,
    #[bits(1)]
    pub hidden: bool,
    #[bits(1)]
    pub configurable: bool,

    #[bits(13)]
    __: u16,
}

/// Container to represent a service.
#[derive(Clone, Debug)]
pub struct Service {
    /// The uuid that describes the service.
    pub uuid: uuid::Uuid,
    /// The service id it is referred to by, note these are aligned to 16 boundaries.
    ///
    /// See <https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L18>
    pub iid: SvcId,
    // 8 = accessory information service, its the one with the most attributes.
    /// The attributes that this service holds.
    pub characteristics: heapless::Vec<Characteristic, 12>,

    /// The bluetooth service handle.
    pub ble_handle: Option<u16>,

    /// The properties of this service.
    pub properties: ServiceProperties,
}
impl Service {
    /// Retrieve a characteristic by its instance id.
    pub fn get_characteristic_by_iid(&self, chr: CharId) -> Option<&Characteristic> {
        for a in self.characteristics.iter() {
            if a.iid == chr {
                return Some(a);
            }
        }
        None
    }

    /// Retrieve a characteristic by its uuid.
    pub fn get_characteristic_by_uuid_mut(
        &mut self,
        attribute_uuid: &uuid::Uuid,
    ) -> Option<&mut Characteristic> {
        for a in self.characteristics.iter_mut() {
            if &a.uuid == attribute_uuid {
                return Some(a);
            }
        }
        None
    }
}

// Can this be generalised?
/// The bluetooth properties of a characteristic.
#[derive(Clone, Debug)]
pub struct BleProperties {
    pub handle: u16,
    pub format: ble::sig::CharacteristicRepresentation,
}
impl BleProperties {
    pub fn from_handle(handle: u16) -> Self {
        Self {
            handle,
            format: Default::default(),
        }
    }
    pub fn with_format(self, format: ble::sig::Format) -> Self {
        let mut ble_format = self.format;
        ble_format.format = format;
        Self {
            format: ble_format,
            ..self
        }
    }
    pub fn with_unit(self, unit: ble::sig::Unit) -> Self {
        let mut ble_format = self.format;
        ble_format.unit = unit;
        Self {
            format: ble_format,
            ..self
        }
    }
    pub fn with_format_opaque(self) -> Self {
        let mut format = self.format;
        format.format = ble::sig::Format::Opaque;
        Self { format, ..self }
    }
}

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPBLEPDU%2BTLV.c#L93
/// Properties for a characteristic
#[bitfield(u16)]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable)]
pub struct CharacteristicProperties {
    #[bits(1)]
    pub read_open: bool, // readableWithoutSecurity
    #[bits(1)]
    pub write_open: bool,
    #[bits(1)]
    pub supports_authorization: bool,
    #[bits(1)]
    pub requires_timed_write: bool,

    #[bits(1)]
    pub read: bool,

    #[bits(1)]
    pub write: bool,

    #[bits(1)]
    pub hidden: bool,

    #[bits(1)]
    pub supports_event_notification: bool,

    #[bits(1)]
    pub supports_disconnect_notification: bool,

    #[bits(1)]
    pub supports_broadcast_notification: bool,

    #[bits(6)]
    __: u16,
}
impl CharacteristicProperties {
    pub fn with_open_rw(self, state: bool) -> Self {
        self.with_read_open(state).with_write_open(state)
    }
    pub fn with_rw(self, state: bool) -> Self {
        self.with_read(state).with_write(state)
    }
}

// https://github.com/apple/HomeKitADK/blob/master/HAP/HAPBLEPDU%2BTLV.c#L156-L158
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Copy, Clone)]
pub enum VariableUnion {
    Bool(bool),
    // kHAPCharacteristicFormat_UInt8
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I32(i32),
    F32(f32),
    // String...
}
impl VariableUnion {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            VariableUnion::Bool(v) => v.as_bytes(),
            VariableUnion::U8(v) => v.as_bytes(),
            VariableUnion::U16(v) => v.as_bytes(),
            VariableUnion::U32(v) => v.as_bytes(),
            VariableUnion::U64(v) => v.as_bytes(),
            VariableUnion::I32(v) => v.as_bytes(),
            VariableUnion::F32(v) => v.as_bytes(),
        }
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Copy, Clone)]
pub struct VariableRange {
    pub start: VariableUnion,
    pub end: VariableUnion,
    pub inclusive: bool,
}

/// The datasource for a characteristic, this specifies how its data is written / read.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Copy, Clone, Default)]
pub enum DataSource {
    /// Reads as 0 length data, writes discard data.
    #[default]
    Nop,
    /// Read/Write to the accessory interface.
    AccessoryInterface,
    /// Super constant data.
    Constant(&'static [u8]),
}

/// Representation for a characteristic.
#[derive(Clone, Debug)]
pub struct Characteristic {
    /// The uuid that describes this characteristic.
    pub uuid: uuid::Uuid,

    /// The characteristic instance id.
    pub iid: CharId,

    /// The bluetooth properties for this characteristic.
    pub ble: Option<BleProperties>,

    /// The data source for this characteristic.
    pub data_source: DataSource,

    /// The permission properties for this characteristic.
    pub properties: CharacteristicProperties,

    /// The range this characteristic can hold.
    pub range: Option<VariableRange>,

    /// The step the ui should use when changing the value.
    pub step: Option<VariableUnion>,
}
impl Characteristic {
    pub fn new(uuid: uuid::Uuid, iid: CharId) -> Self {
        Self {
            uuid,
            iid,
            ble: None,
            data_source: DataSource::Nop,
            properties: CharacteristicProperties::new(),
            range: None,
            step: None,
        }
    }
    pub fn with_ble_properties(self, prop: BleProperties) -> Self {
        Self {
            ble: Some(prop),
            ..self
        }
    }
    pub fn with_data(self, data_source: DataSource) -> Self {
        Self {
            data_source,
            ..self
        }
    }
    pub fn set_data(&mut self, data_source: DataSource) {
        self.data_source = data_source;
    }

    pub fn ble_ref(&self) -> &BleProperties {
        self.ble.as_ref().unwrap()
    }
    pub fn ble_mut(&mut self) -> &mut BleProperties {
        self.ble.as_mut().unwrap()
    }
    pub fn with_properties(self, properties: CharacteristicProperties) -> Self {
        let x = Self { properties, ..self };
        x
    }
    pub fn with_range(self, range: VariableRange) -> Self {
        let x = Self {
            range: Some(range),
            ..self
        };
        x
    }
    pub fn with_step(self, step: VariableUnion) -> Self {
        let x = Self {
            step: Some(step),
            ..self
        };
        x
    }
}

/// Session state container.
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPSession.h#L73
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Copy, Clone, Debug, Default)]
pub struct Session {
    // The following 5 are in the hap substruct.
    /// Accessory to Controller control channel.
    pub a_to_c: ControlChannel,
    /// Controller to Accessory control channel.
    pub c_to_a: ControlChannel,
    /// Whether the session originated from a transient pair setup procedure.
    pub transient: bool,
    /// Whether the security session is active.
    pub security_active: bool,
    /// The pairing id that this session was created for.
    pub pairing_id: crate::pairing::PairingId,
    // ble specific data here?
}

// Where are sessions created, and how to we find the correct session, and how are they assigned to the connections
// or client?
// Session is opaque; https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAP.h#L221-L225
// but asserted here:
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPSession.h#L169-L170
//
// Which also means that the BLE side only has one: https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Main.c#L258
// Can a bluetooth accessory only have one connection?
// Ah yes, it is a peripheral, peripherals in general get only one connection.

// Something to retrieve the accessory callbacks.

/// Error used by the accessory interface
#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterfaceError {
    /// An characteristic that is not provided was read or written to.
    #[error("characteristic id is unknown")]
    CharacteristicUnknown(CharId),

    /// Incorrect write payload
    #[error("characteristic write payload is invalid")]
    CharacteristicWriteInvalid,

    /// A custom error was encountered
    #[error("error: {0:?}")]
    Custom(&'static str),
}

/// Interface through which the characteristics interact with the accessory.
pub trait AccessoryInterface {
    /// Read the characteristic value.
    ///
    /// Note I got <https://doc.rust-lang.org/rustc/lints/listing/warn-by-default.html#async-fn-in-trait> on this method.
    /// can we just ignore that for now? Does this need to be send?
    #[allow(async_fn_in_trait)]
    async fn read_characteristic(
        &self,
        char_id: CharId,
    ) -> Result<impl Into<&[u8]>, InterfaceError>;
    #[allow(async_fn_in_trait)]
    async fn write_characteristic(
        &mut self,
        char_id: CharId,
        data: &[u8],
    ) -> Result<CharacteristicResponse, InterfaceError>;
}

/// Enum that specifies whether a characteristic was changed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CharacteristicResponse {
    Modified,
    Unmodified,
}

/// Dummy no-op accessory that discards reads and writes.
#[derive(Debug, Copy, Clone)]
pub struct NopAccessory;
impl AccessoryInterface for NopAccessory {
    async fn read_characteristic(
        &self,
        char_id: CharId,
    ) -> Result<impl Into<&[u8]>, InterfaceError> {
        let _ = char_id;
        const DUMMY: &[u8] = &[];
        Ok(DUMMY)
    }
    async fn write_characteristic(
        &mut self,
        char_id: CharId,
        data: &[u8],
    ) -> Result<CharacteristicResponse, InterfaceError> {
        let _ = (char_id, data);
        // todo!("write characteristic on 0x{:02?}, handle this?", char_id);
        Ok(CharacteristicResponse::Unmodified)
    }
}

// Todo; make these all async.... This now requires Send, which probably doesn't work the moment I need to actually pass
// a peripheral to the device... maybe none of these can be send? Or we need interior mutability?
/// Trait for functionality the platform should provide.
///
/// These methods provide things like random number generation and key value storage.
pub trait PlatformSupport: Send {
    /// Return the time of this platform
    fn get_time(&self) -> embassy_time::Instant;

    /// Retrieve the long term secret key.
    fn get_ltsk(&self) -> impl Future<Output = [u8; ED25519_LTSK]> + Send;

    /// Fill the specified buffer with random bytes from a cryptographically secure source.
    fn fill_random(&mut self, buffer: &mut [u8]) -> impl Future<Output = ()> + Send;

    /// Store a new pairing.
    fn store_pairing(
        &mut self,
        pairing: &Pairing,
    ) -> impl Future<Output = Result<(), InterfaceError>> + Send;

    /// Retrieve a pairing, or None if it doesn't exist.
    fn get_pairing(
        &mut self,
        id: &PairingId,
    ) -> impl Future<Output = Result<Option<Pairing>, InterfaceError>> + Send;

    /// Remove a pairing id.
    fn remove_pairing(
        &mut self,
        id: &PairingId,
    ) -> impl Future<Output = Result<(), InterfaceError>> + Send;

    /// Return a boolean indicating there is at least one pairing.
    fn is_paired(&mut self) -> impl Future<Output = Result<bool, InterfaceError>> + Send;

    /// Retrieve the global state number, this is used by the BLE transport.
    fn get_global_state_number(&self) -> impl Future<Output = Result<u16, InterfaceError>> + Send;
    /// Set the global state number, this is used by the BLE transport.
    fn set_global_state_number(
        &mut self,
        value: u16,
    ) -> impl Future<Output = Result<(), InterfaceError>> + Send;

    /// Advance the global state number by one, write the new value and return it.
    fn advance_global_state_number(
        &mut self,
    ) -> impl Future<Output = Result<u16, InterfaceError>> + Send {
        async move {
            let old = self.get_global_state_number().await?;
            let new = old.wrapping_add(1);
            let new = new.max(1); // overflow to 1, not to zero.
            self.set_global_state_number(new).await?;
            Ok(new)
        }
    }

    fn get_config_number(&self) -> impl Future<Output = Result<u8, InterfaceError>> + Send;
    fn set_config_number(
        &mut self,
        value: u8,
    ) -> impl Future<Output = Result<(), InterfaceError>> + Send;

    /// Retrieve the BLE broadcast parameters
    fn get_ble_broadcast_parameters(
        &self,
    ) -> impl Future<Output = Result<crate::ble::broadcast::BleBroadcastParameters, InterfaceError>> + Send;
    /// Set the BLE broadcast parameters
    fn set_ble_broadcast_parameters(
        &mut self,
        params: &crate::ble::broadcast::BleBroadcastParameters,
    ) -> impl Future<Output = Result<(), InterfaceError>> + Send;
}

#[derive(Debug)]
pub struct AccessoryContext {
    pub server: pairing::PairServer,
    pub info: pairing::SetupInfo,
    pub session: crate::Session,
    pub accessory: crate::AccessoryInformationStatic,
}
impl Default for AccessoryContext {
    fn default() -> Self {
        Self {
            server: Default::default(),
            info: Default::default(),
            session: Default::default(),
            accessory: Default::default(),
        }
    }
}
impl AccessoryContext {
    fn disconnect(&mut self) {
        self.session = Default::default();
        self.server.disconnect();
    }
    fn reset_secure_session(&mut self) {
        error!("resetting secure session.");
        self.session = Default::default()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    pub fn init() {
        let _ = env_logger::builder()
            .is_test(false)
            .filter_level(log::LevelFilter::max())
            .try_init();
    }

    #[test]
    fn test_setup_id() {
        init();
        let four_bytes = ['A' as u8, '0' as u8, 0, 230];
        let s = crate::SetupId::from(&four_bytes);
        assert_eq!(s.0[1], '0' as u8);
        info!("s: {s:?}");
        let setup_id = SetupId::from(&['7' as u8, 'O' as u8, 'S' as u8, 'X' as u8]);
        // verify round trip.
        assert_eq!(setup_id.0[0], '7' as u8);
        assert_eq!(setup_id.0[1], 'O' as u8);
        assert_eq!(setup_id.0[2], 'S' as u8);
        assert_eq!(setup_id.0[3], 'X' as u8);
    }

    #[test]
    fn test_setup_payload_uri() {
        init();
        let pair_code = PairCode::from_str("518-08-582").unwrap();
        let pair_code_n = PairCode::from_str("000-00-000").unwrap();
        let setup_id = SetupId::from(&['7' as u8, 'O' as u8, 'S' as u8, 'X' as u8]);
        let setup_id_n = SetupId::from(&['0' as u8, '0' as u8, '0' as u8, '0' as u8]);

        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Tests/HAPAccessorySetupGetSetupPayloadTest.c#L9-L14
        // The bottom one.
        assert_eq!(
            &setup_payload(&pair_code, &setup_id, 7.into()),
            "X-HM://0076CDMX27OSX"
        );
        println!("ble passes");

        // The other ones.
        // // first one.
        assert_eq!(
            &setup_payload(
                &pair_code,
                &setup_id,
                SetupPayloadProperties {
                    support_ip: true,
                    support_ble: false,
                    paired: false,
                    category: 7
                }
            ),
            "X-HM://0071WK4SM7OSX"
        );
        // second one.
        assert_eq!(
            &setup_payload(
                &pair_code_n,
                &setup_id_n,
                SetupPayloadProperties {
                    support_ip: true,
                    support_ble: false,
                    paired: false,
                    category: 7
                }
            ),
            "X-HM://00711PP1C0000"
        );
        // The third, paired one.
        assert_eq!(
            &setup_payload(
                &pair_code_n,
                &setup_id_n,
                SetupPayloadProperties {
                    support_ip: true,
                    support_ble: false,
                    paired: true,
                    category: 7
                }
            ),
            "X-HM://00739MG3K0000"
        );
    }
}
