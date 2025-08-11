#![cfg_attr(not(test), no_std)]

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

#[cfg(test)]
extern crate std;

pub mod adv;
pub mod characteristic;
pub mod descriptor;
pub mod service;
pub mod uuid;

pub mod ble;
pub mod http;

// We probably should handle some gatt reads manually with:
// https://github.com/embassy-rs/trouble/pull/311
//

// This is also a bit of a problem;
// https://github.com/embassy-rs/trouble/issues/375
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

/// Helper to set all accessory information from static values in bulk.
#[derive(Copy, Clone, Debug)]
pub struct AccessoryInformationStatic {
    pub hardware_revision: &'static str,
    pub serial_number: &'static str,
    //pub service_instance: u16,
    pub model: &'static str,
    pub name: &'static str,
    pub manufacturer: &'static str,
    pub firmware_revision: &'static str,
}
impl Default for AccessoryInformationStatic {
    fn default() -> Self {
        Self {
            hardware_revision: "0.0.1",
            serial_number: "1234567890ABC",
            //service_instance: 0,
            model: "AmazingDevice",
            name: "Trouble_HAP",
            manufacturer: "TestManufacturer",
            firmware_revision: "0.0.1",
        }
    }
}
