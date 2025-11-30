use super::{HapBleError, HapBleService, sig};
use crate::{BleProperties, CharacteristicProperties, DataSource};
use crate::{CharId, SvcId};
use crate::{characteristic, descriptor, service};
use embassy_sync::blocking_mutex::raw::RawMutex;
use trouble_host::prelude::*;

// MUST have an instance id of 1, service 3e
#[gatt_service(uuid = service::ACCESSORY_INFORMATION)]
pub struct AccessoryInformationService {
    /// Service instance ID, must be a 16 bit unsigned integer.
    // Service instance id for accessory information must be 1, 0 is invalid.
    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAP.h#L3245-L3249
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=1u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 1)]
    pub service_instance: u16,

    // 0x14
    /// Identify routine, triggers something, it does not contain data.
    #[characteristic(uuid=characteristic::IDENTIFY, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=2u16.to_le_bytes())]
    pub identify: bool,

    // 0x20
    /// Manufacturer name that created the device.
    #[characteristic(uuid=characteristic::MANUFACTURER, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=3u16.to_le_bytes())]
    pub manufacturer: FacadeDummyType,

    // 0x21
    /// Manufacturer specific model, length must be greater than one.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=4u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::MODEL, read, write)]
    pub model: FacadeDummyType,

    // 0x0023
    /// Name for the device.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=5u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::NAME, read, write)]
    pub name: FacadeDummyType,

    //0x0030
    /// Manufacturer serial number, length must be greater than one.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=6u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::SERIAL_NUMBER, read, write)]
    pub serial_number: FacadeDummyType,

    //0x0052
    /// Firmware revision string; `<major>.<minor>.<revision>`
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=7u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::FIRMWARE_REVISION, read, write)]
    pub firmware_revision: FacadeDummyType,

    //0x0053
    /// Describes hardware revision string; `<major>.<minor>.<revision>`
    #[characteristic(uuid=characteristic::HARDWARE_REVISION, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=8u16.to_le_bytes())]
    pub hardware_revision: FacadeDummyType,

    // 4ab8811-ac7f-4340-bac3-fd6a85f9943b
    /// ADK version thing from the example,
    #[characteristic(uuid=characteristic::ADK_VERSION, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=9u16.to_le_bytes())]
    pub adk_version: FacadeDummyType,
}

use zerocopy::IntoBytes;

macro_rules! add_service_instance {
    (
        $service_builder:expr,
        $iid: expr,
        $store:expr
    ) => {{
        // #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 1)]
        // pub service_instance: u16,
        let readprops = &[CharacteristicProp::Read];
        let iid_value: u16 = $iid;
        let remaining_length = $store.len();
        let allocation_length = iid_value.as_bytes().len();
        let (value_store, store) = $store.split_at_mut_checked(allocation_length).ok_or(
            BuilderError::AttributeAllocationOverrun {
                remaining_length,
                allocation_length,
                characteristic_uuid: characteristic::SERVICE_INSTANCE.into(),
                name: stringify!(characteristic::SERVICE_INSTANCE),
            },
        )?;
        value_store.copy_from_slice(&iid_value.as_bytes());
        let characteristic = $service_builder
            .add_characteristic(
                characteristic::SERVICE_INSTANCE,
                readprops,
                iid_value,
                value_store,
            )
            .build();
        ($service_builder, store, iid_value + 1, characteristic)
    }};
}

macro_rules! add_facade_characteristic {
    (
        $service_builder:expr,
        $characteristic_uuid:expr,
        $iid: expr,
        $store:expr
    ) => {{
        {
            const READ_PROPS: &[CharacteristicProp] =
                &[CharacteristicProp::Read, CharacteristicProp::Write];
            const VALUE: [u8; 0] = [];
            let remaining_length = $store.len();
            let allocation_length: usize = VALUE.len();
            let (value_store, store) = $store.split_at_mut_checked(allocation_length).ok_or(
                BuilderError::AttributeAllocationOverrun {
                    remaining_length,
                    allocation_length,
                    characteristic_uuid: $characteristic_uuid.into(),
                    name: stringify!($characteristic_uuid),
                },
            )?;
            let mut characteristic_builder = $service_builder.add_characteristic(
                $characteristic_uuid,
                READ_PROPS,
                VALUE,
                value_store,
            );
            let iid_value: u16 = $iid;
            // let remaining_length = $store.len();
            let allocation_length = iid_value.as_bytes().len();
            let (value_store, store) = store.split_at_mut_checked(allocation_length).ok_or(
                BuilderError::AttributeAllocationOverrun {
                    remaining_length,
                    allocation_length,
                    characteristic_uuid: $characteristic_uuid.into(),
                    name: stringify!($characteristic_uuid),
                },
            )?;
            value_store.copy_from_slice(iid_value.as_bytes());
            let _descriptor_object = characteristic_builder
                .add_descriptor_ro::<u16, _>(descriptor::CHARACTERISTIC_INSTANCE_UUID, value_store);
            let characteristic = characteristic_builder.build();
            ($service_builder, store, iid_value + 1, characteristic)
        }
    }};
}

/// Error used by the accessory interface
#[derive(thiserror::Error, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BuilderError {
    #[error(
        "attribute allocation failed, needed {allocation_length}, had {remaining_length} in {name}({characteristic_uuid:?})"
    )]
    AttributeAllocationOverrun {
        remaining_length: usize,
        allocation_length: usize,
        characteristic_uuid: Uuid,
        name: &'static str,
    },
}

impl AccessoryInformationService {
    pub fn add_to_attribute_table<'d, M: RawMutex, const MAX: usize>(
        attribute_table: &mut AttributeTable<'d, M, MAX>,
        store: &'d mut [u8],
    ) -> Result<&'d mut [u8], BuilderError> {
        let service = trouble_host::attribute::Service::new(crate::service::ACCESSORY_INFORMATION);
        let mut service_builder = attribute_table.add_service(service);

        // Accessory information service MUST have a service instance of 1.
        let iid: u16 = 1;

        // #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 1)]
        // pub service_instance: u16,
        let (mut service_builder, store, iid, _chr_svc_instance) =
            add_service_instance!(service_builder, iid, store);

        // Identify is a bit of a special snowflake, we also don't really handle the identify request.

        // #[characteristic(uuid=characteristic::IDENTIFY, read, write)]
        // #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=2u16.to_le_bytes())]
        // pub identify: bool,
        let readprops = &[CharacteristicProp::Read, CharacteristicProp::Write];
        let value = false;
        let remaining_length = store.len();
        let allocation_length = value.as_bytes().len();
        let (value_store, store) = store.split_at_mut_checked(allocation_length).ok_or(
            BuilderError::AttributeAllocationOverrun {
                remaining_length,
                allocation_length,
                characteristic_uuid: characteristic::IDENTIFY.into(),
                name: stringify!(characteristic::IDENTIFY),
            },
        )?;
        let mut svc_ais_chr_identify_builder = service_builder.add_characteristic(
            characteristic::IDENTIFY,
            readprops,
            value,
            value_store,
        );
        let value = iid;
        let remaining_length = store.len();
        let allocation_length = value.as_bytes().len();
        let (value_store, store) = store.split_at_mut_checked(allocation_length).ok_or(
            BuilderError::AttributeAllocationOverrun {
                remaining_length,
                allocation_length,
                characteristic_uuid: characteristic::IDENTIFY.into(),
                name: stringify!(characteristic::IDENTIFY),
            },
        )?;
        let _svc_ais_chr_identify_descr = svc_ais_chr_identify_builder
            .add_descriptor_ro::<u16, _>(descriptor::CHARACTERISTIC_INSTANCE_UUID, value_store);
        let _z = svc_ais_chr_identify_builder.build();
        let iid = iid + 1;

        // 0x20
        // /// Manufacturer name that created the device.
        // #[characteristic(uuid=characteristic::MANUFACTURER, read, write)]
        // #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=3u16.to_le_bytes())]
        // pub manufacturer: FacadeDummyType,
        let (mut service_builder, store, iid, _chr_manufacturer) =
            add_facade_characteristic!(service_builder, characteristic::MANUFACTURER, iid, store);

        let (mut service_builder, store, iid, _chr_model) =
            add_facade_characteristic!(service_builder, characteristic::MODEL, iid, store);

        let (mut service_builder, store, iid, _chr_name) =
            add_facade_characteristic!(service_builder, characteristic::NAME, iid, store);

        let (mut service_builder, store, iid, _chr_serial) =
            add_facade_characteristic!(service_builder, characteristic::SERIAL_NUMBER, iid, store);
        let (mut service_builder, store, iid, _chr_firmware) = add_facade_characteristic!(
            service_builder,
            characteristic::FIRMWARE_REVISION,
            iid,
            store
        );
        let (mut service_builder, store, iid, _chr_hardware_rev) = add_facade_characteristic!(
            service_builder,
            characteristic::HARDWARE_REVISION,
            iid,
            store
        );
        let (mut service_builder, store, iid, _chr_adk_version) =
            add_facade_characteristic!(service_builder, characteristic::ADK_VERSION, iid, store);
        let _ = service_builder.build();

        Ok(store)
    }
}

impl HapBleService for AccessoryInformationService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::ACCESSORY_INFORMATION.into(),
            iid: SvcId(1),
            characteristics: Default::default(),
            properties: Default::default(),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::SERVICE_INSTANCE.into(), CharId(1))
                    .with_ble_properties(BleProperties::from_handle(self.service_instance.handle)),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::IDENTIFY.into(), CharId(2))
                    .with_properties(CharacteristicProperties::new().with_write(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.identify.handle)
                            .with_format(sig::Format::Boolean),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::MANUFACTURER.into(), CharId(3))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.manufacturer.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::MODEL.into(), CharId(4))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.model.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::NAME.into(), CharId(5))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.name.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::SERIAL_NUMBER.into(), CharId(6))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.serial_number.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::FIRMWARE_REVISION.into(), CharId(7))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.firmware_revision.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::HARDWARE_REVISION.into(), CharId(8))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.hardware_revision.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::ADK_VERSION.into(), CharId(9))
                    .with_properties(
                        CharacteristicProperties::new()
                            .with_read(true)
                            .with_hidden(true),
                    )
                    .with_ble_properties(
                        BleProperties::from_handle(self.adk_version.handle)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}

pub type FacadeDummyType = [u8; 0];

// 0xA2
#[gatt_service(uuid = service::PROTOCOL_INFORMATION)]
pub struct ProtocolInformationService {
    /// Service instance ID, must be a 16 bit unsigned integer.
    // May not be 1, value 1 is for accessory information.
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x02u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x10)]
    pub service_instance: u16,

    /// Service signature, only two bytes.
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=0x11u16.to_le_bytes())]
    pub service_signature: FacadeDummyType,

    /// Version string.
    #[characteristic(uuid=characteristic::VERSION, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x12u16.to_le_bytes())]
    pub version: FacadeDummyType,
}

impl ProtocolInformationService {
    pub fn add_to_attribute_table<'d, M: RawMutex, const MAX: usize>(
        attribute_table: &mut AttributeTable<'d, M, MAX>,
        store: &'d mut [u8],
    ) -> Result<&'d mut [u8], BuilderError> {
        let service = trouble_host::attribute::Service::new(crate::service::PROTOCOL_INFORMATION);
        let mut service_builder = attribute_table.add_service(service);

        let iid = 0x10;

        // /// Service instance ID, must be a 16 bit unsigned integer.
        // // May not be 1, value 1 is for accessory information.
        // //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x02u16.to_le_bytes())]
        // #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x10)]
        // pub service_instance: u16,
        let (mut service_builder, store, iid, _chr_svc_instance) =
            add_service_instance!(service_builder, iid, store);

        // /// Service signature, only two bytes.
        // #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
        // #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=0x11u16.to_le_bytes())]
        // pub service_signature: FacadeDummyType,
        let (mut service_builder, store, iid, _chr_service_sign) = add_facade_characteristic!(
            service_builder,
            characteristic::SERVICE_SIGNATURE,
            iid,
            store
        );

        // /// Version string.
        // #[characteristic(uuid=characteristic::VERSION, read, write)]
        // #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x12u16.to_le_bytes())]
        // pub version: FacadeDummyType,
        let (mut service_builder, store, iid, _chr_version) =
            add_facade_characteristic!(service_builder, characteristic::VERSION, iid, store);

        let _ = service_builder.build();

        Ok(store)
    }
}

impl HapBleService for ProtocolInformationService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAP.h#L3200
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::PROTOCOL_INFORMATION.into(),
            iid: SvcId(0x10),
            characteristics: Default::default(),
            properties: crate::ServiceProperties::new().with_configurable(true),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::SERVICE_SIGNATURE.into(), CharId(0x11))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.service_signature.handle)
                            .with_format_opaque(),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::VERSION.into(), CharId(0x12))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.version.handle)
                            .with_format(sig::Format::StringUtf8),
                    )
                    .with_data(crate::DataSource::Constant("2.2.0".as_bytes())),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}

#[gatt_service(uuid = service::PAIRING)]
pub struct PairingService {
    /// Service instance ID, must be a 16 bit unsigned integer.
    // May not be 1, value 1 is for accessory information.
    //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=[0x03, 0x01])]
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x20)]
    pub service_instance: u16,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x22u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::PAIRING_PAIR_SETUP, read, write)]
    pub pair_setup: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x23u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::PAIRING_PAIR_VERIFY, read, write)]
    pub pair_verify: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x24u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::PAIRING_FEATURES, read, write)]
    pub features: FacadeDummyType,

    // Paired read and write only.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x25u16.to_le_bytes())]
    #[characteristic(uuid=characteristic::PAIRING_PAIRINGS, read, write)]
    pub pairings: FacadeDummyType,
}

impl PairingService {
    pub fn add_to_attribute_table<'d, M: RawMutex, const MAX: usize>(
        attribute_table: &mut AttributeTable<'d, M, MAX>,
        store: &'d mut [u8],
    ) -> Result<&'d mut [u8], BuilderError> {
        let service = trouble_host::attribute::Service::new(crate::service::PAIRING);
        let mut service_builder = attribute_table.add_service(service);

        let iid = 0x20;

        let (mut service_builder, store, iid, _chr_svc_instance) =
            add_service_instance!(service_builder, iid, store);

        let (mut service_builder, store, iid, _chr_service_sign) = add_facade_characteristic!(
            service_builder,
            characteristic::PAIRING_PAIR_SETUP,
            iid,
            store
        );

        let (mut service_builder, store, iid, _chr_service_sign) = add_facade_characteristic!(
            service_builder,
            characteristic::PAIRING_PAIR_VERIFY,
            iid,
            store
        );

        let (mut service_builder, store, iid, _chr_service_sign) = add_facade_characteristic!(
            service_builder,
            characteristic::PAIRING_FEATURES,
            iid,
            store
        );

        let (mut service_builder, store, iid, _chr_service_sign) = add_facade_characteristic!(
            service_builder,
            characteristic::PAIRING_PAIRINGS,
            iid,
            store
        );
        service_builder.build();

        Ok(store)
    }
}

impl HapBleService for PairingService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::PAIRING.into(),
            iid: SvcId(0x20),
            characteristics: Default::default(),
            properties: Default::default(),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::PAIRING_PAIR_SETUP.into(), CharId(0x22))
                    .with_properties(CharacteristicProperties::new().with_open_rw(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.pair_setup.handle).with_format_opaque(),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::PAIRING_PAIR_VERIFY.into(),
                    CharId(0x23),
                )
                .with_properties(CharacteristicProperties::new().with_open_rw(true))
                .with_ble_properties(
                    BleProperties::from_handle(self.pair_verify.handle).with_format_opaque(),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::PAIRING_FEATURES.into(), CharId(0x24))
                    .with_properties(CharacteristicProperties::new().with_read_open(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.features.handle)
                            .with_format(crate::ble::sig::Format::U8),
                    )
                    .with_data(crate::DataSource::Constant(&[0])),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::PAIRING_PAIRINGS.into(), CharId(0x25))
                    .with_properties(CharacteristicProperties::new().with_rw(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.pairings.handle).with_format_opaque(),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
        Ok(service)
    }
}

// This service is merely here because it is used throughout the tests, it can be fully defined out of this crate.
// See the example_std/examples/example_rgb.rs example.
pub const CHAR_ID_LIGHTBULB_NAME: CharId = CharId(0x32);
pub const CHAR_ID_LIGHTBULB_ON: CharId = CharId(0x33);
#[gatt_service(uuid = service::LIGHTBULB)]
pub struct LightbulbService {
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x30)]
    pub service_instance: u16,

    /// Service signature, only two bytes.
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=0x31u16.to_le_bytes())]
    pub service_signature: FacadeDummyType,

    // 0x0023
    /// Name for the device.
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_LIGHTBULB_NAME.0.to_le_bytes())]
    #[characteristic(uuid=characteristic::NAME, read, write )]
    pub name: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_LIGHTBULB_ON.0.to_le_bytes())]
    #[characteristic(uuid=characteristic::ON, read, write, indicate )]
    pub on: FacadeDummyType,
}

impl LightbulbService {
    pub fn add_to_attribute_table<'d, M: RawMutex, const MAX: usize>(
        attribute_table: &mut AttributeTable<'d, M, MAX>,
        store: &'d mut [u8],
        service_instance: u16,
    ) -> Result<&'d mut [u8], BuilderError> {
        let service = trouble_host::attribute::Service::new(crate::service::LIGHTBULB);
        let mut service_builder = attribute_table.add_service(service);

        let iid = service_instance;

        let (mut service_builder, store, iid, _chr_svc_instance) =
            add_service_instance!(service_builder, iid, store);

        let (mut service_builder, store, iid, _chr_service_sign) =
            add_facade_characteristic!(service_builder, characteristic::NAME, iid, store);

        let (mut service_builder, store, iid, _chr_service_sign) =
            add_facade_characteristic!(service_builder, characteristic::ON, iid, store);

        service_builder.build();

        Ok(store)
    }
}

impl HapBleService for LightbulbService {
    fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.handle),
            uuid: service::LIGHTBULB.into(),
            iid: SvcId(0x30),
            characteristics: Default::default(),
            properties: crate::ServiceProperties::new().with_primary(true),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::SERVICE_SIGNATURE.into(),
                    CharId(0x31u16),
                )
                .with_properties(CharacteristicProperties::new().with_read(true))
                .with_ble_properties(
                    BleProperties::from_handle(self.service_signature.handle).with_format_opaque(),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::NAME.into(), CharId(0x32u16))
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.name.handle)
                            .with_format(sig::Format::StringUtf8),
                    )
                    .with_data(DataSource::AccessoryInterface),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::ON.into(), CharId(0x33u16))
                    .with_properties(
                        CharacteristicProperties::new()
                            .with_rw(true)
                            .with_supports_event_notification(true)
                            .with_supports_disconnect_notification(true)
                            .with_supports_broadcast_notification(true),
                    )
                    .with_ble_properties(
                        BleProperties::from_handle(self.on.handle)
                            .with_format(sig::Format::Boolean),
                    )
                    .with_data(DataSource::AccessoryInterface),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}
