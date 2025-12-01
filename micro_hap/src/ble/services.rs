use super::{HapBleError, HapBleService, sig};
use crate::{BleProperties, CharacteristicProperties, DataSource};
use crate::{CharId, SvcId};
use crate::{characteristic, descriptor, service};
use embassy_sync::blocking_mutex::raw::RawMutex;
use trouble_host::prelude::*;

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
        let char_id = CharId(iid_value);
        (
            $service_builder,
            store,
            iid_value + 1,
            CharBleIds {
                hap: char_id,
                ble: characteristic.handle,
            },
        )
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
            let char_id = CharId(iid_value);
            (
                $service_builder,
                store,
                iid_value + 1,
                CharBleIds {
                    hap: char_id,
                    ble: characteristic.handle,
                },
            )
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

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub struct SvcBleIds {
    pub hap: SvcId,
    pub ble: u16,
}
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub struct CharBleIds {
    pub hap: CharId,
    pub ble: u16,
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub struct AccessoryInformationServiceHandles {
    /// Handle for the service.
    pub svc_handle: SvcBleIds,

    // Handles for the remainder.
    pub service_instance: CharBleIds,
    pub identify: CharBleIds,
    pub manufacturer: CharBleIds,
    pub model: CharBleIds,
    pub name: CharBleIds,
    pub serial_number: CharBleIds,
    pub firmware_revision: CharBleIds,
    pub hardware_revision: CharBleIds,
    pub adk_version: CharBleIds,
}
impl AccessoryInformationServiceHandles {
    pub fn to_service(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.svc_handle.ble),
            uuid: service::ACCESSORY_INFORMATION.into(),
            iid: self.svc_handle.hap,
            characteristics: Default::default(),
            properties: Default::default(),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::SERVICE_INSTANCE.into(),
                    self.service_instance.hap,
                )
                .with_ble_properties(BleProperties::from_handle(self.service_instance.ble)),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::IDENTIFY.into(), self.identify.hap)
                    .with_properties(CharacteristicProperties::new().with_write(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.identify.ble)
                            .with_format(sig::Format::Boolean),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::MANUFACTURER.into(),
                    self.manufacturer.hap,
                )
                .with_properties(CharacteristicProperties::new().with_read(true))
                .with_ble_properties(
                    BleProperties::from_handle(self.manufacturer.ble)
                        .with_format(sig::Format::StringUtf8),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::MODEL.into(), self.model.hap)
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.model.ble)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::NAME.into(), self.name.hap)
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.name.ble)
                            .with_format(sig::Format::StringUtf8),
                    ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::SERIAL_NUMBER.into(),
                    self.serial_number.hap,
                )
                .with_properties(CharacteristicProperties::new().with_read(true))
                .with_ble_properties(
                    BleProperties::from_handle(self.serial_number.ble)
                        .with_format(sig::Format::StringUtf8),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::FIRMWARE_REVISION.into(),
                    self.firmware_revision.hap,
                )
                .with_properties(CharacteristicProperties::new().with_read(true))
                .with_ble_properties(
                    BleProperties::from_handle(self.firmware_revision.ble)
                        .with_format(sig::Format::StringUtf8),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::HARDWARE_REVISION.into(),
                    self.hardware_revision.hap,
                )
                .with_properties(CharacteristicProperties::new().with_read(true))
                .with_ble_properties(
                    BleProperties::from_handle(self.hardware_revision.ble)
                        .with_format(sig::Format::StringUtf8),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::ADK_VERSION.into(),
                    self.adk_version.hap,
                )
                .with_properties(
                    CharacteristicProperties::new()
                        .with_read(true)
                        .with_hidden(true),
                )
                .with_ble_properties(
                    BleProperties::from_handle(self.adk_version.ble)
                        .with_format(sig::Format::StringUtf8),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}

impl AccessoryInformationService {
    /// This is a free function that uses the builder to generate gatt table for this service.
    pub fn add_to_attribute_table<'d, M: RawMutex, const MAX: usize>(
        attribute_table: &mut AttributeTable<'d, M, MAX>,
        store: &'d mut [u8],
    ) -> Result<(&'d mut [u8], AccessoryInformationServiceHandles), BuilderError> {
        let service = trouble_host::attribute::Service::new(crate::service::ACCESSORY_INFORMATION);
        let mut service_builder = attribute_table.add_service(service);

        // Accessory information service MUST have a service instance of 1.
        let iid: u16 = 1;

        // #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 1)]
        // pub service_instance: u16,
        let (mut service_builder, store, iid, service_instance) =
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
        let chr_identify = svc_ais_chr_identify_builder.build();
        let charid_identify = CharId(iid);
        let handle_identify = chr_identify.handle;
        let iid = iid + 1;

        // 0x20
        // /// Manufacturer name that created the device.
        // #[characteristic(uuid=characteristic::MANUFACTURER, read, write)]
        // #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=3u16.to_le_bytes())]
        // pub manufacturer: FacadeDummyType,
        let (mut service_builder, store, iid, chr_manufacturer) =
            add_facade_characteristic!(service_builder, characteristic::MANUFACTURER, iid, store);

        let (mut service_builder, store, iid, chr_model) =
            add_facade_characteristic!(service_builder, characteristic::MODEL, iid, store);

        let (mut service_builder, store, iid, chr_name) =
            add_facade_characteristic!(service_builder, characteristic::NAME, iid, store);

        let (mut service_builder, store, iid, chr_serial) =
            add_facade_characteristic!(service_builder, characteristic::SERIAL_NUMBER, iid, store);
        let (mut service_builder, store, iid, chr_firmware) = add_facade_characteristic!(
            service_builder,
            characteristic::FIRMWARE_REVISION,
            iid,
            store
        );
        let (mut service_builder, store, iid, chr_hardware_rev) = add_facade_characteristic!(
            service_builder,
            characteristic::HARDWARE_REVISION,
            iid,
            store
        );
        let (service_builder, store, iid, chr_adk_version) =
            add_facade_characteristic!(service_builder, characteristic::ADK_VERSION, iid, store);
        let svc_handle = service_builder.build();
        let _ = iid;

        let handles = AccessoryInformationServiceHandles {
            svc_handle: SvcBleIds {
                hap: SvcId(1),
                ble: svc_handle,
            },
            service_instance,
            identify: CharBleIds {
                hap: charid_identify,
                ble: handle_identify,
            },
            manufacturer: chr_manufacturer,
            model: chr_model,
            name: chr_name,
            serial_number: chr_serial,
            firmware_revision: chr_firmware,
            hardware_revision: chr_hardware_rev,
            adk_version: chr_adk_version,
        };

        Ok((store, handles))
    }

    pub fn to_handles(&self) -> AccessoryInformationServiceHandles {
        AccessoryInformationServiceHandles {
            svc_handle: SvcBleIds {
                hap: SvcId(1),
                ble: self.handle,
            },
            service_instance: CharBleIds {
                hap: CharId(1),
                ble: self.service_instance.handle,
            },
            identify: CharBleIds {
                hap: CharId(2),
                ble: self.identify.handle,
            },
            manufacturer: CharBleIds {
                hap: CharId(3),
                ble: self.manufacturer.handle,
            },
            model: CharBleIds {
                hap: CharId(4),
                ble: self.model.handle,
            },
            name: CharBleIds {
                hap: CharId(5),
                ble: self.name.handle,
            },
            serial_number: CharBleIds {
                hap: CharId(6),
                ble: self.serial_number.handle,
            },
            firmware_revision: CharBleIds {
                hap: CharId(7),
                ble: self.firmware_revision.handle,
            },
            hardware_revision: CharBleIds {
                hap: CharId(8),
                ble: self.hardware_revision.handle,
            },
            adk_version: CharBleIds {
                hap: CharId(9),
                ble: self.adk_version.handle,
            },
        }
    }

    pub fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let handles = self.to_handles();
        handles.to_service()
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

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub struct ProtocolInformationServiceHandles {
    /// Handle for the service.
    pub svc_handle: SvcBleIds,

    // Handles for the remainder.
    // pub service_instance: CharBleIds,
    pub service_signature: CharBleIds,
    pub version: CharBleIds,
}
impl ProtocolInformationServiceHandles {
    pub fn to_service(&self) -> Result<crate::Service, HapBleError> {
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAP.h#L3200
        let mut service = crate::Service {
            ble_handle: Some(self.svc_handle.ble),
            uuid: service::PROTOCOL_INFORMATION.into(),
            iid: self.svc_handle.hap,
            characteristics: Default::default(),
            properties: crate::ServiceProperties::new().with_configurable(true),
        };

        /*
        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::SERVICE_INSTANCE.into(),
                    self.service_instance.hap,
                )
                .with_ble_properties(BleProperties::from_handle(self.service_instance.ble)),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
            */

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::SERVICE_SIGNATURE.into(),
                    self.service_signature.hap,
                )
                .with_properties(CharacteristicProperties::new().with_read(true))
                .with_ble_properties(
                    BleProperties::from_handle(self.service_signature.ble).with_format_opaque(),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::VERSION.into(), self.version.hap)
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.version.ble)
                            .with_format(sig::Format::StringUtf8),
                    )
                    .with_data(crate::DataSource::Constant("2.2.0".as_bytes())),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}

impl ProtocolInformationService {
    pub fn add_to_attribute_table<'d, M: RawMutex, const MAX: usize>(
        attribute_table: &mut AttributeTable<'d, M, MAX>,
        store: &'d mut [u8],
    ) -> Result<(&'d mut [u8], ProtocolInformationServiceHandles), BuilderError> {
        let service = trouble_host::attribute::Service::new(crate::service::PROTOCOL_INFORMATION);
        let mut service_builder = attribute_table.add_service(service);
        // Lets just also start this one at the value from the reference, I see no reason to change this.
        let service_hap_id = SvcId(0x10);

        let iid = 0x10;

        // /// Service instance ID, must be a 16 bit unsigned integer.
        // // May not be 1, value 1 is for accessory information.
        // //#[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x02u16.to_le_bytes())]
        // #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 0x10)]
        // pub service_instance: u16,
        let (mut service_builder, store, iid, service_instance) =
            add_service_instance!(service_builder, iid, store);

        // /// Service signature, only two bytes.
        // #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
        // #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=0x11u16.to_le_bytes())]
        // pub service_signature: FacadeDummyType,
        let (mut service_builder, store, iid, service_signature) = add_facade_characteristic!(
            service_builder,
            characteristic::SERVICE_SIGNATURE,
            iid,
            store
        );

        // /// Version string.
        // #[characteristic(uuid=characteristic::VERSION, read, write)]
        // #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=0x12u16.to_le_bytes())]
        // pub version: FacadeDummyType,
        let (service_builder, store, iid, version) =
            add_facade_characteristic!(service_builder, characteristic::VERSION, iid, store);
        let _ = iid;

        let svc_handle = service_builder.build();

        let handles = ProtocolInformationServiceHandles {
            svc_handle: SvcBleIds {
                hap: service_hap_id,
                ble: svc_handle,
            },
            // service_instance,
            service_signature,
            version,
        };

        Ok((store, handles))
    }

    pub fn to_handles(&self) -> ProtocolInformationServiceHandles {
        ProtocolInformationServiceHandles {
            svc_handle: SvcBleIds {
                hap: SvcId(0x10),
                ble: self.handle,
            },
            // service_instance: CharBleIds {
            //     hap: CharId(1),
            //     ble: self.service_instance.handle,
            // },
            service_signature: CharBleIds {
                hap: CharId(0x11),
                ble: self.service_signature.handle,
            },
            version: CharBleIds {
                hap: CharId(0x12),
                ble: self.version.handle,
            },
        }
    }

    pub fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let handles = self.to_handles();
        handles.to_service()
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

#[cfg(test)]
mod test {
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

    use super::*;

    #[test]
    fn test_service_accessory_information_identical() {
        crate::test::init();
        if !std::env::var("RUN_GATT_TABLE_TEST").is_ok() {
            warn!("Skipping test because `RUN_GATT_TABLE_TEST` is not set");
            info!(
                "Run this test with RUN_GATT_TABLE_TEST=1 cargo t -- test_service_accessory_information_identical"
            );
            return;
        }

        let mut attribute_buffer = [0u8; 1024];

        const ATTRIBUTE_TABLE_SIZE: usize = 1024;
        let mut attribute_table1 = trouble_host::attribute::AttributeTable::<
            CriticalSectionRawMutex,
            ATTRIBUTE_TABLE_SIZE,
        >::new();

        let (remaining_buffer, handles) = AccessoryInformationService::add_to_attribute_table(
            &mut attribute_table1,
            &mut attribute_buffer,
        )
        .unwrap();

        let mut attribute_table2 = trouble_host::attribute::AttributeTable::<
            CriticalSectionRawMutex,
            ATTRIBUTE_TABLE_SIZE,
        >::new();

        let from_macro = AccessoryInformationService::new(&mut attribute_table2);
        let handles_from_macro = from_macro.to_handles();

        info!("handles: {handles:?}");
        info!("handles_from_macro: {handles_from_macro:?}");
        assert_eq!(handles, handles_from_macro);
    }

    #[test]
    fn test_service_protocol_identical() {
        crate::test::init();
        if !std::env::var("RUN_GATT_TABLE_TEST").is_ok() {
            warn!("Skipping test because `RUN_GATT_TABLE_TEST` is not set");
            info!(
                "Run this test with RUN_GATT_TABLE_TEST=1 cargo t -- test_service_protocol_identical"
            );
            return;
        }

        let mut attribute_buffer = [0u8; 1024];

        const ATTRIBUTE_TABLE_SIZE: usize = 1024;
        let mut attribute_table1 = trouble_host::attribute::AttributeTable::<
            CriticalSectionRawMutex,
            ATTRIBUTE_TABLE_SIZE,
        >::new();

        let (remaining_buffer, handles) = ProtocolInformationService::add_to_attribute_table(
            &mut attribute_table1,
            &mut attribute_buffer,
        )
        .unwrap();

        let mut attribute_table2 = trouble_host::attribute::AttributeTable::<
            CriticalSectionRawMutex,
            ATTRIBUTE_TABLE_SIZE,
        >::new();

        let from_macro = ProtocolInformationService::new(&mut attribute_table2);
        let handles_from_macro = from_macro.to_handles();

        info!("handles: {handles:?}");
        info!("handles_from_macro: {handles_from_macro:?}");
        assert_eq!(handles, handles_from_macro);
    }
}
