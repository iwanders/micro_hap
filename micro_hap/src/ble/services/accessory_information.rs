use super::prelude::*;

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

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct AccessoryInformationServiceHandles {
    /// Handle for the service.
    pub svc_handle: SvcBleIds,

    // Handles for the remainder.
    pub service_instance: ServiceInstanceBleIds,
    pub identify: CharBleIds<bool>,
    pub manufacturer: FacadeBleIds,
    pub model: FacadeBleIds,
    pub name: FacadeBleIds,
    pub serial_number: FacadeBleIds,
    pub firmware_revision: FacadeBleIds,
    pub hardware_revision: FacadeBleIds,
    pub adk_version: FacadeBleIds,
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
                .with_ble_properties(BleProperties::from_handle(self.service_instance.ble.handle)),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::IDENTIFY.into(), self.identify.hap)
                    .with_properties(CharacteristicProperties::new().with_write(true))
                    .with_ble_properties(
                        BleProperties::from_handle(self.identify.ble.handle)
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
                    BleProperties::from_characteristic(self.manufacturer.ble)
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
                        BleProperties::from_characteristic(self.model.ble)
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
                        BleProperties::from_characteristic(self.name.ble)
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
                    BleProperties::from_characteristic(self.serial_number.ble)
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
                    BleProperties::from_characteristic(self.firmware_revision.ble)
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
                    BleProperties::from_characteristic(self.hardware_revision.ble)
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
                    BleProperties::from_characteristic(self.adk_version.ble)
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
        let allocation_length = trouble_host::types::gatt_traits::AsGatt::as_gatt(&value).len();
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
        let allocation_length = trouble_host::types::gatt_traits::AsGatt::as_gatt(&value).len();
        let (value_store, store) = store.split_at_mut_checked(allocation_length).ok_or(
            BuilderError::AttributeAllocationOverrun {
                remaining_length,
                allocation_length,
                characteristic_uuid: characteristic::IDENTIFY.into(),
                name: stringify!(characteristic::IDENTIFY),
            },
        )?;
        value_store.copy_from_slice(trouble_host::types::gatt_traits::AsGatt::as_gatt(&value));
        let _svc_ais_chr_identify_descr = svc_ais_chr_identify_builder
            .add_descriptor_ro::<u16, _>(descriptor::CHARACTERISTIC_INSTANCE_UUID, value_store);
        let chr_identify = svc_ais_chr_identify_builder.build();
        let charid_identify = CharId(iid);
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
                ble: chr_identify,
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
                ble: self.service_instance,
            },
            identify: CharBleIds {
                hap: CharId(2),
                ble: self.identify,
            },
            manufacturer: CharBleIds {
                hap: CharId(3),
                ble: self.manufacturer,
            },
            model: CharBleIds {
                hap: CharId(4),
                ble: self.model,
            },
            name: CharBleIds {
                hap: CharId(5),
                ble: self.name,
            },
            serial_number: CharBleIds {
                hap: CharId(6),
                ble: self.serial_number,
            },
            firmware_revision: CharBleIds {
                hap: CharId(7),
                ble: self.firmware_revision,
            },
            hardware_revision: CharBleIds {
                hap: CharId(8),
                ble: self.hardware_revision,
            },
            adk_version: CharBleIds {
                hap: CharId(9),
                ble: self.adk_version,
            },
        }
    }

    pub fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let handles = self.to_handles();
        handles.to_service()
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
            // Running this test in parallel with the 'master' test_exchange test fails because AccessoryInformationService
            // has a static cell and that can't be reinitialised.
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

        let (_remaining_buffer, handles) = AccessoryInformationService::add_to_attribute_table(
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
}
