use super::prelude::*;

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

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct ProtocolInformationServiceHandles {
    /// Handle for the service.
    pub svc_handle: SvcBleIds,

    // Handles for the remainder.
    // pub service_instance: CharBleIds, // not a bug, this is missing in the HAP characteristics!
    pub service_signature: FacadeBleIds,
    pub version: FacadeBleIds,
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

        // This is NOT a bug, adding this as a characteristic is not what the reference does.
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
                    BleProperties::from_handle(self.service_signature.ble.handle)
                        .with_format_opaque(),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::VERSION.into(), self.version.hap)
                    .with_properties(CharacteristicProperties::new().with_read(true))
                    .with_ble_properties(
                        BleProperties::from_characteristic(self.version.ble)
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
        let (mut service_builder, store, iid, _service_instance) =
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
            //     hap: CharId(0x10),
            //     ble: self.service_instance.handle,
            // },
            service_signature: CharBleIds {
                hap: CharId(0x11),
                ble: self.service_signature,
            },
            version: CharBleIds {
                hap: CharId(0x12),
                ble: self.version,
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
    fn test_service_protocol_identical() {
        crate::test::init();
        if !std::env::var("RUN_GATT_TABLE_TEST").is_ok() {
            // Running this test in parallel with the 'master' test_exchange test fails because AccessoryInformationService
            // has a static cell and that can't be reinitialised.
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

        let (_remaining_buffer, handles) = ProtocolInformationService::add_to_attribute_table(
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
