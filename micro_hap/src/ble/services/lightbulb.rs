use super::prelude::*;

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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct LightbulbServiceHandles {
    /// Handle for the service.
    pub svc_handle: SvcBleIds,

    // Handles for the remainder.
    // pub service_instance: CharBleIds, // not a bug, this is missing in the HAP characteristics!
    pub service_signature: FacadeBleIds,
    pub name: FacadeBleIds,
    pub on: FacadeBleIds,
}
impl LightbulbServiceHandles {
    pub fn to_service(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.svc_handle.ble),
            uuid: service::LIGHTBULB.into(),
            iid: self.svc_handle.hap,
            characteristics: Default::default(),
            properties: crate::ServiceProperties::new().with_primary(true),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::SERVICE_SIGNATURE.into(),
                    self.service_signature.hap,
                )
                .with_properties(CharacteristicProperties::new().with_read(true))
                .with_ble_properties(
                    BleProperties::from_characteristic(self.service_signature.ble)
                        .with_format_opaque(),
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
                    )
                    .with_data(DataSource::AccessoryInterface),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(characteristic::ON.into(), self.on.hap)
                    .with_properties(
                        CharacteristicProperties::new()
                            .with_rw(true)
                            .with_supports_event_notification(true)
                            .with_supports_disconnect_notification(true)
                            .with_supports_broadcast_notification(true),
                    )
                    .with_ble_properties(
                        BleProperties::from_characteristic(self.on.ble)
                            .with_format(sig::Format::Boolean),
                    )
                    .with_data(DataSource::AccessoryInterface),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}

impl LightbulbService {
    pub fn add_to_attribute_table<'d, M: RawMutex, const MAX: usize>(
        attribute_table: &mut AttributeTable<'d, M, MAX>,
        store: &'d mut [u8],
        service_instance: u16,
    ) -> Result<(&'d mut [u8], LightbulbServiceHandles), BuilderError> {
        let service = trouble_host::attribute::Service::new(crate::service::LIGHTBULB);

        let mut service_builder = attribute_table.add_service(service);
        let service_hap_id = SvcId(service_instance);
        let iid = service_instance;

        let (mut service_builder, store, iid, _service_instance) =
            add_service_instance!(service_builder, iid, store);

        let (mut service_builder, store, iid, service_signature) = add_facade_characteristic!(
            service_builder,
            characteristic::SERVICE_SIGNATURE,
            iid,
            store
        );

        let (mut service_builder, store, iid, name) =
            add_facade_characteristic!(service_builder, characteristic::NAME, iid, store);

        let (service_builder, store, iid, on) =
            add_facade_characteristic_indicate!(service_builder, characteristic::ON, iid, store);
        let _ = iid;

        let svc_handle = service_builder.build();

        let handles = LightbulbServiceHandles {
            svc_handle: SvcBleIds {
                hap: service_hap_id,
                ble: svc_handle,
            },
            // service_instance,
            service_signature,
            name,
            on,
        };

        Ok((store, handles))
    }
    pub fn to_handles(&self) -> LightbulbServiceHandles {
        self.to_handles_offset(0x30)
    }
    pub fn to_handles_offset(&self, hap_id: u16) -> LightbulbServiceHandles {
        LightbulbServiceHandles {
            svc_handle: SvcBleIds {
                hap: SvcId(hap_id + 0x00),
                ble: self.handle,
            },
            // service_instance: CharBleIds {
            //     hap: CharId(0x31),
            //     ble: self.service_instance.handle,
            // },
            service_signature: CharBleIds {
                hap: CharId(hap_id + 0x01),
                ble: self.service_signature,
            },
            name: CharBleIds {
                hap: CharId(hap_id + 0x02),
                ble: self.name,
            },
            on: CharBleIds {
                hap: CharId(hap_id + 0x03),
                ble: self.on,
            },
        }
    }

    pub fn populate_support(&self) -> Result<crate::Service, HapBleError> {
        let handles = self.to_handles();
        handles.to_service()
    }
    pub fn populate_support_offset(&self, hap_id: u16) -> Result<crate::Service, HapBleError> {
        let handles = self.to_handles_offset(hap_id);
        handles.to_service()
    }
}

#[cfg(test)]
mod test {
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

    use super::*;

    #[test]
    fn test_service_lightbulb_identical() {
        crate::test::init();
        if !std::env::var("RUN_GATT_TABLE_TEST").is_ok() {
            // Running this test in parallel with the 'master' test_exchange test fails because AccessoryInformationService
            // has a static cell and that can't be reinitialised.
            warn!("Skipping test because `RUN_GATT_TABLE_TEST` is not set");
            info!(
                "Run this test with RUN_GATT_TABLE_TEST=1 cargo t -- test_service_lightbulb_identical"
            );
            return;
        }

        let mut attribute_buffer = [0u8; 1024];

        const ATTRIBUTE_TABLE_SIZE: usize = 1024;
        let mut attribute_table1 = trouble_host::attribute::AttributeTable::<
            CriticalSectionRawMutex,
            ATTRIBUTE_TABLE_SIZE,
        >::new();

        let svc_start = 0x30;
        let (_remaining_buffer, handles) = LightbulbService::add_to_attribute_table(
            &mut attribute_table1,
            &mut attribute_buffer,
            svc_start,
        )
        .unwrap();

        let mut attribute_table2 = trouble_host::attribute::AttributeTable::<
            CriticalSectionRawMutex,
            ATTRIBUTE_TABLE_SIZE,
        >::new();

        let from_macro = LightbulbService::new(&mut attribute_table2);
        let handles_from_macro = from_macro.to_handles();

        info!("handles: {handles:?}");
        info!("handles_from_macro: {handles_from_macro:?}");
        assert_eq!(handles, handles_from_macro);
    }
}
