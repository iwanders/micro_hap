use super::prelude::*;

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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct PairingServiceHandles {
    /// Handle for the service.
    pub svc_handle: SvcBleIds,

    // Handles for the remainder.
    // pub service_instance: CharBleIds, // not a bug, this is missing in the HAP characteristics!
    pub pair_setup: FacadeBleIds,
    pub pair_verify: FacadeBleIds,
    pub features: FacadeBleIds,
    pub pairings: FacadeBleIds,
}
impl PairingServiceHandles {
    pub fn to_service(&self) -> Result<crate::Service, HapBleError> {
        let mut service = crate::Service {
            ble_handle: Some(self.svc_handle.ble),
            uuid: service::PAIRING.into(),
            iid: self.svc_handle.hap,
            characteristics: Default::default(),
            properties: Default::default(),
        };

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::PAIRING_PAIR_SETUP.into(),
                    self.pair_setup.hap,
                )
                .with_properties(CharacteristicProperties::new().with_open_rw(true))
                .with_ble_properties(
                    BleProperties::from_characteristic(self.pair_setup.ble).with_format_opaque(),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::PAIRING_PAIR_VERIFY.into(),
                    self.pair_verify.hap,
                )
                .with_properties(CharacteristicProperties::new().with_open_rw(true))
                .with_ble_properties(
                    BleProperties::from_characteristic(self.pair_verify.ble).with_format_opaque(),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::PAIRING_FEATURES.into(),
                    self.features.hap,
                )
                .with_properties(CharacteristicProperties::new().with_read_open(true))
                .with_ble_properties(
                    BleProperties::from_characteristic(self.features.ble)
                        .with_format(crate::ble::sig::Format::U8),
                )
                .with_data(crate::DataSource::Constant(&[0])),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
        service
            .characteristics
            .push(
                crate::Characteristic::new(
                    characteristic::PAIRING_PAIRINGS.into(),
                    self.pairings.hap,
                )
                .with_properties(CharacteristicProperties::new().with_rw(true))
                .with_ble_properties(
                    BleProperties::from_characteristic(self.pairings.ble).with_format_opaque(),
                ),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;
        Ok(service)
    }
}

impl PairingService {
    pub fn add_to_attribute_table<'d, M: RawMutex, const MAX: usize>(
        attribute_table: &mut AttributeTable<'d, M, MAX>,
        store: &'d mut [u8],
    ) -> Result<(&'d mut [u8], PairingServiceHandles), BuilderError> {
        let service = trouble_host::attribute::Service::new(crate::service::PAIRING);
        let mut service_builder = attribute_table.add_service(service);
        let service_hap_id = SvcId(0x20);
        let iid = 0x20;

        let (mut service_builder, store, iid, _service_instance) =
            add_service_instance!(service_builder, iid, store);
        // iid == 21 now

        // Not a bug, this is super weird, no service signature characteristic, yet we still jump:
        // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Applications/Lightbulb/DB.c#L33-L37
        // #define kIID_Pairing                ((uint64_t) 0x0020)
        // #define kIID_PairingPairSetup       ((uint64_t) 0x0022)
        let iid = iid + 1;
        // iid is 22 now.

        let (mut service_builder, store, iid, pair_setup) = add_facade_characteristic!(
            service_builder,
            characteristic::PAIRING_PAIR_SETUP,
            iid,
            store
        );

        let (mut service_builder, store, iid, pair_verify) = add_facade_characteristic!(
            service_builder,
            characteristic::PAIRING_PAIR_VERIFY,
            iid,
            store
        );

        let (mut service_builder, store, iid, features) = add_facade_characteristic!(
            service_builder,
            characteristic::PAIRING_FEATURES,
            iid,
            store
        );

        let (service_builder, store, iid, pairings) = add_facade_characteristic!(
            service_builder,
            characteristic::PAIRING_PAIRINGS,
            iid,
            store
        );
        let _ = iid;
        let svc_handle = service_builder.build();

        let handles = PairingServiceHandles {
            svc_handle: SvcBleIds {
                hap: service_hap_id,
                ble: svc_handle,
            },
            // service_instance,
            pair_setup,
            pair_verify,
            features,
            pairings,
        };

        Ok((store, handles))
    }
    pub fn to_handles(&self) -> PairingServiceHandles {
        PairingServiceHandles {
            svc_handle: SvcBleIds {
                hap: SvcId(0x20),
                ble: self.handle,
            },
            // service_instance: CharBleIds {
            //     hap: CharId(0x21),
            //     ble: self.service_instance.handle,
            // },
            pair_setup: CharBleIds {
                hap: CharId(0x22),
                ble: self.pair_setup,
            },
            pair_verify: CharBleIds {
                hap: CharId(0x23),
                ble: self.pair_verify,
            },
            features: CharBleIds {
                hap: CharId(0x24),
                ble: self.features,
            },
            pairings: CharBleIds {
                hap: CharId(0x25),
                ble: self.pairings,
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
    fn test_service_pairing_identical() {
        crate::test::init();
        if !std::env::var("RUN_GATT_TABLE_TEST").is_ok() {
            // Running this test in parallel with the 'master' test_exchange test fails because AccessoryInformationService
            // has a static cell and that can't be reinitialised.
            warn!("Skipping test because `RUN_GATT_TABLE_TEST` is not set");
            info!(
                "Run this test with RUST_LOG=trace  RUN_GATT_TABLE_TEST=1 cargo t  --features log -- --nocapture  -- test_service_pairing_identical"
            );
            return;
        }

        let mut attribute_buffer = [0u8; 1024];

        const ATTRIBUTE_TABLE_SIZE: usize = 1024;
        let mut attribute_table1 = trouble_host::attribute::AttributeTable::<
            CriticalSectionRawMutex,
            ATTRIBUTE_TABLE_SIZE,
        >::new();

        let (_remaining_buffer, handles) =
            PairingService::add_to_attribute_table(&mut attribute_table1, &mut attribute_buffer)
                .unwrap();

        let mut attribute_table2 = trouble_host::attribute::AttributeTable::<
            CriticalSectionRawMutex,
            ATTRIBUTE_TABLE_SIZE,
        >::new();

        let from_macro = PairingService::new(&mut attribute_table2);
        let handles_from_macro = from_macro.to_handles();

        info!("handles: {handles:?}");
        info!("handles_from_macro: {handles_from_macro:?}");
        assert_eq!(handles, handles_from_macro);
    }
}
