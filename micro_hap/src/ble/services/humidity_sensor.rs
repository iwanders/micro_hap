use super::prelude::*;
use crate as micro_hap;

// This makes a lightbulb with a color temperature.
pub const SERVICE_ID_HUMIDITY_SENSOR: SvcId = SvcId(0x30);
pub const CHAR_ID_HUMIDITY_SENSOR_SIGNATURE: CharId = CharId(SERVICE_ID_HUMIDITY_SENSOR.0 + 1);
pub const CHAR_ID_HUMIDITY_SENSOR_VALUE: CharId = CharId(SERVICE_ID_HUMIDITY_SENSOR.0 + 2);

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPCharacteristicTypes.c#L23
pub const CHARACTERISTIC_CURRENT_RELATIVE_HUMIDITY: HomekitUuid16 = HomekitUuid16::new(0x0010);
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPServiceTypes.c#L51
pub const SERVICE_HUMIDITY_SENSOR: HomekitUuid16 = HomekitUuid16::new(0x82);

#[gatt_service(uuid = SERVICE_HUMIDITY_SENSOR)]
pub struct HumiditySensorService {
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = SERVICE_ID_HUMIDITY_SENSOR.0)]
    pub service_instance: u16,

    /// Service signature, only two bytes.
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=CHAR_ID_HUMIDITY_SENSOR_SIGNATURE.0.to_le_bytes())]
    pub service_signature: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_HUMIDITY_SENSOR_VALUE.0.to_le_bytes())]
    #[characteristic(uuid=CHARACTERISTIC_CURRENT_RELATIVE_HUMIDITY, read, write, indicate)]
    pub value: FacadeDummyType,
}

use micro_hap::ble::services::FacadeBleIds;

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct HumiditySensorServiceHandles {
    /// Handle for the service.
    pub svc_handle: SvcBleIds,

    pub service_signature: FacadeBleIds,
    pub value: FacadeBleIds,
}

impl HumiditySensorServiceHandles {
    pub fn to_service(&self) -> Result<micro_hap::Service, HapBleError> {
        let mut service = Service {
            ble_handle: Some(self.svc_handle.ble),
            uuid: SERVICE_HUMIDITY_SENSOR.into(),
            iid: self.svc_handle.hap,
            characteristics: Default::default(),
            properties: ServiceProperties::new().with_primary(true),
        };

        service
            .characteristics
            .push(
                Characteristic::new(
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

        // read, notify
        // float, min 0, max 100, steps 1
        // unit: percentage.
        service
            .characteristics
            .push(
                Characteristic::new(
                    CHARACTERISTIC_CURRENT_RELATIVE_HUMIDITY.into(),
                    self.value.hap,
                )
                .with_properties(
                    CharacteristicProperties::new()
                        .with_read(true)
                        .with_supports_event_notification(true)
                        .with_supports_disconnect_notification(true)
                        .with_supports_broadcast_notification(true),
                )
                .with_range(micro_hap::VariableRange {
                    start: micro_hap::VariableUnion::F32(0.0),
                    end: micro_hap::VariableUnion::F32(100.0),
                    inclusive: true,
                })
                .with_step(micro_hap::VariableUnion::F32(1.0))
                .with_ble_properties(
                    BleProperties::from_characteristic(self.value.ble)
                        .with_format(sig::Format::F32)
                        .with_unit(sig::Unit::Percentage),
                )
                .with_data(DataSource::AccessoryInterface),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}
impl HumiditySensorService {
    pub fn add_to_attribute_table<'d, M: RawMutex, const MAX: usize>(
        attribute_table: &mut AttributeTable<'d, M, MAX>,
        store: &'d mut [u8],
        service_instance: u16,
    ) -> Result<(&'d mut [u8], HumiditySensorServiceHandles), micro_hap::ble::BuilderError> {
        let service = trouble_host::attribute::Service::new(SERVICE_HUMIDITY_SENSOR);

        let mut service_builder = attribute_table.add_service(service);
        let service_hap_id = SvcId(service_instance);
        let iid = service_instance;

        let (mut service_builder, store, iid, _service_instance) =
            micro_hap::add_service_instance!(service_builder, iid, store);

        let (mut service_builder, store, iid, service_signature) = micro_hap::add_facade_characteristic!(
            service_builder,
            characteristic::SERVICE_SIGNATURE,
            iid,
            store
        );

        let (service_builder, store, iid, value) = micro_hap::add_facade_characteristic_indicate!(
            service_builder,
            CHARACTERISTIC_CURRENT_RELATIVE_HUMIDITY,
            iid,
            store
        );

        let _ = iid;

        let svc_handle = service_builder.build();

        let handles = HumiditySensorServiceHandles {
            svc_handle: SvcBleIds {
                hap: service_hap_id,
                ble: svc_handle,
            },
            service_signature,
            value,
        };

        Ok((store, handles))
    }

    pub fn to_handles(&self) -> HumiditySensorServiceHandles {
        // If you want another ID, you must copy the `gatt_service` section and replace the values in the descriptors
        // or use the builder.
        let hap_id = 0x30;
        HumiditySensorServiceHandles {
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
            value: CharBleIds {
                hap: CharId(hap_id + 0x02),
                ble: self.value,
            },
        }
    }

    pub fn populate_support(&self) -> Result<micro_hap::Service, HapBleError> {
        let handles = self.to_handles();
        handles.to_service()
    }
}
