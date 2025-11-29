// THis is a verbatim copy of the temperature sensor from the example_std temperature sensor.
use micro_hap::{
    ble::{sig, FacadeDummyType, HapBleError},
    characteristic, descriptor,
    uuid::HomekitUuid16,
    BleProperties, CharId, Characteristic, CharacteristicProperties, DataSource, Service,
    ServiceProperties, SvcId,
};
use trouble_host::prelude::*;

// This makes a lightbulb with a color temperature.
pub const SERVICE_ID_TEMP_SENSOR: SvcId = SvcId(0x40);
pub const CHAR_ID_TEMP_SENSOR_SIGNATURE: CharId = CharId(0x41);
pub const CHAR_ID_TEMP_SENSOR_VALUE: CharId = CharId(0x42);
pub const CHAR_ID_TEMP_LOW_BATTERY: CharId = CharId(0x43);

// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPCharacteristicTypes.c#L23
// This always displays in 0.5 degree increments, to check is if the other temperature allows more precision.
pub const CHARACTERISTIC_CURRENT_TEMPERATURE: HomekitUuid16 = HomekitUuid16::new(0x0011);
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPServiceTypes.c#L51
pub const SERVICE_TEMPERATURE_SENSOR: HomekitUuid16 = HomekitUuid16::new(0x8A);

#[gatt_service(uuid = SERVICE_TEMPERATURE_SENSOR)]
pub struct TemperatureSensorService {
    #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = SERVICE_ID_TEMP_SENSOR.0)]
    pub service_instance: u16,

    /// Service signature, only two bytes.
    #[characteristic(uuid=characteristic::SERVICE_SIGNATURE, read, write)]
    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read,  value=CHAR_ID_TEMP_SENSOR_SIGNATURE.0.to_le_bytes())]
    pub service_signature: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_TEMP_SENSOR_VALUE.0.to_le_bytes())]
    #[characteristic(uuid=CHARACTERISTIC_CURRENT_TEMPERATURE, read, write, indicate)]
    pub value: FacadeDummyType,

    #[descriptor(uuid=descriptor::CHARACTERISTIC_INSTANCE_UUID, read, value=CHAR_ID_TEMP_LOW_BATTERY.0.to_le_bytes())]
    #[characteristic(uuid=characteristic::CHARACTERISTIC_LOW_BATTERY, read, write, indicate)]
    pub low_battery: FacadeDummyType,
}
use embassy_sync::blocking_mutex::raw::RawMutex;
impl TemperatureSensorService {
    pub fn create_hap_service<
        'server,
        'values,
        M: RawMutex,
        const ATT_MAX: usize,
        const CCCD_MAX: usize,
        const CONN_MAX: usize,
    >(
        &self,
        server: &'server AttributeServer<
            'values,
            M,
            DefaultPacketPool,
            ATT_MAX,
            CCCD_MAX,
            CONN_MAX,
        >,
    ) -> Result<Service, HapBleError> {
        let mut service = Service {
            ble_handle: Some(self.handle),
            uuid: SERVICE_TEMPERATURE_SENSOR.into(),
            iid: SERVICE_ID_TEMP_SENSOR,
            characteristics: Default::default(),
            properties: ServiceProperties::new().with_primary(false),
        };

        service
            .characteristics
            .push(
                Characteristic::new(
                    characteristic::SERVICE_SIGNATURE.into(),
                    CHAR_ID_TEMP_SENSOR_SIGNATURE,
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
                Characteristic::new(
                    CHARACTERISTIC_CURRENT_TEMPERATURE.into(),
                    CHAR_ID_TEMP_SENSOR_VALUE,
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
                .with_step(micro_hap::VariableUnion::F32(0.1))
                .with_ble_properties(
                    BleProperties::from_handle(self.value.handle)
                        .with_format(sig::Format::F32)
                        .with_unit(sig::Unit::Celsius)
                        .with_characteristic(
                            server
                                .table()
                                .find_characteristic_by_value_handle(self.value.handle)
                                .unwrap(),
                        ),
                )
                .with_data(DataSource::AccessoryInterface),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        service
            .characteristics
            .push(
                Characteristic::new(
                    characteristic::CHARACTERISTIC_LOW_BATTERY.into(),
                    CHAR_ID_TEMP_LOW_BATTERY,
                )
                .with_properties(
                    CharacteristicProperties::new()
                        .with_read(true)
                        .with_supports_event_notification(true)
                        .with_supports_disconnect_notification(true)
                        .with_supports_broadcast_notification(true),
                )
                .with_range(micro_hap::VariableRange {
                    start: micro_hap::VariableUnion::U8(0),
                    end: micro_hap::VariableUnion::U8(1),
                    inclusive: true,
                })
                .with_step(micro_hap::VariableUnion::U8(1))
                .with_ble_properties(
                    BleProperties::from_handle(self.low_battery.handle)
                        .with_format(sig::Format::U8)
                        .with_characteristic(
                            server
                                .table()
                                .find_characteristic_by_value_handle(self.low_battery.handle)
                                .unwrap(),
                        ),
                )
                .with_data(DataSource::AccessoryInterface),
            )
            .map_err(|_| HapBleError::AllocationOverrun)?;

        Ok(service)
    }
}
