pub mod accessory_information;
pub mod lightbulb;
pub mod pairing;
pub mod protocol_information;

pub use accessory_information::{AccessoryInformationService, AccessoryInformationServiceHandles};
pub use lightbulb::{LightbulbService, LightbulbServiceHandles};
pub use pairing::{PairingService, PairingServiceHandles};
pub use protocol_information::{ProtocolInformationService, ProtocolInformationServiceHandles};

use crate::{CharId, SvcId};
use trouble_host::prelude::*;

pub mod prelude {
    pub use super::{
        BuilderError, CharBleIds, FacadeBleIds, FacadeDummyType, ServiceInstanceBleIds, SvcBleIds,
    };
    pub use crate::ble::{HapBleError, sig};
    pub use crate::{
        BleProperties, CharId, CharacteristicProperties, DataSource, Service, SvcId,
        characteristic, descriptor, service,
    };
    pub use crate::{
        add_facade_characteristic, add_facade_characteristic_indicate,
        add_facade_characteristic_props, add_service_instance,
    };
    pub use embassy_sync::blocking_mutex::raw::RawMutex;
    pub use trouble_host::prelude::{AttributeTable, CharacteristicProp, gatt_service};
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct SvcBleIds {
    pub hap: SvcId,
    pub ble: u16,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Copy, Clone)]
pub struct CharBleIds<T: Copy + trouble_host::types::gatt_traits::AsGatt> {
    pub hap: CharId,
    pub ble: trouble_host::attribute::Characteristic<T>,
}
impl<T: Copy + trouble_host::types::gatt_traits::AsGatt> core::cmp::Eq for CharBleIds<T> {}
impl<T: Copy + trouble_host::types::gatt_traits::AsGatt> core::cmp::PartialEq for CharBleIds<T> {
    fn eq(&self, other: &Self) -> bool {
        self.hap == other.hap && self.ble.handle == other.ble.handle
    }
}
pub type FacadeBleIds = CharBleIds<FacadeDummyType>;
pub type ServiceInstanceBleIds = CharBleIds<u16>;

#[macro_export]
macro_rules! add_service_instance {
    (
        $service_builder:expr,
        $iid: expr,
        $store:expr
    ) => {{
        use $crate::ble::BuilderError;
        // #[characteristic(uuid=characteristic::SERVICE_INSTANCE, read, value = 1)]
        // pub service_instance: u16,
        let readprops = &[CharacteristicProp::Read];
        let iid_value: u16 = $iid;
        let remaining_length = $store.len();
        let allocation_length = trouble_host::types::gatt_traits::AsGatt::as_gatt(&iid_value).len();
        let (value_store, store) = $store.split_at_mut_checked(allocation_length).ok_or(
            BuilderError::AttributeAllocationOverrun {
                remaining_length,
                allocation_length,
                characteristic_uuid: characteristic::SERVICE_INSTANCE.into(),
                name: stringify!(characteristic::SERVICE_INSTANCE),
            },
        )?;
        value_store.copy_from_slice(trouble_host::types::gatt_traits::AsGatt::as_gatt(
            &iid_value,
        ));
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
                ble: characteristic,
            },
        )
    }};
}

/// Add a standard characteristic for the facade, with control over its properties like Read, Write, Indicate
#[macro_export]
macro_rules! add_facade_characteristic_props {
    (
        $service_builder:expr,
        $characteristic_uuid:expr,
        $characteristic_props:expr,
        $iid: expr,
        $store:expr
    ) => {{
        {
            use $crate::ble::BuilderError;
            const READ_PROPS: &[CharacteristicProp] = &$characteristic_props;
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
            // Next, create the characteristic instance descriptor.
            let iid_value: u16 = $iid;
            // let remaining_length = $store.len();
            let allocation_length =
                trouble_host::types::gatt_traits::AsGatt::as_gatt(&iid_value).len();
            let (value_store, store) = store.split_at_mut_checked(allocation_length).ok_or(
                BuilderError::AttributeAllocationOverrun {
                    remaining_length,
                    allocation_length,
                    characteristic_uuid: $characteristic_uuid.into(),
                    name: stringify!($characteristic_uuid),
                },
            )?;
            value_store.copy_from_slice(trouble_host::types::gatt_traits::AsGatt::as_gatt(
                &iid_value,
            ));
            let props = [CharacteristicProp::Read];
            let _descriptor_object = characteristic_builder.add_descriptor::<&[u8], _>(
                descriptor::CHARACTERISTIC_INSTANCE_UUID,
                &props,
                value_store,
            );
            // info!("_descriptor_object.handle: {}", _descriptor_object.handle());
            let characteristic = characteristic_builder.build();
            // info!("characteristic.handle: {}", characteristic.handle);
            let char_id = CharId(iid_value);
            (
                $service_builder,
                store,
                iid_value + 1,
                CharBleIds {
                    hap: char_id,
                    ble: characteristic,
                },
            )
        }
    }};
}

/// Add a standard read-write characteristic, like for the facade.
#[macro_export]
macro_rules! add_facade_characteristic {
    (
        $service_builder:expr,
        $characteristic_uuid:expr,
        $iid: expr,
        $store:expr
    ) => {{
        $crate::add_facade_characteristic_props!(
            $service_builder,
            $characteristic_uuid,
            [CharacteristicProp::Read, CharacteristicProp::Write],
            $iid,
            $store
        )
    }};
}

#[macro_export]
macro_rules! add_facade_characteristic_indicate {
    (
        $service_builder:expr,
        $characteristic_uuid:expr,
        $iid: expr,
        $store:expr
    ) => {{
        $crate::add_facade_characteristic_props!(
            $service_builder,
            $characteristic_uuid,
            [
                CharacteristicProp::Read,
                CharacteristicProp::Write,
                CharacteristicProp::Indicate
            ],
            $iid,
            $store
        )
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

pub type FacadeDummyType = [u8; 0];
