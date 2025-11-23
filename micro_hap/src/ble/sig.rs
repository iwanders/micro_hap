use super::*;

// https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/core/formattypes.yaml
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[repr(u8)]
pub enum Format {
    Boolean = 0x01,
    U8 = 0x04,
    U16 = 0x06,
    U32 = 0x08,
    U64 = 0x0a,
    I8 = 0x0c,
    I16 = 0x0E,
    I32 = 0x10,
    I64 = 0x13,
    F32 = 0x14,
    F64 = 0x15,
    StringUtf8 = 0x19,
    Opaque = 0x1B,
    Other(u8),
}
impl Format {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Format::Other(v) => &v.as_bytes(),

            Format::Boolean => 0x01u8.as_bytes(),
            Format::U8 => 0x04u8.as_bytes(),
            Format::U16 => 0x06u8.as_bytes(),
            Format::U32 => 0x08u8.as_bytes(),
            Format::U64 => 0x0au8.as_bytes(),
            Format::I8 => 0x0cu8.as_bytes(),
            Format::I16 => 0x0Eu8.as_bytes(),
            Format::I32 => 0x10u8.as_bytes(),
            Format::I64 => 0x13u8.as_bytes(),
            Format::F32 => 0x14u8.as_bytes(),
            Format::F64 => 0x15u8.as_bytes(),
            Format::StringUtf8 => 0x19u8.as_bytes(),
            Format::Opaque => 0x1Bu8.as_bytes(),
        }
    }
}

// Integers have exponent True

// https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/uuids/units.yaml
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[repr(u16)]
pub enum Unit {
    /// HAP Unit None
    UnitLess = 0x2700,
    Meter = 0x2701,
    Kilogram = 0x2702,
    /// HAP Unit seconds
    Second = 0x2703,
    Kelvin = 0x2705,
    /// HAP Unit celsius
    Celsius = 0x272f,
    PressurePascal = 0x2724,
    /// HAP Unit Lux
    Lux = 0x2731,
    /// HAP Unit percentage
    Percentage = 0x27AD,
    Decibel = 0x27C3,
    PressureBar = 0x2780,
    /// HAP Unit arcdegrees; Plane angle in SIG
    ArcDegrees = 0x2763,
    Other(u16),
}
impl Unit {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Unit::Other(v) => &v.as_bytes(),
            Unit::UnitLess => 0x2700u16.as_bytes(),
            Unit::Meter => 0x2701u16.as_bytes(),
            Unit::Kilogram => 0x2702u16.as_bytes(),
            Unit::Second => 0x2703u16.as_bytes(),
            Unit::Kelvin => 0x2705u16.as_bytes(),
            Unit::Celsius => 0x272fu16.as_bytes(),
            Unit::PressurePascal => 0x2724u16.as_bytes(),
            Unit::Lux => 0x2731u16.as_bytes(),
            Unit::Percentage => 0x27ADu16.as_bytes(),
            Unit::Decibel => 0x27C3u16.as_bytes(),
            Unit::PressureBar => 0x2780u16.as_bytes(),
            Unit::ArcDegrees => 0x2763u16.as_bytes(),
        }
    }
}

#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(u8)]
pub enum Namespace {
    Bluetooth = 0x01,
}

// Characteristic Presentation Format, p1492 of the Bluetooth core spec, v5.3; section 3.3.3.5
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct CharacteristicRepresentation {
    pub format: Format,
    pub exponent: i8,
    pub unit: Unit,
    pub namespace: Namespace,
    pub description: u16,
}
impl Default for CharacteristicRepresentation {
    fn default() -> Self {
        Self {
            format: Format::U8,
            exponent: 0,
            unit: Unit::UnitLess,
            namespace: Namespace::Bluetooth,
            description: 0,
        }
    }
}
impl CharacteristicRepresentation {
    pub fn into_bytes(&self) -> [u8; 7] {
        let mut buf = [0u8; 7];
        buf[0..1].copy_from_slice(self.format.as_bytes());
        buf[1..2].copy_from_slice(self.exponent.as_bytes());
        buf[2..4].copy_from_slice(self.unit.as_bytes());
        buf[4..5].copy_from_slice(self.namespace.as_bytes());
        buf[5..7].copy_from_slice(self.description.as_bytes());
        buf
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_sigformat() {
        crate::test::init();
        let temperature = CharacteristicRepresentation {
            unit: Unit::Celsius,
            format: Format::F64,
            ..Default::default()
        };

        let b = temperature.into_bytes();
        assert_eq!(b.len(), 7);
        assert_eq!(b, [21, 0, 47, 39, 1, 0, 0]);
    }
}
