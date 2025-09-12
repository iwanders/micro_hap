use super::*;

// https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/core/formattypes.yaml
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
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
    // Other(u8),
}
// Integers have exponent True

// https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/uuids/units.yaml
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(u16)]
pub enum Unit {
    UnitLess = 0x2700,
    Meter = 0x2701,
    Kilogram = 0x2702,
    Second = 0x2703,
    Kelvin = 0x2705,
    Celsius = 0x272f,
    PressurePascal = 0x2724,
    Percentage = 0x27AD,
    Decibel = 0x27C3,
    PressureBar = 0x2780,
    /// Plane angle.
    ArcDegrees = 0x2763,
    // Other(u16),
}

#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(u8)]
pub enum Namespace {
    Bluetooth = 0x01,
}

// Characteristic Presentation Format, p1492 of the Bluetooth core spec, v5.3; section 3.3.3.5
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
#[repr(C, packed)]
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

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_sigformat() {
        let temperature = CharacteristicRepresentation {
            unit: Unit::Celsius,
            format: Format::F64,
            ..Default::default()
        };

        let b = temperature.as_bytes();
        assert_eq!(b.len(), 7);
    }
}
