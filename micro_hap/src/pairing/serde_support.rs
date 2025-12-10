// This is adapted from https://github.com/serde-rs/serde/issues/1937#issuecomment-812137971
// Changes are; read immediately into the array and enforce Default + Copy, which is fine for our byte arrays.
// Use a heapless string for the error.
pub mod arrays {
    use core::{convert::TryInto, marker::PhantomData};

    use serde::{
        Deserialize, Deserializer, Serialize, Serializer,
        de::{SeqAccess, Visitor},
        ser::SerializeTuple,
    };
    pub fn serialize<S: Serializer, T: Serialize, const N: usize>(
        data: &[T; N],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        let mut s = ser.serialize_tuple(N)?;
        for item in data {
            s.serialize_element(item)?;
        }
        s.end()
    }

    struct ArrayVisitor<T, const N: usize>(PhantomData<T>);

    impl<'de, T, const N: usize> Visitor<'de> for ArrayVisitor<T, N>
    where
        T: Deserialize<'de> + Default + Copy,
    {
        type Value = [T; N];

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            let z: heapless::String<32> = heapless::format!("an array of length {}", N).unwrap();
            formatter.write_str(&z)
        }

        #[inline]
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // can be optimized using MaybeUninit
            let mut data: [T; N] = [T::default(); N];
            // let mut data = heapless::Vec::<T, N>::new();
            for i in 0..N {
                match (seq.next_element())? {
                    Some(val) => data[i] = val,
                    None => return Err(serde::de::Error::invalid_length(N, &self)),
                }
            }
            match data.try_into() {
                Ok(arr) => Ok(arr),
                Err(_) => unreachable!(),
            }
        }
    }
    pub fn deserialize<'de, D, T, const N: usize>(deserializer: D) -> Result<[T; N], D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> + Default + Copy,
    {
        deserializer.deserialize_tuple(N, ArrayVisitor::<T, N>(PhantomData))
    }
}
