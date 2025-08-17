/// Reader iterator for TLV sequences;
/// Yielding entries that hold:
///   type_id: u8,
///   length: u8,
///   data: [u8;length]
pub struct TLVReader<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> TLVReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self::new_at(buffer, 0)
    }
    pub fn new_at(buffer: &'a [u8], start: usize) -> Self {
        Self {
            position: start,
            buffer,
        }
    }

    pub fn read_into(self, tlvs: &mut [&mut TLV<'a>]) -> Result<(), TLVError> {
        //let collected = TLVReader::read(&[&mut a, &mut b]);
        for entry in self {
            let entry = entry?;
            for v in tlvs.iter_mut() {
                if v.type_id == entry.type_id {
                    (**v).length = entry.length;
                    (**v).data = &entry.data;
                }
            }
        }
        Ok(())
    }
}

pub struct TLV<'a> {
    pub type_id: u8,
    pub length: u8,
    pub data: &'a [u8],
}
impl<'a> TLV<'a> {
    pub fn tied<T: Into<u8>>(data: &'a [u8], type_id: T) -> Self {
        Self {
            type_id: type_id.into(),
            length: 0,
            data: &data[0..0],
        }
    }
    pub fn is_some(&self) -> bool {
        self.length != 0
    }
}

#[derive(Debug, Copy, Clone)]
pub enum TLVError {
    NotEnoughData,
}

impl From<TLVError> for trouble_host::Error {
    fn from(e: TLVError) -> trouble_host::Error {
        match e {
            TLVError::NotEnoughData => trouble_host::Error::OutOfMemory,
        }
    }
}

impl<'a> Iterator for TLVReader<'a> {
    type Item = Result<TLV<'a>, TLVError>;
    fn next(&mut self) -> Option<Self::Item> {
        if (self.position + 1) < self.buffer.len() {
            let type_id = self.buffer[self.position];
            let length = self.buffer[self.position + 1];
            let data_end = self.position + 2 + length as usize;
            if data_end <= self.buffer.len() {
                let data = &self.buffer[self.position + 2..data_end];
                self.position = data_end;
                return Some(Ok(TLV {
                    type_id,
                    length,
                    data,
                }));
            } else {
                // Ensure the iterator will only ever yields None from now.
                self.position = self.buffer.len() + 1;
                Some(Err(TLVError::NotEnoughData))
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::max())
            .try_init();
    }

    // https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/Tests/HAPTLVTest.c#L103
    #[test]
    fn test_pairing_tlv_parse() {
        init();

        // Single TLV.
        // This is a bad test... why aren't the numbers different!?
        let tlv_payload = [0x01, 0x01, 0x01];
        let mut reader = TLVReader::new(&tlv_payload);
        let z = reader.next().unwrap().unwrap();
        assert_eq!(z.type_id, 0x01);
        assert_eq!(z.length, 0x01);
        assert_eq!(z.data, &[0x01]);

        // iw; Single tlv good test.
        let tlv_payload = [0x05, 0x01, 0x03];
        let mut reader = TLVReader::new(&tlv_payload);
        let z = reader.next().unwrap().unwrap();
        assert_eq!(z.type_id, 0x05);
        assert_eq!(z.length, 0x01);
        assert_eq!(z.data, &[0x03]);

        // HomeKit Pair Setup M1
        let data = [0x00, 0x01, 0x00, 0x06, 0x01, 0x01];
        let mut reader = TLVReader::new(&data);
        let a = reader.next().unwrap().unwrap();
        let b = reader.next().unwrap().unwrap();
        assert_eq!(a.type_id, 0x00);
        assert_eq!(a.length, 0x01);
        assert_eq!(a.data, &[0x00]);
        assert_eq!(b.type_id, 0x06);
        assert_eq!(b.length, 0x01);
        assert_eq!(b.data, &[0x01]);

        let mut a = TLV::tied(&data, 0x00);
        let mut b = TLV::tied(&data, 0x06);

        let collected = TLVReader::new(&data).read_into(&mut [&mut a, &mut b]);
        assert_eq!(collected.is_ok(), true);
        assert_eq!(a.type_id, 0x00);
        assert_eq!(a.length, 0x01);
        assert_eq!(a.data, &[0x00]);
        assert_eq!(b.type_id, 0x06);
        assert_eq!(b.length, 0x01);
        assert_eq!(b.data, &[0x01]);
    }
}
