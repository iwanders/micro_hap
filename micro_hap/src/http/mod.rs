use embedded_io_async::{Read, Write};

pub struct TcpConnection<T: Read + Write> {
    v: T,
}

impl<T: Read + Write> TcpConnection<T> {
    pub fn new(t: T) -> Self {
        Self { v: t }
    }
}

// hmm, lets first build the ble transport layer, maybe I can mock most of the stuff with unit tests...
