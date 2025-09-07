// We allow static mut refs here because we need to access a global in a non-thread-safe way, we do so from a critical
// section.
#![allow(static_mut_refs)]
#![cfg_attr(not(target_arch = "arm"), allow(dead_code))]

use embassy_usb::driver::Driver as UsbDriver;
use static_cell::StaticCell;

// Modelled after
// https://github.com/knurling-rs/defmt/blob/8e517f8d7224237893e39337a61de8ef98b341f2/firmware/defmt-itm/src/lib.rs#L44
// Is this useful?
// https://github.com/embassy-rs/embassy/blob/9651cfca51a273ba46d34ce8197fc0e63389b09e/examples/rp/src/bin/assign_resources.rs

use core::sync::atomic::{AtomicBool, Ordering};
use embassy_usb::class::cdc_acm::Sender;

/// Encoder for defmt messages.
static mut ENCODER: defmt::Encoder = defmt::Encoder::new();

/// Boolean set to true if an overrun occurs, which means the queue was full and it prevented bytes from being
/// appended to it.
static DEFMT_OVERRUN: AtomicBool = AtomicBool::new(false);

// Private globals for critical section handling.
static TAKEN: AtomicBool = AtomicBool::new(false);
static mut CS_RESTORE: critical_section::RestoreState = critical_section::RestoreState::invalid();

/// Buffer for defmt messages, if this is too small overruns occur.
const DEFMT_SERIAL_BUFFER: usize = 4096;

type CS = embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
type Queue = embassy_sync::pipe::Pipe<CS, DEFMT_SERIAL_BUFFER>;
type Producer = embassy_sync::pipe::Writer<'static, CS, DEFMT_SERIAL_BUFFER>;

static mut TX_THING: Option<Producer> = None;

pub struct SerialLogger<D: UsbDriver<'static>> {
    s: Sender<'static, D>,
}
impl<D: UsbDriver<'static>> SerialLogger<D> {
    pub fn new(s: Sender<'static, D>) -> Self {
        Self { s }
    }
}

pub async fn run<D: UsbDriver<'static>>(logger: SerialLogger<D>) -> ! {
    let mut logger = logger;
    let queue: &'static mut Queue = {
        static STATE: StaticCell<Queue> = StaticCell::new();
        STATE.init(Queue::new())
    };
    let (rx, tx) = queue.split();

    unsafe {
        TX_THING = Some(tx);
    }

    loop {
        // Take stuff from rx and shove into serial port.

        // Swap the overrun buffer to alert user of an overrun.
        if DEFMT_OVERRUN.swap(false, Ordering::Relaxed) {
            defmt::error!("SERIAL OVERRUN");
        }

        const USB_CDC_MAX_PACKET_SIZE_LIMIT: usize = 64;
        let mut buffer = [0u8; USB_CDC_MAX_PACKET_SIZE_LIMIT];
        // Use read here, instead of read exact to ensure that we get short messages individually if they're spaced.
        let read_size = rx.read(&mut buffer).await;
        // This can't really return an error, since our pipe will never reach EOF.
        if let Err(e) = logger.s.write_packet(&buffer[0..read_size]).await {
            // ehh... panic? Maybe it's transient? Lets just push a message about it.
            defmt::error!("failed writing: {:?}", e);
        }
    }
}

fn do_write(mut bytes: &[u8]) {
    // NOTE(unsafe) this function will be invoked *after* run has been started and the global logger has been populated.
    unsafe {
        if let Some(tx) = TX_THING.as_mut() {
            while !bytes.is_empty() {
                bytes = match tx.try_write(bytes) {
                    Ok(b) => &bytes[b..],
                    Err(_) => {
                        // No recourse here.
                        DEFMT_OVERRUN.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
    }
}

/// Throw out all safety promises and shove bytes into the pipe, this will mess up the defmt printing setup.
/// Remember to still let the executor handle the pipe->usb process.
pub unsafe fn push_serial(mut bytes: &[u8]) {
    unsafe {
        if let Some(tx) = TX_THING.as_mut() {
            while !bytes.is_empty() {
                bytes = match tx.try_write(bytes) {
                    Ok(b) => &bytes[b..],
                    Err(_) => {
                        // No recourse here.
                        DEFMT_OVERRUN.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
    }
}

#[defmt::global_logger]
struct Logger;

#[cfg(target_arch = "arm")]
unsafe impl defmt::Logger for Logger {
    fn acquire() {
        // safety: Must be paired with corresponding call to release(), see below
        let restore = unsafe { critical_section::acquire() };

        // safety: accessing the atomic without CAS is OK because we have acquired a critical section.
        if TAKEN.load(Ordering::Relaxed) {
            panic!("defmt logger taken reentrantly")
        }

        // safety: accessing the atomic without CAS is OK because we have acquired a critical section.
        TAKEN.store(true, Ordering::Relaxed);

        // safety: accessing the `static mut` is OK because we have acquired a critical section.
        unsafe { CS_RESTORE = restore };

        // safety: accessing the `static mut` is OK because we have acquired a critical section.
        unsafe {
            let encoder: &mut defmt::Encoder = &mut *core::ptr::addr_of_mut!(ENCODER);
            encoder.start_frame(do_write)
        }
    }
    unsafe fn flush() {
        // ...
    }
    unsafe fn release() {
        // safety: accessing the `static mut` is OK because we have acquired a critical section.
        unsafe {
            let encoder: &mut defmt::Encoder = &mut *core::ptr::addr_of_mut!(ENCODER);
            encoder.end_frame(do_write);
        }

        // safety: accessing the atomic without CAS is OK because we have acquired a critical section.
        TAKEN.store(false, Ordering::Relaxed);

        // safety: accessing the `static mut` is OK because we have acquired a critical section.
        let restore = unsafe { CS_RESTORE };

        // safety: Must be paired with corresponding call to acquire(), see above
        unsafe {
            critical_section::release(restore);
        }
    }
    unsafe fn write(bytes: &[u8]) {
        // safety: accessing the `static mut` is OK because we have acquired a critical section.
        unsafe {
            let encoder: &mut defmt::Encoder = &mut *core::ptr::addr_of_mut!(ENCODER);
            encoder.write(bytes, do_write);
        }
    }
}

#[cfg(not(target_arch = "arm"))]
mod defmt_test_fix {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    defmt::timestamp!(
        "{=usize}",
        COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    unsafe impl defmt::Logger for Logger {
        fn acquire() {}
        unsafe fn flush() {}
        unsafe fn release() {}
        unsafe fn write(bytes: &[u8]) {
            fn do_write(_: &[u8]) {
                // This output here is pretty useless.
                //println!("{b:?}");
            }
            let mut encoder = defmt::Encoder::new();
            encoder.start_frame(do_write);
            encoder.write(bytes, do_write);
            encoder.end_frame(do_write);
        }
    }
}
