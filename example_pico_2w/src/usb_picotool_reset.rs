//! RPi picotool reset class usb interface handler.

// https://github.com/raspberrypi/pico-sdk/blob/9a4113fbbae65ee82d8cd6537963bc3d3b14bcca/src/common/pico_usb_reset_interface_headers/include/pico/usb_reset_interface.h
// Do we need the whole Microsoft OS 2.0 descriptor stuff??
//

use defmt::error;

use crate::rp2350_util::reboot;
use embassy_time::Duration;
use embassy_usb::control::{OutResponse, Request};
use embassy_usb::driver::Driver;

use embassy_usb::{Builder, Handler};

pub const PICO_RESET_CLASS: u8 = 0xFF;
pub const PICO_RESET_SUBCLASS: u8 = 0x00;
pub const PICO_RESET_INTERFACE_PROTOCOL: u8 = 0x01;

use core::mem::MaybeUninit;

use crate::rp2350_util::reboot::RebootSettings;

struct Control {
    index: u16,
}

impl Control {
    fn new(index: u16) -> Self {
        Control { index }
    }
}

impl Handler for Control {
    fn control_out(&mut self, req: Request, _buf: &[u8]) -> Option<OutResponse> {
        // control_out is HostToDevice.
        error!("Got data out control: {:?}", req);
        const RESET_REQUEST_BOOTSEL: u8 = 0x01;
        const RESET_REQUEST_FLASH: u8 = 0x02;
        if req.index == self.index {
            if req.request == RESET_REQUEST_BOOTSEL {
                // Flags from request seems irrelevant?
                let _flags_from_request = (req.value & 0x7f) as u32;
                error!("Flash Reboot!"); // Our dying breath, which doesn't make it out.
                reboot::reboot(RebootSettings::flash(), Duration::from_millis(100));
                // never reached, reboot blocks.
            }
            if req.request == RESET_REQUEST_FLASH {
                error!("Normal Reboot!");
                reboot::reboot(RebootSettings::Normal, Duration::from_millis(100));
                // never reached, reboot blocks.
            }
            return Some(OutResponse::Rejected);
        }
        None
    }
}

pub struct State {
    control: MaybeUninit<Control>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub const fn new() -> Self {
        State {
            control: MaybeUninit::uninit(),
        }
    }
}

pub struct PicoResetClass<'d, D: Driver<'d>> {
    _driver: core::marker::PhantomData<&'d D>,
}

impl<'d, D: Driver<'d>> PicoResetClass<'d, D> {
    pub fn new(builder: &mut Builder<'d, D>, state: &'d mut State) {
        let mut func = builder.function(
            PICO_RESET_CLASS,
            PICO_RESET_SUBCLASS,
            PICO_RESET_INTERFACE_PROTOCOL,
        );
        let mut iface = func.interface();
        let count = iface.interface_number().0;
        let mut _alt = iface.alt_setting(
            PICO_RESET_CLASS,
            PICO_RESET_SUBCLASS,
            PICO_RESET_INTERFACE_PROTOCOL,
            None,
        );

        let control = state.control.write(Control::new(count as u16));

        drop(func);

        builder.handler(control);
    }
}
