# Firmware

This is a bit over-engineered atm as I gutted another project to make this example.
As such it contains some stuff that we should remove still:

- Replace defmt_serial with `embassy-usb-logger`.
- Ensure the pico 2w onboard led is used instead of pin 26.


## Usage
Easiest is running `make deploy` from this directory.


## Reset interface

The USB endpoint to allow the picotool to reset works. It is located in [./src/usb_picotool_reset.rs](./src/usb_picotool_reset.rs).

Relevant links:

- https://github.com/embassy-rs/embassy/issues/3726
- https://github.com/raspberrypi/pico-sdk/blob/9a4113fbbae65ee82d8cd6537963bc3d3b14bcca/src/common/pico_usb_reset_interface_headers/include/pico/usb_reset_interface.h
- https://github.com/raspberrypi/pico-sdk/tree/9a4113fbbae65ee82d8cd6537963bc3d3b14bcca/src/rp2_common/pico_stdio_usb

- https://github.com/raspberrypi/pico-sdk/blob/9a4113fbbae65ee82d8cd6537963bc3d3b14bcca/src/rp2_common/pico_stdio_usb/reset_interface.c


# defmt-print

Currently uses a logger that pushes the defmt data over the serial port; [./src/defmt_serial.rs](./src/defmt_serial.rs).

From https://crates.io/crates/defmt-print, install with `cargo install defmt-print`

```
defmt-print  -e ./target/thumbv8m.main-none-eabihf/release/firmware serial --path /dev/ttyACM
```
