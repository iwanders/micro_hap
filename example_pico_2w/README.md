# Firmware

This is a bit over-engineered atm as I gutted another project to make this example.
As such it contains some stuff that we should remove still:

- Replace defmt_serial with `embassy-usb-logger`, just to make it simpler.

It toggles the on-board LED of the RPi Pico 2W.



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

# Todo / Improvements

- Consider [assign_resources](https://crates.io/crates/assign-resources), found through [this issue](https://github.com/embassy-rs/embassy/issues/4868).

# The issue of the pairing failures with temperature sensor

So the lightbulb only example seems to work well and reliably, if the temperature sensor is added (and sampling), _something_ will fail. This either 
be an PDU decoding error, a BadProof, or BadDecrypt... Initially I suspected memory corruption / stack walking into the heap or something, but it appears
to be a hardware issue.

In the defmt prints we see:
```
48.812579 DEBUG HCI rx: [02, 40, 20, 0c, 00, 08, 00, 04, 00, 12, 47, 00, 00, 00, 72, 12, 00]
48.813029 WARN  Processing returned exception: StatusError(UnsupportedPDU)
```

While in the sniffed (using an external NRF52840 running the Nordic bluetooth sniffer):
```
0000    00 01 72 12 00
decode:
        00              no fragmentation, 16 bit iid, request, 1 byte control field
           01           opcode; 0x01 characteristic signature read
              72        tid
                 12 00  charid
```
So the opcode `0x01`, and that single bit got dropped, current suspicion is the SPI bus between the cyw43 and the mcu.

This is with the fix from [here](https://github.com/embassy-rs/embassy/issues/4791), on `cyw43=0.6.0,cyw43-pio=0.9.0`.
It appears to be _much_ better with [this newer firmware](https://github.com/georgerobotics/cyw43-driver/commit/7f422fef4ea5bff7285fb78340d3f28f5461cff2),
haven't seen a single PDU issue, saw one BadDecrypt with the higher SPI rate, but asides from that it's been fairly stable.
