# micro_hap

This is a Rust (no-alloc, no_std) implementation of the HomeKit Accessory Protocol.
Specifically aimed at running on microcontrollers, currently it only implements the BLE transport.
There are many HAP implementations available, a few implement the logic needed to create an IP peripheral, I could not find any that implemented a BLE one.

- It roughly follows the [reference implementation](https://github.com/apple/HomeKitADK), and thus has the same license.
- It uses [trouble](https://github.com/embassy-rs/trouble) for interacting with Bluetooth.
- It was developed against a recorded capture with [this repo](https://github.com/iwanders/HomeKitADK_program) which used the reference implementation to create a BLE peripheral from a Desktop machine.
- It was originally developed in [this repo](https://github.com/iwanders/pico2w_thing_91c27), but seemed worthwhile to split out.
- Code needs some cleanup, but it can pair and toggle an LED on a RPi Pico 2W.


## License
License is [`LICENSE-APACHE`](./LICENSE-APACHE) since it is based on [HomeKitADK](https://github.com/apple/HomeKitADK).
