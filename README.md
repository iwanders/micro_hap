# micro_hap

This is a Rust (no-alloc, no_std) implementation of the HomeKit Accessory Protocol.
Specifically aimed at running within [embassy](https://github.com/embassy-rs/embassy), currently it only implements the BLE transport.
There are many HAP implementations available, a few implement the logic needed to create an IP peripheral but I could not find any that implemented a BLE one, so I wrote yet another one.

- It roughly follows the [reference implementation](https://github.com/apple/HomeKitADK), and thus has the same license.
- It uses [trouble](https://github.com/embassy-rs/trouble) for interacting with Bluetooth.
- It was originally developed in [this repo](https://github.com/iwanders/pico2w_thing_91c27), but seemed worthwhile to split out.
- Code needs some cleanup, but it can pair and toggle an LED on a RPi Pico 2W.
- Example (and code) currently only supports a single pairing procedure and only the 'happy path'.

## Testing
The main test for the BLE transport right now is in [./micro_hap/src/ble/mod.rs](./micro_hap/src/ble/mod.rs).
This contains a full pairing procedure, pair verify and toggling of the lightbulb.
This tests pretty much everything except pairing storage, session invalidation and of course any messages that were not encountered in the recording.
This data was captured using  [this repo](https://github.com/iwanders/HomeKitADK_program) which used the reference implementation to create a BLE peripheral from my desktop.
Actions in this main test are; pair, toggle a few times, disable & enable bluetooth, toggle a few more times.

## Architecture
Many parts were only tackled when I encountered a new concept in building out the logic against the recording. It could
do with a cleanup, but I'm not sure if I get to that before I have to step away from this for a while, so here's a dump
of information for myself, and others that may interact with this:

To help people understand the code and the concepts, here's an information dump:
- An accessory is comprised of Services, the `accessory_information`, `protocol` and `pairing` services are required.
- A service has attributes (in the BLE transport moddeled as characteristics).
- HomeKit's pairing, session and permission management has nothing to do with BLE's equivalents.
- On the BLE level, all characteristics are read/write without a secure BLE session.
- Attributes are interacted with through a BLE write AND read, together they form a request.
- For example, toggling the lightbulb performs a BLE write on the `On` attribute of the `Lightbulb` Service, the response of this request is verified with a BLE Read on the same characteristic.
- The HAP protocol is merely transported over the BLE write/reads.
- The Trouble GATT server is merely a facade to provide the correct characteristics & services.
- The `HapPeripheralContext::process_gatt_event` is the entry point for the bluetooth transport.
- The `PairSupport` is effectively the platform interface.
- The `AccessoryInterface` is the interface the accessory's endpoints, so the actual lightbulb.
- A pairing is effectively an exchange of public keys, after which a session is established through pair verify.

## Todo
- Clean up error handling.
- Correctly return HAP errors, instead of failing the BLE request.
- Figure out how values that proactively change work (like temperature sensor), how to notify?
- When the state on the accessory changes, it is supposed to increment the global state number.
- The global state number is in the advertisement, this is how iOS knows it should connect to retrieve the state.
- Add periodic 'service' method to handle global state and advertisement.
- Clear the session, pair_verify and pair_setup on disconnect, currently it requires a powercycle to reset state.
- Numerous comments starting with `// NONCOMPLIANCE` where I ignored something that should probably be handled.
- Any errors currently drop the request instead of returning the correct HAP error code.
- How much is shared between BLE & IP? Can we implement IP as well with minimal work?
- ~Make the accessory interface async.~ it is now, the RPi Pico 2w example uses the built-in led, toggling requires an async function.
- Modify/add second example to show how to add a service, ensure common stuff is shared.
- Perhaps a commissioning binary to create the salt & verifier, using the `PairingCode` type that now exists.

## example_std
This example is intended to run a Linux host, similar to [trouble's linux](https://github.com/embassy-rs/trouble/tree/main/examples/linux) examples.
This is the main binary used for debugging & development of the actual interaction with iOS.
Build this with `cargo b`, it has to be ran as root to bind the linux HCI interface.
It also requires freeing that interface, usually by disabling your bluetooth service with `service bluetooth stop`.

## example_pico_2w
This example is a gutted version of the project I'm originally developing this for.
It contains a bunch of stuff that is not really relevant for the HAP example, but the current state at least puts a working bare metal example in the repo. It toggles the default LED on the pcb through the cyw43 chip.

## License
License is [`LICENSE-APACHE`](./LICENSE-APACHE) since it is based on [HomeKitADK](https://github.com/apple/HomeKitADK).
