# micro_hap

This is a Rust (no-alloc, no_std) implementation of the HomeKit Accessory Protocol.
Specifically aimed at running within [embassy](https://github.com/embassy-rs/embassy),
currently it only implements the BLE transport, building on the [trouble](https://github.com/embassy-rs/trouble) Bluetooth stack.
There are many HAP implementations available, a few implement the logic needed to create an IP peripheral but I could not find any that implemented a BLE one, so I wrote one to do just that.

- It roughly follows the [reference implementation](https://github.com/apple/HomeKitADK), and thus has the same license.
- It uses [trouble](https://github.com/embassy-rs/trouble) for interacting with Bluetooth.
- It was originally developed in [this repo](https://github.com/iwanders/pico2w_thing_91c27), but seemed worthwhile to split out.
- Pairing fully works, including pair resume.
- Enumeration of the device works.
- Read and Writes over the HAP session work.
- Services & Characeristics can be defined out-of-crate.
- Still missing; Characteristic changes via broadcasts & status number broadcasts.

## Testing
The main test for the BLE transport right now is in [./micro_hap/src/ble/test.rs](./micro_hap/src/ble/test.rs).
This contains a full pairing procedure, pair verify and toggling of the lightbulb.
This tests pretty much everything except pairing storage, session invalidation and of course any messages that were not encountered in the recording.
This data was captured using  [this repo](https://github.com/iwanders/HomeKitADK_program) which used the reference implementation to create a BLE peripheral from my desktop.
Actions in this main test are; pair, toggle a few times, disable & enable bluetooth, toggle a few more times.

## Architecture
Many parts were only tackled when I encountered a new concept in building out the logic against the recording.

To help people understand the code and the concepts, here's an information dump:
- An accessory is comprised of Services, the `accessory_information`, `protocol` and `pairing` services are required.
- A service has attributes (in the BLE transport moddeled as characteristics).
- HomeKit's pairing, session and permission management has nothing to do with BLE's equivalents.
- On the BLE level, all characteristics are read/write without a secure BLE session.
- Attributes are interacted with through a BLE write AND read, together they form a request.
- For example, toggling the lightbulb performs a BLE write on the `On` attribute of the `Lightbulb` Service, the response of this request is verified with a BLE Read on the same characteristic.
- The HAP protocol is merely transported over the BLE gatt write/reads.
- The Trouble GATT server is merely a facade to provide the correct characteristics & services.
- The `HapPeripheralContext::gatt_events_task` is the entry point for the bluetooth transport.
- The `PlatformSupport` is the platform interface / key-value store and auxiliary function support like random bytes.
- The `AccessoryInterface` is the interface the accessory's endpoints, so for example the actual lightbulb.
- A pairing is effectively an exchange of public keys, after which a session is established through pair verify.
- The 'entry point' to all the logic is the `process_gatt_event` method of the `HapPeripheralContext`.
- On error handling. The pairing handling returns `PairingError` which provide relevant information what went wrong.
  The `ble` layer changes this into appropriate `ble::pdu::HapBleStatusError` errors that are responded to the client,
  only real trouble errors are bubbled up to the calling code.
- The `InternalError` is internal, some of its values end up being HAP protocol status results, others end up bubbling
  through to the user application like `InterfaceError`.

## Todo
- ~Clean up error handling.n (snafu / thiserror?)~
- ~Correctly return HAP errors, instead of failing the BLE request.~
- ~Any errors currently drop the request instead of returning the correct HAP error code.~
- ~Figure out when `MaxProcedures` should be returned..~ Looks like a sentinel?
- Figure out how values that proactively change work (like temperature sensor), how to notify?
- ~When the state on the accessory changes, it is supposed to increment the global state number.~
- ~The global state number is in the advertisement, this is how iOS knows it should connect to retrieve the state.~
- Add periodic 'service' method to handle global state counter, advertisement and expiring timed writes to free slots.
- How do the advertisements actually work?
- ~And what about notify while a connection is active?~ Send indicate over BLE
- ~Clear the session, pair_verify and pair_setup on disconnect, currently it requires a powercycle to reset state.~ Can pair numerous times now.
- Numerous comments starting with `// NONCOMPLIANCE` where I ignored something that should probably be handled.
- How much is shared between BLE & IP? Can we implement IP as well with minimal work?
- ~Make the accessory interface async.~ it is now, the RPi Pico 2w example uses the built-in led, toggling requires an async function.
- ~Modify/add second example to show how to add a service, ensure common stuff is shared.~
- Perhaps a commissioning binary to create the salt & verifier, using the `PairingCode` type that now exists.
- ~Make the `PlatformSupport` methods async.~ Async now, but `PlatformSupport: Send` because `Send` is on all futures, this likely needs
  some changes in the future as we probably can't `Send` peripherals? Maybe just drop the bound?
- ~Build out `characteristic_signature_request` to support range and step, probably needed for hue.~
- ~Verify pair resume actually works, keep a list of sessions...~
- ~Make `pairing` and `pair_verify` modules crate-private?~ They are now, and refactored, error is still public.
- ~Implement TimedWrite request.~
- ~Implement `CharacteristicExecuteWrite`.~
- ~Do we ever need to support interleaved requests? So write on characteristic 1, write on characteristic 2, read on 1, read on 2. -> Probably [not](https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPAccessoryServer%2BInternal.h#L206).~
- Implement `SetupInfo`'s serialize/deserialize, this [issue](https://github.com/serde-rs/serde/issues/1937#issuecomment-812137971) is helpful.
- ~Bluetooth session cache for session resume.~ ~Cache exists, use during initial setup works, works for lightbulb, not for thermometer between restarts. Issue was that the device id shouldn't change!~
- The services made with `#[gatt_service(..` have a `StaticCell` in them, as such they can't be instantiated twice. This makes the mutually exclusive lightbulb example cumbersome.
- File PR [into trouble](https://github.com/embassy-rs/trouble/pull/502) to add `indiate` functionality, because `notify != indicate`.
- Go through all the log / defmt prints and ensure the level makes sense.

## example_std
This example is intended to run a Linux host, similar to [trouble's linux](https://github.com/embassy-rs/trouble/tree/main/examples/linux) examples.
This is the main binary used for debugging & development of the actual interaction with iOS.
Build this with `cargo b`, it has to be ran as root to bind the linux HCI interface.
It also requires freeing that interface, usually by disabling your bluetooth service with `service bluetooth stop`.

This contains multiple examples:
- `example_lightbulb` The default lightbulb example with just an on-off toggle.
- `example_rgb` This contains two lightbulbs, one that allows modifying the color temperature, and one that facilitates hue, staturation and brightness configuration.

## example_pico_2w
This example is a gutted version of the project I'm originally developing this for.
It contains a bunch of stuff that is not really relevant for the HAP example, but the current state at least puts a working bare metal example in the repo. It toggles the default LED on the pcb through the cyw43 chip.

This example is independent from the workspace, such that `cargo b` at the workspace level doesn't result in both `log` and `defmt` being enabled.

## License
License is [`LICENSE-APACHE`](./LICENSE-APACHE) since it is based on [HomeKitADK](https://github.com/apple/HomeKitADK).
