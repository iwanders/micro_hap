pub mod chip_info {
    use embassy_rp::rom_data;
    // The serial number provided before reboot must match the serial number that becomes available.
    // We need to extract get_sys_info,  datasheet section 5.4.8.17
    // https://github.com/raspberrypi/pico-sdk/blob/9a4113fbbae65ee82d8cd6537963bc3d3b14bcca/src/rp2_common/pico_unique_id/unique_id.c#L35-L44

    pub const PICO_UNIQUE_BOARD_ID_SIZE_BYTES: usize = 8;

    #[derive(Debug, Copy, Clone, Default, Eq, PartialEq, defmt::Format)]
    pub struct SerialAscii([u8; PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2]);

    #[derive(Debug, Copy, Clone, Default, Eq, PartialEq, defmt::Format)]
    pub struct SerialNumber(pub u64);

    #[derive(Debug, Copy, Clone, Default, defmt::Format)]
    pub struct ChipInfo {
        /// Value of the CHIP_INFO_PACKAGE_SEL register, no documentation on that?
        pub package_sel: u32,
        /// RP2350 device id.
        pub device_id: u32,
        /// RP2350 wafer id.
        pub wafer_id: u32,
    }

    impl ChipInfo {
        pub fn serial_number(&self) -> SerialNumber {
            let mut serial_number_bytes: [u8; PICO_UNIQUE_BOARD_ID_SIZE_BYTES] = Default::default();
            serial_number_bytes[4..].copy_from_slice(&self.wafer_id.to_le_bytes());
            serial_number_bytes[0..4].copy_from_slice(&self.device_id.to_le_bytes());
            SerialNumber(u64::from_le_bytes(serial_number_bytes))
        }
        pub fn serial_ascii(&self) -> SerialAscii {
            let mut res: SerialAscii = Default::default();
            // Lets just avoid format here and do it manually, it needs to be upper case for the USB
            // serial matching.
            const LOOKUP: &[u8; 16] = b"0123456789ABCDEF";

            let mut serial_number_bytes: [u8; PICO_UNIQUE_BOARD_ID_SIZE_BYTES] = Default::default();
            serial_number_bytes[4..].copy_from_slice(&self.wafer_id.to_le_bytes());
            serial_number_bytes[0..4].copy_from_slice(&self.device_id.to_le_bytes());

            for i in 0..(res.0.len() / 2) {
                let low = serial_number_bytes[i] & 0xF;
                let high = (serial_number_bytes[i] >> 4) & 0xF;
                res.0[res.0.len() - i * 2 - 1] = LOOKUP[low as usize];
                res.0[res.0.len() - i * 2 - 1 - 1] = LOOKUP[high as usize];
            }
            res
        }
    }
    impl SerialAscii {
        pub fn as_str(&self) -> &str {
            // Unwrap is safe because this is only ever created by serial_ascii, which always creates
            // valid ascii.
            unsafe { core::str::from_utf8_unchecked(&self.0) }
        }
        pub fn as_slice(&self) -> &[u8] {
            &self.0
        }
        pub fn as_array(&self) -> &[u8; PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2] {
            &self.0
        }
    }

    pub fn get_chip_info() -> ChipInfo {
        const SYS_INFO_CHIP_INFO: u32 = 0x0001;
        const FLAGS: u32 = SYS_INFO_CHIP_INFO;
        let mut words: [u32; 4] = Default::default();
        let rc = unsafe { rom_data::get_sys_info(words.as_mut_ptr(), words.len(), FLAGS) };
        if rc < 0 {
            panic!("get sys info failed; {rc}");
        }
        if rc != 4 {
            panic!("get sys info returned unexpected count; {rc}");
        }
        if (words[0] & SYS_INFO_CHIP_INFO) == 0 {
            panic!("get sys info did not return chip info {}", words[0]);
        }
        // Okay, now finally we can read the data, since chip info is always the first entry in the returned data.
        ChipInfo {
            package_sel: words[1],
            device_id: words[2],
            wafer_id: words[3],
        }
    }

    #[derive(Debug, Copy, Clone, Default, defmt::Format)]
    pub struct FlashDeviceInfo {
        pub cs0_size_bits: u32,
        pub cs1_size_bits: u32,
        pub d8h_support_erase: bool,
    }

    /// Get the flash device info, which can only express up to 2megabytes of storage...
    pub fn get_flash_dev_info() -> FlashDeviceInfo {
        const SYS_FLASH_DEVICE_INFO: u32 = 0x0008;
        const FLAGS: u32 = SYS_FLASH_DEVICE_INFO;
        let mut words: [u32; 2] = Default::default();
        let rc = unsafe { rom_data::get_sys_info(words.as_mut_ptr(), words.len(), FLAGS) };
        if rc < 0 {
            panic!("get sys info failed; {rc}");
        }
        if rc != 2 {
            panic!("get sys info returned unexpected count; {rc}");
        }
        if (words[0] & SYS_FLASH_DEVICE_INFO) == 0 {
            panic!("get sys info did not return chip info {}", words[0]);
        }
        // bits 31:16 are reserved, lets mask those out.
        let data = words[1] & 0xFFFF;
        // Then, 4 bytes for each chip select.
        let cs1 = (data >> 12) & 0b1111;
        let cs0 = (data >> 8) & 0b1111;
        let cs0_size_bits = if cs0 == 0 { 0 } else { 4096 << cs0 };
        let cs1_size_bits = if cs1 == 0 { 0 } else { 4096 << cs1 };
        let d8h_support_erase = ((data >> 7) & 0b1) == 1;

        // Okay, now finally we can read the data, since chip info is always the first entry in the returned data.
        FlashDeviceInfo {
            cs0_size_bits,
            cs1_size_bits,
            d8h_support_erase,
        }
    }
}

pub mod otp {
    const OTP_DATA_BASE: *const u32 = 0x40130000 as *const u32;
    // First byte seems to be good, matches the serial.
    pub fn get_otp_chipid() -> [u32; 4] {
        unsafe {
            [
                *OTP_DATA_BASE.offset(0),
                *OTP_DATA_BASE.offset(1),
                *OTP_DATA_BASE.offset(2),
                *OTP_DATA_BASE.offset(3),
            ]
        }
    }
}

pub mod xip {
    const XIP_NOCACHE_NOALLOC_NOTRANSLATE_BASE: *const u8 = 0x1c000000 as *const u8;
    pub unsafe fn flash_slice(flash_offset: usize, length: usize) -> &'static [u8] {
        &core::slice::from_raw_parts(
            XIP_NOCACHE_NOALLOC_NOTRANSLATE_BASE.offset(flash_offset as isize),
            length,
        )
    }
}

pub mod rom_data {
    // The functions below use the bootrom api, but the datasheet states the partition table is at the start of the flash
    // and we could read it from there...;
    // let start_slice = unsafe { super::xip::flash_slice(0, 0x20) };
    // defmt::warn!("start slice: {:x}", start_slice);
    // Yeah, we could probably read that as well...
    // [d3, de, ff, ff, a, 11, 0, 2, 0, 80, 0, fc, 2, 20, 20, fc, 1, 10, 6, fc, 0, 0, 0, 0, 0, 0, 0, 0, 8, 66, 69, 72]
    // is a block, p356; PICOBIN_BLOCK_MARKER_START (0xffffded3)
    // See page 416 on block structure.
    //   a, 11, 0, 2  is an item. From picobin.h; PICOBIN_BLOCK_ITEM_PARTITION_TABLE ix 0x0a
    // 0x66, 0x69, 0x72... 'fir' mware...

    pub fn get_partition_count() -> Option<usize> {
        let mut words = [0u32; 4];
        const PT_INFO: u32 = 0x0001;
        let rc = unsafe {
            embassy_rp::rom_data::get_partition_table_info(words.as_mut_ptr(), words.len(), PT_INFO)
        };
        if rc < 0 {
            panic!("get_partition_table_info failed; {rc}");
        }
        if rc != 4 {
            panic!("get_partition_table_info returned unexpected count; {rc}");
        }
        if (words[0] & PT_INFO) == 0 {
            panic!(
                "get_partition_table_info did not return partition info {}",
                words[0]
            );
        }
        let partition_count_info = words[1].to_le_bytes();
        let partition_count = partition_count_info[0];
        let have_partitions = (partition_count_info[1] & 0b1) == 1;
        if have_partitions {
            Some(partition_count as usize)
        } else {
            None
        }
    }

    pub fn get_partition_by_name(name: &str) -> Option<embassy_rp::block::Partition> {
        if let Some(v) = get_partition_count() {
            for i in 0..v {
                if let Some(p) = get_partition(i) {
                    if let Some(p_name) = p.get_name() {
                        if p_name == name {
                            return Some(p);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn get_partition(index: usize) -> Option<embassy_rp::block::Partition> {
        if index >= 16 {
            return None; // Can only support up to 16 partitions; 5.1.2. Partition Tables
        }
        const SINGLE_PARTITION: u32 = 0x8000;
        const PARTITION_LOCATION_AND_FLAGS: u32 = 0x0010;
        const PARTITION_ID: u32 = 0x0020;
        const PARTITION_FAMILY_IDS: u32 = 0x0040; // not clear what this returns, doesn't return any words?
        const PARTITION_NAME: u32 = 0x0080;

        // Create the partition and flags.
        let (mut partition, flags) = {
            let mut words = [0u32; 4];
            let rc = unsafe {
                embassy_rp::rom_data::get_partition_table_info(
                    words.as_mut_ptr(),
                    words.len(),
                    SINGLE_PARTITION | ((index as u32) << 24) | PARTITION_LOCATION_AND_FLAGS,
                )
            };
            defmt::warn!("rc and words: {}, {:?}", rc, words);
            if rc != 3 {
                // ROM function call failed, or we got an unexpected number of words.
                return None;
            }

            let partition = if (words[0] & PARTITION_LOCATION_AND_FLAGS) != 0 {
                embassy_rp::block::Partition::from_raw(words[1], words[2])
            } else {
                return None;
            };
            let flags = words[2];
            (partition, flags)
        };

        const FLAGS_HAS_ID_BITS: u32 = 0x00000001;
        const FLAGS_HAS_NAME_BITS: u32 = 0x00001000;
        if flags & FLAGS_HAS_ID_BITS != 0 {
            'id_retrieval: {
                // Read the id, and copy it.
                let mut words = [0u32; 3];
                let rc = unsafe {
                    embassy_rp::rom_data::get_partition_table_info(
                        words.as_mut_ptr(),
                        words.len(),
                        SINGLE_PARTITION | ((index as u32) << 24) | PARTITION_ID,
                    )
                };
                //defmt::warn!("id rc and words: {}, {:?}", rc, words);
                if rc != 3 {
                    // We can still return the partition this far.
                    break 'id_retrieval;
                }
                if words[0] & PARTITION_ID != 0 {
                    let id = (words[2] as u64) << 32 | words[1] as u64;
                    partition = partition.with_id(id);
                }
            }
        }
        if flags & FLAGS_HAS_NAME_BITS != 0 {
            'name_retrieval: {
                // Read the name, and then copy it into the buffer, we can't copy into the name directly.
                let mut name_buffer = [0u32; 128 / 4]; // need a u32 buffer, but max length is 128 bytes.
                let rc = unsafe {
                    embassy_rp::rom_data::get_partition_table_info(
                        name_buffer.as_mut_ptr(),
                        name_buffer.len(),
                        SINGLE_PARTITION | ((index as u32) << 24) | PARTITION_NAME,
                    )
                };
                //defmt::warn!("name rc and words: {}, {:?}", rc, name_buffer);
                if rc < 2 {
                    // ROM function call failed, or we got an unexpected number of words.
                    break 'name_retrieval;
                }
                if name_buffer[0] & PARTITION_NAME != 0 {
                    // get a u8 slice first.
                    use zerocopy::IntoBytes;
                    let raw = name_buffer[1..].as_bytes();
                    let len = (raw[0] & 0x7f) as usize;
                    let name_bytes = &raw[1..1 + len];
                    if let Ok(name) = str::from_utf8(name_bytes) {
                        partition = partition.with_name(name);
                    }
                }
            }
        }

        // This is untested, but seems pretty simple.
        {
            let mut families = [0u32; 5];
            let rc = unsafe {
                embassy_rp::rom_data::get_partition_table_info(
                    families.as_mut_ptr(),
                    families.len(),
                    SINGLE_PARTITION | ((index as u32) << 24) | PARTITION_FAMILY_IDS,
                )
            };
            //defmt::warn!("families rc and words: {}, {:?}", rc, families);
            if families[0] & PARTITION_FAMILY_IDS != 0 {
                let actual_families = rc - 1;
                let family_slice = &families[1..1 + actual_families as usize];
                partition = partition.with_extra_families(&family_slice);
            }
        }

        Some(partition)
    }
}

pub mod reboot {

    use embassy_time::Duration;

    use core::ops::BitXor;
    // Section 5.4.8.24. reboot, page 395
    // Normal:
    pub const PICO_BOOTROM_REBOOT_FLAGS_NORMAL: u32 = 0x0000;
    // p0 is the boot diagnostic partition, lower 8 bits only.
    // Bootsel:
    // P0 is GPIO for actvitity indicator.
    pub const PICO_BOOTROM_REBOOT_FLAGS_BOOTSEL: u32 = 0x02;
    pub const PICO_BOOTROM_REBOOT_FLAGS_BOOTSEL_P1_DISABLE_MSD: u32 = 0x01;
    pub const PICO_BOOTROM_REBOOT_FLAGS_BOOTSEL_P1_DISABLE_PICOBOOT: u32 = 0x02;

    // Can be OR with any of these flags.
    pub const PICO_BOOTROM_REBOOT_NO_RETURN_ON_SUCCESS: u32 = 0x0100;

    #[allow(unused)]
    pub fn dev_boot_to_bootsel_watchdog(w: &mut embassy_rp::watchdog::Watchdog) -> ! {
        // This method also works, and was the main identifier for the p0 & p1 situation.
        // boot flags
        w.set_scratch(2, PICO_BOOTROM_REBOOT_FLAGS_BOOTSEL_P1_DISABLE_MSD);
        // gpio index.
        w.set_scratch(3, 0);

        // Magic values to trigger bootrom method.
        w.set_scratch(4, 0xb007c0d3);
        w.set_scratch(5, 0x4ff83f2du32.bitxor(0xb007c0d3));
        w.set_scratch(6, 2);
        w.set_scratch(7, 0xb007c0d3);

        // Invoke the watchdog
        w.trigger_reset();
        loop {}
    }

    pub fn dev_boot_to_bootsel() -> ! {
        // Now we need to do the equivalent of;
        // rom_reset_usb_boot_extra(gpio, (request->wValue & 0x7f) | PICO_STDIO_USB_RESET_BOOTSEL_INTERFACE_DISABLE_MASK, active_low);
        // Well, that exists for the rp2040;
        // https://github.com/embassy-rs/embassy/blob/20ce4d7deb3b16ff32bd68f7adae9066ddd40e94/embassy-rp/src/rom_data/rp2040.rs#L229-L239
        //let f = embassy_rp::rom_data::reset_to_usb_boot::ptr();
        const BOOTSEL_MAIN: u32 =
            PICO_BOOTROM_REBOOT_FLAGS_BOOTSEL | PICO_BOOTROM_REBOOT_NO_RETURN_ON_SUCCESS;
        const DELAY_MS: u32 = 500;
        const P0_GPIO_PIN: u32 = 0;
        const P1_BOOT_PROPERTIES: u32 = PICO_BOOTROM_REBOOT_FLAGS_BOOTSEL_P1_DISABLE_MSD;

        // Well, that disable MSD doesn't stick?
        // The p0 and p1 parameters are generally written to watchdog scratch registers 2 & 3, and are interpreted post-reboot
        // by the boot path code.
        //
        //

        // I think the datasheet is wrong, it doesn't agree with pico-sdk, the following works to inhibit the MSD.
        // https://github.com/raspberrypi/pico-feedback/issues/466
        embassy_rp::rom_data::reboot(BOOTSEL_MAIN, DELAY_MS, P1_BOOT_PROPERTIES, P0_GPIO_PIN);

        // This is never reached.
        loop {}
    }

    #[derive(Debug, Copy, Clone, Default, Eq, PartialEq, defmt::Format)]
    pub enum RebootSettings {
        #[default]
        Normal,
        Bootsel {
            picoboot: bool,
            mass_storage: bool,
        },
    }
    impl RebootSettings {
        /// Reboot settings for flashing the microcontroller.
        ///
        /// This disables the mass storage interface to avoid mounting it etc.
        pub fn flash() -> Self {
            RebootSettings::Bootsel {
                picoboot: true,
                mass_storage: false,
            }
        }
    }

    pub fn reboot_raw(main_flags: u32, delay_ms: u32, boot_properties: u32) {
        const P0_GPIO_PIN: u32 = 0;
        // I think the datasheet is wrong, it doesn't agree with pico-sdk, the following works to inhibit the MSD.
        // https://github.com/raspberrypi/pico-feedback/issues/466
        embassy_rp::rom_data::reboot(main_flags, delay_ms, boot_properties, P0_GPIO_PIN);
    }

    pub fn reboot(boot_type: RebootSettings, delay: Duration) -> ! {
        let (main, boot_properties) = match boot_type {
            RebootSettings::Normal => (0, 0),
            RebootSettings::Bootsel {
                picoboot,
                mass_storage,
            } => (
                PICO_BOOTROM_REBOOT_FLAGS_BOOTSEL,
                if picoboot {
                    0
                } else {
                    PICO_BOOTROM_REBOOT_FLAGS_BOOTSEL_P1_DISABLE_PICOBOOT
                } | if mass_storage {
                    0
                } else {
                    PICO_BOOTROM_REBOOT_FLAGS_BOOTSEL_P1_DISABLE_MSD
                },
            ),
        };

        const P0_GPIO_PIN: u32 = 0;

        let delay_ms = delay.as_millis().min(u32::MAX as u64) as u32;
        // I think the datasheet is wrong, it doesn't agree with pico-sdk, the following works to inhibit the MSD.
        // https://github.com/raspberrypi/pico-feedback/issues/466
        embassy_rp::rom_data::reboot(
            main | PICO_BOOTROM_REBOOT_NO_RETURN_ON_SUCCESS,
            delay_ms,
            boot_properties,
            P0_GPIO_PIN,
        );

        // This is never reached.
        loop {}
    }
}

pub mod panic_info_scratch {
    #![allow(static_mut_refs)]

    use super::reboot;
    use core::num::NonZeroU8;
    use embassy_rp::watchdog::Watchdog;
    // We cannot use the entire watchdog's scratch registers, and we don't currently have access to the scratch registers
    // from POWMAN because they're just not exposed in the HAL yet.
    // Instead, lets just keep track of files by a single byte.
    //

    // Global that holds the strings used to create the file index.
    static mut PANIC_FILE_STRINGS: Option<&[&'static str]> = None;

    #[derive(Debug, Copy, Clone, Default, Eq, PartialEq, defmt::Format)]
    pub struct PanicStorage {
        /// The line number at which the panic occured.
        line: u16,
        /// The file index in which the panic occured.
        file: Option<NonZeroU8>,
        _pad: u8,
    }

    impl PanicStorage {
        /// The line number on which the panic occured.
        pub fn line(&self) -> u16 {
            self.line
        }
        /// Returns the string from the panic file strings for which the file index matches.
        pub fn file(&self) -> Option<&str> {
            unsafe {
                if let Some(index) = self.file {
                    PANIC_FILE_STRINGS
                        .map(|x| x.get(index.get() as usize - 1))
                        .flatten()
                        .copied()
                } else {
                    None
                }
            }
        }

        /// Returns whether this PanicStorage actually panicked.
        pub fn is_panicked(&self) -> bool {
            self.line != 0 && self.line != 0xfffe // value after flashing.
        }
        /// Instantiates the PanicStorage from the 4 byte buffer.
        pub fn from_buffer(buffer: [u8; 4]) -> PanicStorage {
            let line = u16::from_le_bytes([buffer[0], buffer[1]]);
            let file_value = buffer[2];
            let file = if file_value != 0 {
                Some(NonZeroU8::new(file_value).unwrap())
            } else {
                None
            };
            let _pad = buffer[3];
            Self { line, file, _pad }
        }

        /// Converts the PanicStorage to the 4 byte buffer.
        pub fn to_buffer(&self) -> [u8; 4] {
            let mut res: [u8; 4] = Default::default();
            let l = self.line().to_le_bytes();
            res[0] = l[0];
            res[1] = l[1];
            if let Some(v) = self.file.as_ref() {
                res[2] = v.get();
            }

            res
        }

        /// Constructs a PanicStorage from the panic information, using the PANIC_FILE_STRINGS to look up the files.
        pub fn from_panic(info: &core::panic::PanicInfo) -> PanicStorage {
            let mut storage = PanicStorage {
                line: 1, // force something to be non-zero, even if no storage.
                ..Default::default()
            };

            if let Some(location) = info.location() {
                storage.line = location.line() as u16;

                // Determine the file index by matching from the rear.
                let filename = location.file();
                if let Some(static_files) = unsafe { PANIC_FILE_STRINGS } {
                    for (si, s) in static_files.iter().enumerate() {
                        let si = si + 1; // ensure nonzero.
                        if filename.ends_with(s) {
                            storage.file = Some(NonZeroU8::new(si as u8).unwrap());
                            break;
                        }
                    }
                } else {
                    defmt::error!("no panic file strings set");
                }
            }
            storage
        }
    }

    // 5 Seems to be emptied on a fresh boot, which is nice, and a constant value after flashing.
    pub const PANIC_INFO_WATCHDOG_SCRATCH: usize = 5;

    /// Take the panic from the storage location and return it if it has panicked.
    pub fn take_panic(w: &mut Watchdog) -> Option<PanicStorage> {
        let v = w.get_scratch(PANIC_INFO_WATCHDOG_SCRATCH);
        w.set_scratch(PANIC_INFO_WATCHDOG_SCRATCH, 0);
        let storage = PanicStorage::from_buffer(v.to_le_bytes());
        if storage.is_panicked() {
            Some(storage)
        } else {
            None
        }
    }

    /// Should be called once with a static array of strings that hold the filenames. Filenames are matched from right,
    /// first matching filename wins.
    pub fn set_panic_files(s: &'static [&'static str]) {
        unsafe {
            if PANIC_FILE_STRINGS.is_some() {
                defmt::error!("setting panic strings while already set, ignoring");
            } else {
                PANIC_FILE_STRINGS = Some(s);
            }
        }
    }

    // Just to easily have one in another file.
    pub fn trigger_panic() {
        panic!();
    }

    /// Panic handler that stores the panic information into a watchdog register and reboots the device.
    #[panic_handler]
    fn panic(info: &core::panic::PanicInfo) -> ! {
        use crate::rp2350_util::reboot::RebootSettings;
        use embassy_time::Duration;

        let storage = PanicStorage::from_panic(info);

        unsafe {
            let p = embassy_rp::Peripherals::steal();
            let mut w = embassy_rp::watchdog::Watchdog::new(p.WATCHDOG);
            let data = storage.to_buffer();
            w.set_scratch(PANIC_INFO_WATCHDOG_SCRATCH, u32::from_le_bytes(data));
        }
        reboot::reboot(RebootSettings::Normal, Duration::from_millis(100));
    }
}
