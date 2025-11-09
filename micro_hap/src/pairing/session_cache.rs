// This is the HAPBLESession cache.
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingBLESessionCache.c
// Used for storing the session shared secrets and by pair resume.
// Throughout, we cut the corner to just use a proper PairingID and not an integer.

// Cache is 8 long
// https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/HAP/HAPPairingBLESessionCache.h#L25
// Odd that fetch invalidates the stored information, but it also keeps a lastUsed... how does that work?

use super::{SessionId, X25519_BYTES};
use crate::PlatformSupport;

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
struct CacheEntry {
    // How is this pairing id used here? it's an integer....
    session_id: SessionId,
    shared_secret: [u8; X25519_BYTES],
    /// 0 is invalid, >0 is timestamp.
    last_used: u64, // at 64 bits, we can store an embassy_time::Instant in us and never overflow.
}

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct BleSessionCache {
    entries: [CacheEntry; 8],
}
impl BleSessionCache {
    pub fn save(
        &mut self,
        support: &impl PlatformSupport,
        session_id: &SessionId,
        shared: &[u8; X25519_BYTES],
    ) {
        // Find the lowest last used slot.
        // Unwrap is safe because the iterator is never empty.
        let slot = self.entries.iter_mut().min_by_key(|f| f.last_used).unwrap();
        slot.last_used = support.get_time().as_micros();
        slot.session_id = *session_id;
        slot.shared_secret = *shared;
    }
    pub fn fetch(&mut self, session: &SessionId) -> Option<[u8; X25519_BYTES]> {
        if let Some(found_cache) = self.entries.iter_mut().find(|z| &z.session_id == session) {
            let shared = found_cache.shared_secret;
            *found_cache = Default::default();
            Some(shared)
        } else {
            None
        }
    }
    pub fn wipe(&mut self) {
        *self = Default::default()
    }
}
