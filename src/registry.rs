//! The set of devices currently on the network.

use core::net::Ipv4Addr;

use crate::constants::{MAX_DEVICES, MODEL_LEN};
use crate::device::Device;
use crate::packet::DeviceType;
use crate::time::Millis;
use crate::wire::{FixedStr, MacAddr};

/// Every device currently believed to be on the network.
///
/// Fixed capacity, no allocation: a Pro DJ Link network holds at most six
/// players plus a mixer plus rekordbox, so [`MAX_DEVICES`] slots is not a
/// limitation anyone will meet in practice. Devices are keyed by player
/// number, which is the identity the rest of the protocol uses.
#[derive(Debug, Clone, Default)]
pub struct DeviceRegistry {
    devices: [Option<Device>; MAX_DEVICES],
}

/// What changed as a result of observing a keepalive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryChange {
    /// A device we had not seen before.
    Added,
    /// A device we already knew about, still alive.
    Refreshed,
    /// A device we knew about, now reachable at a different address.
    ///
    /// Almost always a DHCP lease change, but also what a device impersonating
    /// another one would look like.
    Readdressed {
        /// Where it used to be.
        previous_ip: Ipv4Addr,
    },
    /// The registry is full and this device was not recorded.
    Full,
}

impl DeviceRegistry {
    /// An empty registry.
    pub const fn new() -> Self {
        DeviceRegistry {
            devices: [None; MAX_DEVICES],
        }
    }

    /// Records that `player_number` is alive at `ip`, adding it if new.
    pub fn observe(
        &mut self,
        player_number: u8,
        device_type: DeviceType,
        model: FixedStr<MODEL_LEN>,
        ip: Ipv4Addr,
        mac: Option<MacAddr>,
        now: Millis,
    ) -> RegistryChange {
        if let Some(index) = self.index_of(player_number) {
            let device = self.devices[index].as_mut().expect("index_of found it");
            let previous_ip = device.ip;

            device.last_keepalive = now;
            device.device_type = device_type;
            device.model = model;
            device.ip = ip;
            if mac.is_some() {
                device.mac = mac;
            }

            return if previous_ip == ip {
                RegistryChange::Refreshed
            } else {
                RegistryChange::Readdressed { previous_ip }
            };
        }

        let Some(slot) = self.devices.iter_mut().find(|slot| slot.is_none()) else {
            return RegistryChange::Full;
        };
        let mut device = Device::new(player_number, device_type, model, ip, now);
        device.mac = mac;
        *slot = Some(device);
        RegistryChange::Added
    }

    /// The device with this player number, if it is present.
    pub fn get(&self, player_number: u8) -> Option<&Device> {
        self.index_of(player_number)
            .and_then(|index| self.devices[index].as_ref())
    }

    /// The device with this player number, mutably.
    pub fn get_mut(&mut self, player_number: u8) -> Option<&mut Device> {
        self.index_of(player_number)
            .and_then(|index| self.devices[index].as_mut())
    }

    /// Every device currently present, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter().flatten()
    }

    /// How many devices are present.
    pub fn len(&self) -> usize {
        self.devices.iter().flatten().count()
    }

    /// Whether no devices are present.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether a player number is currently claimed.
    ///
    /// This is what the virtual-CDJ negotiation consults before proposing a
    /// number for itself.
    pub fn is_taken(&self, player_number: u8) -> bool {
        self.get(player_number).is_some()
    }

    /// The device that is currently tempo master, if any.
    pub fn master(&self) -> Option<&Device> {
        self.iter().find(|device| device.is_master())
    }

    /// Removes every device that has been silent for longer than `ttl_ms`.
    ///
    /// Calls `on_lost` with each removed player number. Returns how many were
    /// removed.
    pub fn expire(&mut self, now: Millis, ttl_ms: u64, mut on_lost: impl FnMut(u8)) -> usize {
        let mut removed = 0;
        for slot in &mut self.devices {
            let Some(device) = slot else { continue };
            if device.is_expired(now, ttl_ms) {
                on_lost(device.player_number);
                *slot = None;
                removed += 1;
            }
        }
        removed
    }

    /// Forgets everything.
    pub fn clear(&mut self) {
        self.devices = [None; MAX_DEVICES];
    }

    fn index_of(&self, player_number: u8) -> Option<usize> {
        self.devices.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|device| device.player_number == player_number)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> FixedStr<MODEL_LEN> {
        FixedStr::new("CDJ-3000").unwrap()
    }

    fn observe(registry: &mut DeviceRegistry, number: u8, last: u8, now: u64) -> RegistryChange {
        registry.observe(
            number,
            DeviceType::Cdj,
            model(),
            Ipv4Addr::new(192, 168, 1, last),
            None,
            Millis(now),
        )
    }

    #[test]
    fn a_new_device_is_added_then_refreshed() {
        let mut registry = DeviceRegistry::new();
        assert_eq!(observe(&mut registry, 1, 5, 0), RegistryChange::Added);
        assert_eq!(observe(&mut registry, 1, 5, 100), RegistryChange::Refreshed);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn a_moved_device_reports_its_previous_address() {
        let mut registry = DeviceRegistry::new();
        observe(&mut registry, 1, 5, 0);
        assert_eq!(
            observe(&mut registry, 1, 9, 100),
            RegistryChange::Readdressed {
                previous_ip: Ipv4Addr::new(192, 168, 1, 5)
            }
        );
        assert_eq!(registry.get(1).unwrap().ip, Ipv4Addr::new(192, 168, 1, 9));
        assert_eq!(registry.len(), 1, "readdressing must not duplicate");
    }

    #[test]
    fn silence_past_the_ttl_removes_a_device() {
        let mut registry = DeviceRegistry::new();
        observe(&mut registry, 1, 5, 1_000);
        observe(&mut registry, 2, 6, 1_000);
        observe(&mut registry, 2, 6, 4_000); // player 2 keeps talking

        let mut lost = [0u8; 4];
        let mut count = 0;
        let removed = registry.expire(Millis(6_500), 5_000, |number| {
            lost[count] = number;
            count += 1;
        });

        assert_eq!(removed, 1);
        assert_eq!(&lost[..count], &[1]);
        assert!(registry.get(1).is_none());
        assert!(registry.get(2).is_some());
    }

    #[test]
    fn a_device_exactly_at_the_ttl_is_kept() {
        let mut registry = DeviceRegistry::new();
        observe(&mut registry, 1, 5, 0);
        assert_eq!(registry.expire(Millis(5_000), 5_000, |_| {}), 0);
        assert_eq!(registry.expire(Millis(5_001), 5_000, |_| {}), 1);
    }

    #[test]
    fn taken_numbers_are_what_negotiation_must_avoid() {
        let mut registry = DeviceRegistry::new();
        observe(&mut registry, 1, 5, 0);
        observe(&mut registry, 3, 7, 0);
        assert!(registry.is_taken(1));
        assert!(registry.is_taken(3));
        assert!(!registry.is_taken(2));
    }

    #[test]
    fn a_full_registry_refuses_rather_than_evicting() {
        let mut registry = DeviceRegistry::new();
        for n in 0..MAX_DEVICES as u8 {
            assert_eq!(
                observe(&mut registry, n + 1, n + 1, 0),
                RegistryChange::Added
            );
        }
        assert_eq!(observe(&mut registry, 99, 99, 0), RegistryChange::Full);
        // The devices we already had must be untouched.
        assert_eq!(registry.len(), MAX_DEVICES);
        assert!(registry.is_taken(1));
    }

    #[test]
    fn a_freed_slot_is_reused() {
        let mut registry = DeviceRegistry::new();
        for n in 0..MAX_DEVICES as u8 {
            observe(&mut registry, n + 1, n + 1, 0);
        }
        registry.expire(Millis(10_000), 5_000, |_| {});
        assert!(registry.is_empty());
        assert_eq!(observe(&mut registry, 1, 1, 10_000), RegistryChange::Added);
    }
}
