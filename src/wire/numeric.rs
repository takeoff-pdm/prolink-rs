//! The two fixed-point scalars Pro DJ Link uses for tempo and pitch.

use core::fmt;

/// Turntable pitch as a multiplier, where `1.0` means the track plays at its
/// recorded tempo.
///
/// On the wire this is a 32-bit fixed-point value with `0x100000` meaning
/// `1.0`, giving a resolution of roughly one part in a million.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
pub struct Pitch(pub f32);

impl Pitch {
    /// The scaling factor between the wire value and the multiplier.
    pub const SCALE: f32 = 1_048_576.0; // 0x100000

    /// Normal playback speed.
    pub const NORMAL: Pitch = Pitch(1.0);

    /// Decodes the raw 32-bit wire value.
    pub fn from_raw(raw: u32) -> Self {
        Pitch(raw as f32 / Self::SCALE)
    }

    /// Encodes back to the raw 32-bit wire value, saturating at the ends of the
    /// representable range.
    pub fn to_raw(self) -> u32 {
        let scaled = libm::roundf(self.0 * Self::SCALE);
        if scaled <= 0.0 {
            0
        } else if scaled >= u32::MAX as f32 {
            u32::MAX
        } else {
            scaled as u32
        }
    }

    /// Pitch expressed the way a CDJ display shows it: percent deviation from
    /// normal speed, so `1.06` becomes `+6.0`.
    pub fn as_percent(self) -> f32 {
        (self.0 - 1.0) * 100.0
    }
}

impl fmt::Display for Pitch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:+.2}%", self.as_percent())
    }
}

/// Track tempo in beats per minute.
///
/// On the wire this is a 16-bit value scaled by 100, so `128.5` BPM travels as
/// `12850`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
pub struct Bpm(pub f32);

impl Bpm {
    /// The scaling factor between the wire value and BPM.
    pub const SCALE: f32 = 100.0;

    /// The raw value hardware sends when it has no tempo to report — either no
    /// track is loaded or the track has not been analyzed.
    pub const NONE_RAW: u16 = 0xffff;

    /// Decodes the raw 16-bit wire value.
    ///
    /// Returns `None` for the [`NONE_RAW`] sentinel rather than the nonsense
    /// value `655.35`, which is what a naive division would produce.
    ///
    /// [`NONE_RAW`]: Bpm::NONE_RAW
    pub fn from_raw(raw: u16) -> Option<Self> {
        if raw == Self::NONE_RAW {
            None
        } else {
            Some(Bpm(raw as f32 / Self::SCALE))
        }
    }

    /// Encodes back to the raw 16-bit wire value.
    ///
    /// Returns `None` if the tempo does not fit, rather than saturating: `as
    /// u16` would clamp an out-of-range tempo to `0xffff`, which the protocol
    /// reads as "no tempo at all" — a silently wrong value rather than an
    /// obviously wrong one.
    pub fn to_raw_checked(self) -> Option<u16> {
        let scaled = libm::roundf(self.0 * Self::SCALE);
        if scaled < 0.0 || scaled >= Self::NONE_RAW as f32 {
            None
        } else {
            Some(scaled as u16)
        }
    }

    /// Encodes back to the raw wire value, substituting the "no tempo"
    /// sentinel for anything out of range.
    pub fn to_raw(self) -> u16 {
        self.to_raw_checked().unwrap_or(Self::NONE_RAW)
    }
}

impl fmt::Display for Bpm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

/// Encodes an optional tempo, mapping `None` to the wire sentinel.
pub(crate) fn bpm_to_raw(bpm: Option<Bpm>) -> u16 {
    bpm.map_or(Bpm::NONE_RAW, Bpm::to_raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pitch_round_trips() {
        for raw in [0u32, 0x080000, 0x100000, 0x180000, 0x200000] {
            assert_eq!(Pitch::from_raw(raw).to_raw(), raw, "raw {raw:#x}");
        }
        assert_eq!(Pitch::from_raw(0x100000), Pitch::NORMAL);
        assert_eq!(Pitch::from_raw(0x080000).0, 0.5);
    }

    #[test]
    fn pitch_percent_matches_the_cdj_display() {
        let pitch = Pitch::from_raw(0x100000 + 0x100000 / 100 * 6);
        assert!((pitch.as_percent() - 6.0).abs() < 0.01);
    }

    #[test]
    fn pitch_saturates_rather_than_wrapping() {
        assert_eq!(Pitch(-1.0).to_raw(), 0);
        assert_eq!(Pitch(1.0e9).to_raw(), u32::MAX);
    }

    #[test]
    fn bpm_round_trips() {
        for raw in [0u16, 1, 12345, 12800, 0xfffe] {
            let bpm = Bpm::from_raw(raw).expect("not the sentinel");
            assert_eq!(bpm.to_raw(), raw, "raw {raw}");
        }
        assert_eq!(Bpm::from_raw(12345).unwrap().0, 123.45);
    }

    #[test]
    fn bpm_sentinel_is_absence_not_six_hundred() {
        assert_eq!(Bpm::from_raw(Bpm::NONE_RAW), None);
        // The value a naive `raw / 100.0` would have produced.
        assert_eq!(Bpm(655.35).to_raw_checked(), None);
    }

    #[test]
    fn bpm_out_of_range_is_reported_not_clamped() {
        assert_eq!(Bpm(-1.0).to_raw_checked(), None);
        assert_eq!(Bpm(10_000.0).to_raw_checked(), None);
        assert_eq!(Bpm(10_000.0).to_raw(), Bpm::NONE_RAW);
    }
}
