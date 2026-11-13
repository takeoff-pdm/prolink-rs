//! Monotonic time, expressed in milliseconds.

/// Milliseconds since an arbitrary but fixed epoch.
///
/// `u64` rather than `u32` deliberately: 32 bits of milliseconds wraps after
/// 49.7 days, which is a realistic uptime for a box left running in a booth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millis(pub u64);

impl Millis {
    /// The epoch itself.
    pub const ZERO: Millis = Millis(0);

    /// A deadline far enough out that nothing will ever reach it.
    pub const NEVER: Millis = Millis(u64::MAX);

    /// This instant, moved `ms` milliseconds later. Saturates at [`NEVER`].
    ///
    /// [`NEVER`]: Millis::NEVER
    pub const fn add(self, ms: u64) -> Millis {
        Millis(self.0.saturating_add(ms))
    }

    /// Milliseconds elapsed since `earlier`, or zero if `earlier` is in the
    /// future. Never panics on a clock that steps backwards.
    pub const fn since(self, earlier: Millis) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    /// Whether this instant is at or past `deadline`.
    pub const fn reached(self, deadline: Millis) -> bool {
        self.0 >= deadline.0
    }

    /// The earlier of two instants.
    pub const fn min(self, other: Millis) -> Millis {
        if self.0 <= other.0 {
            self
        } else {
            other
        }
    }
}

/// A source of monotonic time.
///
/// Implementing this is optional: [`Session::poll`] takes the current time as
/// an argument, so a caller that already has an `Instant` in hand can pass it
/// straight in. The trait exists for the common case where you would rather
/// hand the session a clock once and call [`Session::poll_clocked`].
///
/// Time is *passed in* rather than pulled from an owned clock because the
/// replay adapter needs to drive a virtual clock from capture timestamps —
/// which would otherwise require the adapter and the clock to share mutable
/// state.
///
/// [`Session::poll`]: crate::session::Session::poll
/// [`Session::poll_clocked`]: crate::session::Session::poll_clocked
pub trait Clock {
    /// The current time.
    fn now(&self) -> Millis;
}

/// A [`Clock`] backed by [`std::time::Instant`].
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct StdClock {
    start: std::time::Instant,
}

#[cfg(feature = "std")]
impl StdClock {
    /// Starts a clock whose epoch is now.
    pub fn new() -> Self {
        StdClock {
            start: std::time::Instant::now(),
        }
    }
}

#[cfg(feature = "std")]
impl Default for StdClock {
    fn default() -> Self {
        StdClock::new()
    }
}

#[cfg(feature = "std")]
impl Clock for StdClock {
    fn now(&self) -> Millis {
        Millis(self.start.elapsed().as_millis() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_saturates_instead_of_panicking() {
        assert_eq!(Millis(100).since(Millis(400)), 0);
        assert_eq!(Millis(400).since(Millis(100)), 300);
    }

    #[test]
    fn add_saturates_at_never() {
        assert_eq!(Millis::NEVER.add(1_000), Millis::NEVER);
    }
}
