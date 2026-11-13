//! The seam between this library and your network.
//!
//! [`Transport`] is the only thing standing between the protocol logic and a
//! real socket. Implement it and everything else in this crate — packet
//! codecs, device tracking, the virtual-CDJ state machine, [`Session`] — works
//! unchanged, whether you are on a laptop, on an embedded board, or replaying
//! a capture in a test.
//!
//! With the `std` feature you do not have to implement anything:
//! [`std_udp::StdUdpTransport`] binds the three ports for you.
//!
//! # Why synchronous and non-blocking
//!
//! `poll_recv` returns `Ok(None)` when there is nothing to read rather than
//! waiting for something to arrive. That one decision is what lets the same
//! [`Session`] run under a `std` thread, under an async embedded executor, and
//! over a canned byte stream:
//!
//! * a blocking implementation would need its own thread, which bare metal
//!   does not have;
//! * an `async fn` implementation would force every caller into a runtime, and
//!   make the replay adapter absurd.
//!
//! Waiting is therefore *not* part of this trait. An adapter that can wait
//! efficiently offers that as its own inherent method —
//! [`StdUdpTransport::wait_readable`] blocks on the three sockets, and an
//! embassy adapter would expose an `async fn wait_recv_ready`. This is the
//! same split `embedded-io` draws between `Read` and `ReadReady`.
//!
//! [`Session`]: crate::session::Session
//! [`StdUdpTransport::wait_readable`]: std_udp::StdUdpTransport::wait_readable

use core::net::Ipv4Addr;

use crate::constants::{ANNOUNCE_PORT, BEAT_PORT, STATUS_PORT};
use crate::wire::MacAddr;

#[cfg(any(test, feature = "testing"))]
pub mod loopback;
#[cfg(feature = "alloc")]
pub mod replay;
#[cfg(feature = "std")]
pub mod std_udp;

#[cfg(any(test, feature = "testing"))]
pub use loopback::MockTransport;
#[cfg(feature = "alloc")]
pub use replay::ReplayTransport;

/// One of the three Pro DJ Link UDP channels.
///
/// The protocol is symmetric: a packet sent on a channel goes to that
/// channel's port, and a packet received on that port belongs to that channel.
///
/// This is not interchangeable with a port number. Every channel carries the
/// same ten-byte magic prefix and their type bytes collide — `0x02` is an IP
/// claim on [`Announce`] but a fader-start command on [`Beat`] — so which
/// channel a datagram arrived on is the only thing that tells them apart. That
/// is why [`Transport::poll_recv`] must report it.
///
/// [`Announce`]: Channel::Announce
/// [`Beat`]: Channel::Beat
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Channel {
    /// UDP 50000 — keepalives, announcements, player-number negotiation.
    Announce = 0,
    /// UDP 50001 — beats, absolute position, on-air state, fader start.
    Beat = 1,
    /// UDP 50002 — CDJ and mixer status, media queries, load commands.
    Status = 2,
}

impl Channel {
    /// All three channels, in the order an adapter should poll them.
    ///
    /// [`Announce`](Channel::Announce) comes first because it carries device
    /// liveness: losing keepalives to a flood of status packets would make
    /// devices appear to drop off the network.
    pub const ALL: [Channel; 3] = [Channel::Announce, Channel::Beat, Channel::Status];

    /// The UDP port this channel uses.
    pub const fn port(self) -> u16 {
        match self {
            Channel::Announce => ANNOUNCE_PORT,
            Channel::Beat => BEAT_PORT,
            Channel::Status => STATUS_PORT,
        }
    }

    /// The channel a UDP port belongs to, if it is one of ours.
    pub const fn from_port(port: u16) -> Option<Channel> {
        match port {
            ANNOUNCE_PORT => Some(Channel::Announce),
            BEAT_PORT => Some(Channel::Beat),
            STATUS_PORT => Some(Channel::Status),
            _ => None,
        }
    }

    /// Whether traffic on this channel is normally broadcast.
    pub const fn is_broadcast(self) -> bool {
        matches!(self, Channel::Announce | Channel::Beat)
    }
}

/// Where a datagram should go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// Everyone on the local network.
    ///
    /// Deliberately symbolic. Computing a directed broadcast address needs the
    /// interface netmask, which the protocol layer has no way to learn and no
    /// business caching — it changes on a DHCP renewal. The adapter is the only
    /// layer that knows, so the adapter substitutes the real address.
    Broadcast,
    /// One specific device.
    Unicast(Ipv4Addr),
}

/// Describes a datagram that [`Transport::poll_recv`] wrote into the caller's
/// buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Which channel it arrived on.
    pub channel: Channel,
    /// Who sent it.
    pub source: Ipv4Addr,
    /// How many bytes were written to the front of the buffer.
    pub len: usize,
}

/// A non-blocking datagram endpoint owning all three Pro DJ Link channels.
///
/// # Implementing this
///
/// One implementation owns all three channels rather than one channel each.
/// An embedded adapter naturally holds a single socket set with three handles,
/// a replay adapter is a single cursor over a file, and a per-channel trait
/// would turn [`Session<T>`] into `Session<A, B, C>` with no way to express
/// fairness between them.
///
/// # Contract
///
/// * **`poll_recv` must not block.** Return `Ok(None)` when nothing is waiting.
/// * **`poll_recv` should round-robin.** With six players on the network the
///   status channel produces far more traffic than the other two; draining it
///   exclusively would starve the keepalives that keep devices alive in the
///   registry.
/// * **`send` must not block.** Dropping a datagram when the transmit queue is
///   full and returning `Ok(())` is correct behaviour — this protocol is
///   lossy by design and the next keepalive is 1.5 seconds away.
/// * **Oversize datagrams must be truncated, not rejected.** Report the
///   truncated length. An unrecognised jumbo frame from some unknown device
///   must not be able to stop the session.
/// * **Errors should be reserved for real failures.** A dead socket is an
///   error; a malformed packet is not, and is not your concern anyway.
///
/// [`Session<T>`]: crate::session::Session
pub trait Transport {
    /// How this adapter reports failure.
    ///
    /// Bounded by [`Debug`] rather than [`Display`] so an adapter on a target
    /// without formatting machinery is not forced to provide it.
    ///
    /// [`Debug`]: core::fmt::Debug
    /// [`Display`]: core::fmt::Display
    type Error: core::fmt::Debug;

    /// Sends `payload` on `channel`.
    fn send(
        &mut self,
        channel: Channel,
        dest: Destination,
        payload: &[u8],
    ) -> Result<(), Self::Error>;

    /// Takes the next waiting datagram, if there is one.
    ///
    /// Writes it to the front of `buf` and describes it in the return value.
    /// Returns `Ok(None)` immediately when nothing is waiting.
    fn poll_recv(&mut self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error>;

    /// This interface's IPv4 address, if the adapter can discover it.
    ///
    /// Used to fill in [`VcdjConfig`] automatically. Returning `None` is fine —
    /// it just means the caller has to supply the address, which a replay
    /// adapter or a pre-DHCP embedded stack cannot avoid anyway.
    ///
    /// [`VcdjConfig`]: crate::vcdj::VcdjConfig
    fn local_ipv4(&self) -> Option<Ipv4Addr> {
        None
    }

    /// This interface's hardware address, if the adapter can discover it.
    fn local_mac(&self) -> Option<MacAddr> {
        None
    }
}

impl<T: Transport + ?Sized> Transport for &mut T {
    type Error = T::Error;

    fn send(
        &mut self,
        channel: Channel,
        dest: Destination,
        payload: &[u8],
    ) -> Result<(), Self::Error> {
        (**self).send(channel, dest, payload)
    }

    fn poll_recv(&mut self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
        (**self).poll_recv(buf)
    }

    fn local_ipv4(&self) -> Option<Ipv4Addr> {
        (**self).local_ipv4()
    }

    fn local_mac(&self) -> Option<MacAddr> {
        (**self).local_mac()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_and_ports_agree_both_ways() {
        for channel in Channel::ALL {
            assert_eq!(Channel::from_port(channel.port()), Some(channel));
        }
        assert_eq!(Channel::from_port(1234), None);
    }

    #[test]
    fn ports_are_the_documented_ones() {
        assert_eq!(Channel::Announce.port(), 50000);
        assert_eq!(Channel::Beat.port(), 50001);
        assert_eq!(Channel::Status.port(), 50002);
    }

    #[test]
    fn announce_is_polled_first_so_liveness_is_never_starved() {
        assert_eq!(Channel::ALL[0], Channel::Announce);
    }
}
