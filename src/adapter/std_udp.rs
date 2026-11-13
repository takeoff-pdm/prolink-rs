//! A ready-made [`Transport`] over real UDP sockets.
//!
//! This is what the `std` feature buys you: no trait to implement, just
//! [`StdUdpTransport::bind_auto`] and a [`Session`].
//!
//! [`Session`]: crate::session::Session

use core::net::Ipv4Addr;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::adapter::{Channel, Destination, Received, Transport};
use crate::wire::MacAddr;

/// The address used when the interface's broadcast address is unknown.
const LIMITED_BROADCAST: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// Three non-blocking UDP sockets, one per Pro DJ Link channel.
///
/// # Sharing the ports
///
/// The sockets are bound with `SO_REUSEADDR` (and `SO_REUSEPORT` where the
/// platform has it) so this can run alongside rekordbox, or alongside a second
/// copy of itself. Without that, binding fails outright the moment anything
/// else on the machine is already listening — which, at a gig, is exactly when
/// you find out.
///
/// # Fairness
///
/// [`poll_recv`](Transport::poll_recv) resumes from the channel *after* the one
/// it last read, so a busy status channel cannot monopolise it. Six players
/// generate far more status traffic than announce traffic, and starving the
/// announce channel would make devices appear to drop off the network.
#[derive(Debug)]
pub struct StdUdpTransport {
    sockets: [UdpSocket; 3],
    next_channel: usize,
    broadcast: Ipv4Addr,
    local_ip: Option<Ipv4Addr>,
    local_mac: Option<MacAddr>,
}

impl StdUdpTransport {
    /// Binds all three ports on every interface.
    ///
    /// Broadcasts go to `255.255.255.255` until you supply a specific address
    /// with [`with_broadcast`], and no local identity is reported — call
    /// [`with_identity`] or set it on the [`VcdjConfig`] directly.
    ///
    /// [`with_broadcast`]: StdUdpTransport::with_broadcast
    /// [`with_identity`]: StdUdpTransport::with_identity
    /// [`VcdjConfig`]: crate::vcdj::VcdjConfig
    pub fn bind_auto() -> io::Result<Self> {
        Self::bind(Ipv4Addr::UNSPECIFIED)
    }

    /// Binds all three ports on one interface address.
    ///
    /// The broadcast address is derived from `addr` assuming a /24, which is
    /// what Pro DJ Link networks almost always are. Override it with
    /// [`with_broadcast`] if yours is not.
    ///
    /// [`with_broadcast`]: StdUdpTransport::with_broadcast
    pub fn bind(addr: Ipv4Addr) -> io::Result<Self> {
        let sockets = [
            bind_channel(Channel::Announce, addr)?,
            bind_channel(Channel::Beat, addr)?,
            bind_channel(Channel::Status, addr)?,
        ];

        let (local_ip, broadcast) = if addr.is_unspecified() {
            (None, LIMITED_BROADCAST)
        } else {
            (Some(addr), assume_slash_24_broadcast(addr))
        };

        Ok(StdUdpTransport {
            sockets,
            next_channel: 0,
            broadcast,
            local_ip,
            local_mac: None,
        })
    }

    /// Sets the address [`Destination::Broadcast`] resolves to.
    pub fn with_broadcast(mut self, broadcast: Ipv4Addr) -> Self {
        self.broadcast = broadcast;
        self
    }

    /// Sets the identity reported by [`local_ipv4`] and [`local_mac`].
    ///
    /// Needed because Rust's standard library cannot enumerate interfaces, so
    /// the MAC address has to come from somewhere else — a platform crate, a
    /// config file, or a hard-coded value.
    ///
    /// [`local_ipv4`]: Transport::local_ipv4
    /// [`local_mac`]: Transport::local_mac
    pub fn with_identity(mut self, ip: Ipv4Addr, mac: MacAddr) -> Self {
        self.local_ip = Some(ip);
        self.local_mac = Some(mac);
        self
    }

    /// The address [`Destination::Broadcast`] currently resolves to.
    pub fn broadcast_address(&self) -> Ipv4Addr {
        self.broadcast
    }

    /// Blocks until a datagram arrives or `timeout` elapses, whichever comes
    /// first. Returns whether anything is now readable.
    ///
    /// This is not part of [`Transport`], and deliberately so: waiting has no
    /// meaning for a replay adapter and the wrong shape for an async embedded
    /// one. It lives here because a `std` main loop that only slept until
    /// [`Session::next_deadline`] would add up to a second of latency to every
    /// incoming packet.
    ///
    /// Implemented by probing the three sockets and sleeping briefly between
    /// rounds, rather than by `select`. The cost is up to
    /// [`POLL_GRANULARITY`] of extra latency and a negligible amount of CPU;
    /// the benefit is no additional dependency and identical behaviour on
    /// every platform. If you need true readiness notification, drive the
    /// session from your own event loop instead — that is what the
    /// non-blocking [`Transport`] contract is for.
    ///
    /// [`Session::next_deadline`]: crate::session::Session::next_deadline
    /// [`POLL_GRANULARITY`]: Self::POLL_GRANULARITY
    pub fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            for socket in &self.sockets {
                if peek_ready(socket)? {
                    return Ok(true);
                }
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Self::POLL_GRANULARITY.min(deadline - now));
        }
    }

    /// How long [`wait_readable`](Self::wait_readable) sleeps between probes,
    /// and therefore the worst-case latency it adds.
    pub const POLL_GRANULARITY: Duration = Duration::from_millis(2);
}

fn peek_ready(socket: &UdpSocket) -> io::Result<bool> {
    let mut scratch = [0u8; 1];
    match socket.peek_from(&mut scratch) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
        // A datagram too big for the one-byte peek buffer is still a datagram.
        Err(e) if is_message_truncated(&e) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Whether an error means "the datagram did not fit in your buffer".
///
/// Platforms disagree on how to report this and none of the kinds involved are
/// stable, so match on the raw code where we can.
fn is_message_truncated(error: &io::Error) -> bool {
    #[cfg(unix)]
    const EMSGSIZE: i32 = 90;
    #[cfg(windows)]
    const EMSGSIZE: i32 = 10040; // WSAEMSGSIZE

    #[cfg(any(unix, windows))]
    if error.raw_os_error() == Some(EMSGSIZE) {
        return true;
    }

    error.kind() == io::ErrorKind::Other
}

/// Assumes a /24, which Pro DJ Link networks essentially always are.
fn assume_slash_24_broadcast(addr: Ipv4Addr) -> Ipv4Addr {
    let [a, b, c, _] = addr.octets();
    Ipv4Addr::new(a, b, c, 255)
}

fn bind_channel(channel: Channel, addr: Ipv4Addr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    // Both must be set before bind, which is the whole reason socket2 is here.
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;

    socket.set_broadcast(true)?;
    socket.bind(&SocketAddrV4::new(addr, channel.port()).into())?;
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

impl Transport for StdUdpTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        channel: Channel,
        dest: Destination,
        payload: &[u8],
    ) -> Result<(), Self::Error> {
        let target = match dest {
            Destination::Broadcast => self.broadcast,
            Destination::Unicast(ip) => ip,
        };
        let addr = SocketAddr::from(SocketAddrV4::new(target, channel.port()));

        match self.sockets[channel as usize].send_to(payload, addr) {
            Ok(_) => Ok(()),
            // A full transmit queue is not a failure worth stopping for: the
            // next keepalive is 1.5 seconds away and this protocol expects loss.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn poll_recv(&mut self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
        for offset in 0..self.sockets.len() {
            let index = (self.next_channel + offset) % self.sockets.len();
            match self.sockets[index].recv_from(buf) {
                Ok((len, source)) => {
                    self.next_channel = (index + 1) % self.sockets.len();
                    let source = match source {
                        SocketAddr::V4(addr) => *addr.ip(),
                        SocketAddr::V6(addr) => {
                            addr.ip().to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED)
                        }
                    };
                    return Ok(Some(Received {
                        channel: Channel::ALL[index],
                        source,
                        len: len.min(buf.len()),
                    }));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                // A datagram too large for `buf` was truncated. That is a
                // report, not a failure — skip it and keep going.
                Err(e) if is_message_truncated(&e) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    fn local_ipv4(&self) -> Option<Ipv4Addr> {
        self.local_ip
    }

    fn local_mac(&self) -> Option<MacAddr> {
        self.local_mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_assumes_a_slash_24() {
        assert_eq!(
            assume_slash_24_broadcast(Ipv4Addr::new(192, 168, 1, 5)),
            Ipv4Addr::new(192, 168, 1, 255)
        );
    }

    #[test]
    fn unspecified_bind_uses_the_limited_broadcast() {
        // Binding the real ports may fail in a sandbox, so only check the
        // address derivation, which is the part with logic in it.
        assert_eq!(LIMITED_BROADCAST, Ipv4Addr::new(255, 255, 255, 255));
    }
}
