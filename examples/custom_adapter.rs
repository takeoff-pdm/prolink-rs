//! Implementing [`Transport`] yourself.
//!
//! This is the whole point of the library's design: the adapter below is
//! written against `core` only — no `std`, no allocator, no async runtime —
//! and yet the [`Session`] driving it is exactly the same code the `std`
//! examples use. The same adapter shape works over smoltcp, embassy-net, or a
//! raw Ethernet driver.
//!
//! It is an example rather than a test so you can read it top to bottom, and
//! it runs so you can see the negotiation actually happen:
//!
//! ```console
//! $ cargo run --example custom_adapter
//! ```

use core::net::Ipv4Addr;

use prolink::adapter::{Channel, Destination, Received, Transport};
use prolink::prelude::*;

/// A transport over two fixed-size queues.
///
/// Stands in for whatever your hardware actually offers. Note what is *not*
/// here: no `Vec`, no `Box`, no `dyn`, no `async`. Everything is inline
/// storage of a known size.
struct RingTransport {
    /// Datagrams waiting to be received.
    inbox: [Option<Datagram>; 8],
    inbox_head: usize,
    inbox_len: usize,
    /// Datagrams we have "transmitted".
    outbox_count: usize,
    ip: Ipv4Addr,
    mac: MacAddr,
}

#[derive(Clone, Copy)]
struct Datagram {
    channel: Channel,
    source: Ipv4Addr,
    bytes: [u8; MAX_PACKET_LEN],
    len: usize,
}

/// What can go wrong. On real hardware this would wrap your driver's error.
#[derive(Debug)]
struct LinkDown;

impl RingTransport {
    fn new(ip: Ipv4Addr, mac: MacAddr) -> Self {
        RingTransport {
            inbox: [None; 8],
            inbox_head: 0,
            inbox_len: 0,
            outbox_count: 0,
            ip,
            mac,
        }
    }

    /// Pretends a datagram arrived from the network.
    fn deliver(&mut self, channel: Channel, source: Ipv4Addr, payload: &[u8]) {
        if self.inbox_len == self.inbox.len() {
            return; // a real driver would drop it too
        }
        let mut bytes = [0u8; MAX_PACKET_LEN];
        let len = payload.len().min(bytes.len());
        bytes[..len].copy_from_slice(&payload[..len]);

        let index = (self.inbox_head + self.inbox_len) % self.inbox.len();
        self.inbox[index] = Some(Datagram {
            channel,
            source,
            bytes,
            len,
        });
        self.inbox_len += 1;
    }
}

impl Transport for RingTransport {
    type Error = LinkDown;

    fn send(
        &mut self,
        channel: Channel,
        dest: Destination,
        payload: &[u8],
    ) -> Result<(), Self::Error> {
        // On real hardware: hand `payload` to the UDP socket for
        // `channel.port()`, resolving `Destination::Broadcast` to whatever
        // your interface's broadcast address is.
        self.outbox_count += 1;
        println!(
            "  tx {:>8} → {:<24} {} bytes",
            format!("{channel:?}"),
            match dest {
                Destination::Broadcast => "broadcast".to_string(),
                Destination::Unicast(ip) => ip.to_string(),
            },
            payload.len(),
        );
        Ok(())
    }

    fn poll_recv(&mut self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
        // Must never block: return `Ok(None)` when nothing is waiting.
        if self.inbox_len == 0 {
            return Ok(None);
        }
        let datagram = self.inbox[self.inbox_head].take().expect("len > 0");
        self.inbox_head = (self.inbox_head + 1) % self.inbox.len();
        self.inbox_len -= 1;

        // Truncate rather than erroring if the caller's buffer is smaller.
        let len = datagram.len.min(buf.len());
        buf[..len].copy_from_slice(&datagram.bytes[..len]);

        Ok(Some(Received {
            channel: datagram.channel,
            source: datagram.source,
            len,
        }))
    }

    fn local_ipv4(&self) -> Option<Ipv4Addr> {
        Some(self.ip)
    }

    fn local_mac(&self) -> Option<MacAddr> {
        Some(self.mac)
    }
}

fn main() {
    let ip = Ipv4Addr::new(192, 168, 1, 200);
    let mac = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);

    let mut session = Session::new(
        RingTransport::new(ip, mac),
        VcdjConfig::new("Embedded CDJ").with_identity(ip, mac),
    );

    session.start(Millis(0)).expect("identity is configured");

    // Drive it forward. On real hardware `now` comes from your monotonic timer
    // and the loop sleeps until `session.next_deadline(now)`.
    let mut now = 0u64;
    while now <= 5_000 {
        while let Some(event) = session.poll(Millis(now)).expect("the link stays up") {
            println!("  ev {event:?}");
        }

        // At two seconds, pretend a CDJ shows up on the network.
        if now == 2_000 {
            println!("\n-- a CDJ appears --");
            let keepalive = build_keepalive(2);
            session.transport_mut().deliver(
                Channel::Announce,
                Ipv4Addr::new(192, 168, 1, 5),
                &keepalive.0[..keepalive.1],
            );
        }

        now += 100;
    }

    println!("\nfinal state: {:?}", session.state());
    println!("player number: {:?}", session.player_number());
    for device in session.devices() {
        println!("device: player {} — {}", device.player_number, device.model);
    }
}

/// Builds a keepalive as a real player would send it.
fn build_keepalive(player_number: u8) -> ([u8; MAX_PACKET_LEN], usize) {
    use prolink::packet::keepalive::{KeepAliveBody, KeepAlivePacket};
    use prolink::packet::StatusFeatureFlags;

    let packet = KeepAlivePacket::new(
        FixedStr::new("CDJ-3000").unwrap(),
        DeviceType::Cdj,
        KeepAliveBody::Status {
            player_number,
            related_player_number: player_number,
            mac: MacAddr([0x74, 0x5e, 0x1c, 0x0a, 0xbb, 0x03]),
            ip: Ipv4Addr::new(192, 168, 1, 5),
            device_count: 2,
            flags: StatusFeatureFlags::IS_PLAYER_OR_MIXER,
            extra_flags: 0,
        },
    );

    let mut buf = [0u8; MAX_PACKET_LEN];
    let len = packet.encode(&mut buf).expect("a keepalive always fits");
    (buf, len)
}
