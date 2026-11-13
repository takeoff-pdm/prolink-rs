//! An in-memory [`Transport`] for tests.
//!
//! Available under the `testing` feature so that code built on this library can
//! be tested the same way the library tests itself: hand a session a scripted
//! inbox, drive it, and assert on what came out.
//!
//! There is deliberately no mock clock to go with it. [`Session::poll`] takes
//! the time as an argument, so a test that wants to be at `t = 1500 ms` simply
//! says so.
//!
//! [`Transport`]: crate::adapter::Transport
//! [`Session::poll`]: crate::session::Session::poll

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::adapter::{Channel, Destination, Received, Transport};
use crate::wire::MacAddr;

/// The failure a [`MockTransport`] can be told to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockError;

/// A datagram a [`MockTransport`] sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentDatagram {
    /// Which channel it went out on.
    pub channel: Channel,
    /// Where it was addressed.
    pub dest: Destination,
    /// The bytes.
    pub payload: Vec<u8>,
}

/// A [`Transport`] backed by two queues instead of a network.
///
/// ```
/// # use prolink::adapter::{Channel, Destination, MockTransport, Transport};
/// # use core::net::Ipv4Addr;
/// let mut transport = MockTransport::new();
/// transport.push(Channel::Announce, Ipv4Addr::new(192, 168, 1, 5), &[1, 2, 3]);
///
/// let mut buf = [0u8; 16];
/// let received = transport.poll_recv(&mut buf).unwrap().unwrap();
/// assert_eq!(&buf[..received.len], &[1, 2, 3]);
/// assert!(transport.poll_recv(&mut buf).unwrap().is_none());
/// ```
#[derive(Debug, Default)]
pub struct MockTransport {
    inbox: VecDeque<(Channel, Ipv4Addr, Vec<u8>)>,
    /// Every datagram the session has sent, oldest first.
    pub sent: Vec<SentDatagram>,
    /// When set, the next [`send`](Transport::send) fails and clears this.
    pub fail_next_send: bool,
    /// When set, the next [`poll_recv`](Transport::poll_recv) fails and clears
    /// this.
    pub fail_next_recv: bool,
    ip: Option<Ipv4Addr>,
    mac: Option<MacAddr>,
}

impl MockTransport {
    /// An empty transport that reports no local identity.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty transport that reports the given identity, as a real adapter
    /// on a configured interface would.
    pub fn with_identity(ip: Ipv4Addr, mac: MacAddr) -> Self {
        MockTransport {
            ip: Some(ip),
            mac: Some(mac),
            ..Self::default()
        }
    }

    /// Queues a datagram for the session to receive.
    pub fn push(&mut self, channel: Channel, source: Ipv4Addr, payload: &[u8]) {
        self.inbox.push_back((channel, source, payload.to_vec()));
    }

    /// Discards the record of what has been sent.
    pub fn clear_sent(&mut self) {
        self.sent.clear();
    }

    /// The datagrams sent on `channel`, oldest first.
    pub fn sent_on(&self, channel: Channel) -> impl Iterator<Item = &SentDatagram> {
        self.sent.iter().filter(move |d| d.channel == channel)
    }

    /// The most recently sent datagram.
    pub fn last_sent(&self) -> Option<&SentDatagram> {
        self.sent.last()
    }

    /// How many datagrams are still waiting to be received.
    pub fn pending(&self) -> usize {
        self.inbox.len()
    }
}

impl Transport for MockTransport {
    type Error = MockError;

    fn send(
        &mut self,
        channel: Channel,
        dest: Destination,
        payload: &[u8],
    ) -> Result<(), Self::Error> {
        if core::mem::take(&mut self.fail_next_send) {
            return Err(MockError);
        }
        self.sent.push(SentDatagram {
            channel,
            dest,
            payload: payload.to_vec(),
        });
        Ok(())
    }

    fn poll_recv(&mut self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
        if core::mem::take(&mut self.fail_next_recv) {
            return Err(MockError);
        }
        let Some((channel, source, payload)) = self.inbox.pop_front() else {
            return Ok(None);
        };
        // Truncate rather than erroring, exactly as a real socket does.
        let len = payload.len().min(buf.len());
        buf[..len].copy_from_slice(&payload[..len]);
        Ok(Some(Received {
            channel,
            source,
            len,
        }))
    }

    fn local_ipv4(&self) -> Option<Ipv4Addr> {
        self.ip
    }

    fn local_mac(&self) -> Option<MacAddr> {
        self.mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagrams_come_back_in_order() {
        let mut transport = MockTransport::new();
        let src = Ipv4Addr::new(192, 168, 1, 5);
        transport.push(Channel::Announce, src, &[1]);
        transport.push(Channel::Beat, src, &[2]);

        let mut buf = [0u8; 8];
        assert_eq!(
            transport.poll_recv(&mut buf).unwrap().unwrap().channel,
            Channel::Announce
        );
        assert_eq!(
            transport.poll_recv(&mut buf).unwrap().unwrap().channel,
            Channel::Beat
        );
        assert!(transport.poll_recv(&mut buf).unwrap().is_none());
    }

    #[test]
    fn an_oversize_datagram_is_truncated_not_rejected() {
        let mut transport = MockTransport::new();
        transport.push(Channel::Status, Ipv4Addr::LOCALHOST, &[0xaa; 32]);

        let mut buf = [0u8; 8];
        let received = transport.poll_recv(&mut buf).unwrap().unwrap();
        assert_eq!(received.len, 8);
    }

    #[test]
    fn injected_failures_fire_once() {
        let mut transport = MockTransport::new();
        transport.fail_next_send = true;
        assert!(transport
            .send(Channel::Announce, Destination::Broadcast, &[1])
            .is_err());
        assert!(transport
            .send(Channel::Announce, Destination::Broadcast, &[1])
            .is_ok());
        assert_eq!(transport.sent.len(), 1);
    }
}
