//! A [`Transport`] that replays a recorded capture.
//!
//! Useful for two things: debugging against traffic from a rig you no longer
//! have in front of you, and regression tests that assert on the exact event
//! stream a known capture produces.
//!
//! The capture format is one record per line, so it can be produced by a
//! three-line script and inspected with `grep`:
//!
//! ```text
//! 1234 announce 192.168.1.5 5173707431576d4a4f4c06...
//! 1250 beat     192.168.1.5 5173707431576d4a4f4c28...
//! ```
//!
//! Fields are milliseconds since the capture started, the channel name, the
//! source address, and the payload in hex. Blank lines and lines starting with
//! `#` are ignored.
//!
//! # Driving the clock
//!
//! A replay does not run in real time, so the timestamps in the file *are* the
//! clock. [`next_timestamp`] reports when the next datagram is due; feed that
//! straight to [`Session::poll`]:
//!
//! ```no_run
//! # use prolink::prelude::*;
//! # use prolink::adapter::replay::ReplayTransport;
//! # fn run(config: VcdjConfig) -> Result<(), Box<dyn std::error::Error>> {
//! let transport = ReplayTransport::from_file("capture.txt")?;
//! let mut session = Session::new(transport, config);
//!
//! while let Some(now) = session.transport().next_timestamp() {
//!     while let Some(event) = session.poll(now)? {
//!         println!("{now:?} {event:?}");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`next_timestamp`]: ReplayTransport::next_timestamp
//! [`Session::poll`]: crate::session::Session::poll

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::adapter::{Channel, Destination, Received, Transport};
use crate::time::Millis;
use crate::wire::MacAddr;

/// One recorded datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// When it arrived, relative to the start of the capture.
    pub at: Millis,
    /// Which channel it arrived on.
    pub channel: Channel,
    /// Who sent it.
    pub source: Ipv4Addr,
    /// The bytes.
    pub payload: Vec<u8>,
}

/// Why a capture file could not be read.
#[derive(Debug)]
pub enum ReplayError {
    /// A line was malformed.
    Malformed {
        /// Which line, counting from one.
        line: usize,
        /// What was wrong with it.
        reason: &'static str,
    },
    /// The file could not be opened or read.
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

impl core::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReplayError::Malformed { line, reason } => {
                write!(f, "capture line {line}: {reason}")
            }
            #[cfg(feature = "std")]
            ReplayError::Io(error) => write!(f, "reading capture: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReplayError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for ReplayError {
    fn from(error: std::io::Error) -> Self {
        ReplayError::Io(error)
    }
}

/// Replays recorded datagrams in timestamp order.
#[derive(Debug, Default)]
pub struct ReplayTransport {
    pending: VecDeque<Record>,
    /// Datagrams the session tried to send. Nothing is transmitted, but a
    /// replay test can still assert on what would have been.
    pub sent: Vec<(Channel, Destination, Vec<u8>)>,
    ip: Option<Ipv4Addr>,
    mac: Option<MacAddr>,
}

impl ReplayTransport {
    /// A transport over an already-parsed set of records.
    ///
    /// Records are sorted by timestamp, so a capture assembled out of order
    /// still replays correctly.
    pub fn new(mut records: Vec<Record>) -> Self {
        records.sort_by_key(|record| record.at);
        ReplayTransport {
            pending: records.into(),
            sent: Vec::new(),
            ip: None,
            mac: None,
        }
    }

    /// Parses a capture from text. See the module docs for the format.
    pub fn parse(text: &str) -> Result<Self, ReplayError> {
        let mut records = Vec::new();

        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut fields = line.split_whitespace();
            let mut next = |reason| {
                fields.next().ok_or(ReplayError::Malformed {
                    line: line_number,
                    reason,
                })
            };

            let at =
                next("missing timestamp")?
                    .parse::<u64>()
                    .map_err(|_| ReplayError::Malformed {
                        line: line_number,
                        reason: "timestamp is not a number",
                    })?;

            let channel = match next("missing channel")? {
                "announce" | "50000" => Channel::Announce,
                "beat" | "50001" => Channel::Beat,
                "status" | "50002" => Channel::Status,
                _ => {
                    return Err(ReplayError::Malformed {
                        line: line_number,
                        reason: "channel must be announce, beat or status",
                    })
                }
            };

            let source =
                next("missing source address")?
                    .parse()
                    .map_err(|_| ReplayError::Malformed {
                        line: line_number,
                        reason: "source is not an IPv4 address",
                    })?;

            let payload = decode_hex(next("missing payload")?).ok_or(ReplayError::Malformed {
                line: line_number,
                reason: "payload is not valid hex",
            })?;

            records.push(Record {
                at: Millis(at),
                channel,
                source,
                payload,
            });
        }

        Ok(Self::new(records))
    }

    /// Reads and parses a capture file.
    #[cfg(feature = "std")]
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, ReplayError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// When the next datagram is due, or `None` once the capture is exhausted.
    ///
    /// This is the replay's clock. Feed it to
    /// [`Session::poll`](crate::session::Session::poll).
    pub fn next_timestamp(&self) -> Option<Millis> {
        self.pending.front().map(|record| record.at)
    }

    /// How many datagrams are left.
    pub fn remaining(&self) -> usize {
        self.pending.len()
    }

    /// Whether the capture has been fully replayed.
    pub fn is_finished(&self) -> bool {
        self.pending.is_empty()
    }

    /// Sets the identity to report, since a capture does not record ours.
    pub fn with_identity(mut self, ip: Ipv4Addr, mac: MacAddr) -> Self {
        self.ip = Some(ip);
        self.mac = Some(mac);
        self
    }
}

impl Transport for ReplayTransport {
    /// A replay cannot fail: the file was fully parsed up front.
    type Error = core::convert::Infallible;

    fn send(
        &mut self,
        channel: Channel,
        dest: Destination,
        payload: &[u8],
    ) -> Result<(), Self::Error> {
        self.sent.push((channel, dest, payload.to_vec()));
        Ok(())
    }

    fn poll_recv(&mut self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
        let Some(record) = self.pending.pop_front() else {
            return Ok(None);
        };
        let len = record.payload.len().min(buf.len());
        buf[..len].copy_from_slice(&record.payload[..len]);
        Ok(Some(Received {
            channel: record.channel,
            source: record.source,
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

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

/// Renders records back to the capture format, for building fixtures.
pub fn to_text(records: &[Record]) -> String {
    use core::fmt::Write;

    let mut out = String::new();
    for record in records {
        let channel = match record.channel {
            Channel::Announce => "announce",
            Channel::Beat => "beat",
            Channel::Status => "status",
        };
        let _ = write!(out, "{} {} {} ", record.at.0, channel, record.source);
        for byte in &record.payload {
            let _ = write!(out, "{byte:02x}");
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPTURE: &str = "\
# a comment, and a blank line follow

100 announce 192.168.1.5 010203
250 beat     192.168.1.6 aabb
50  status   192.168.1.7 ff
";

    #[test]
    fn a_capture_parses_and_sorts_by_time() {
        let transport = ReplayTransport::parse(CAPTURE).unwrap();
        assert_eq!(transport.remaining(), 3);
        // The status record was last in the file but first in time.
        assert_eq!(transport.next_timestamp(), Some(Millis(50)));
    }

    #[test]
    fn records_come_back_in_time_order_with_their_channel() {
        let mut transport = ReplayTransport::parse(CAPTURE).unwrap();
        let mut buf = [0u8; 16];

        let first = transport.poll_recv(&mut buf).unwrap().unwrap();
        assert_eq!(first.channel, Channel::Status);
        assert_eq!(&buf[..first.len], &[0xff]);

        let second = transport.poll_recv(&mut buf).unwrap().unwrap();
        assert_eq!(second.channel, Channel::Announce);
        assert_eq!(&buf[..second.len], &[1, 2, 3]);

        let third = transport.poll_recv(&mut buf).unwrap().unwrap();
        assert_eq!(third.channel, Channel::Beat);
        assert_eq!(third.source, Ipv4Addr::new(192, 168, 1, 6));

        assert!(transport.poll_recv(&mut buf).unwrap().is_none());
        assert!(transport.is_finished());
    }

    #[test]
    fn port_numbers_work_as_channel_names() {
        let transport = ReplayTransport::parse("0 50002 10.0.0.1 ff").unwrap();
        assert_eq!(transport.pending[0].channel, Channel::Status);
    }

    #[test]
    fn malformed_lines_say_which_line_and_why() {
        let cases = [
            ("0 announce 10.0.0.1", "missing payload"),
            ("x announce 10.0.0.1 ff", "timestamp is not a number"),
            (
                "0 sideband 10.0.0.1 ff",
                "channel must be announce, beat or status",
            ),
            ("0 announce not-an-ip ff", "source is not an IPv4 address"),
            ("0 announce 10.0.0.1 fff", "payload is not valid hex"),
            ("0 announce 10.0.0.1 zz", "payload is not valid hex"),
        ];
        for (input, expected) in cases {
            match ReplayTransport::parse(input) {
                Err(ReplayError::Malformed { line, reason }) => {
                    assert_eq!(line, 1, "for {input:?}");
                    assert_eq!(reason, expected, "for {input:?}");
                }
                other => panic!("expected a parse error for {input:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn rendering_and_parsing_are_inverses() {
        let transport = ReplayTransport::parse(CAPTURE).unwrap();
        let records: Vec<Record> = transport.pending.iter().cloned().collect();

        let text = to_text(&records);
        let reparsed = ReplayTransport::parse(&text).unwrap();
        let round_tripped: Vec<Record> = reparsed.pending.iter().cloned().collect();

        assert_eq!(records, round_tripped);
    }

    #[test]
    fn sends_are_recorded_rather_than_transmitted() {
        let mut transport = ReplayTransport::parse("").unwrap();
        transport
            .send(Channel::Announce, Destination::Broadcast, &[1, 2, 3])
            .unwrap();
        assert_eq!(
            transport.sent,
            [(
                Channel::Announce,
                Destination::Broadcast,
                alloc::vec![1, 2, 3]
            )]
        );
    }
}
