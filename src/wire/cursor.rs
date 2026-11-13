//! Bounds-checked big-endian cursors over borrowed slices.
//!
//! Every multi-byte field in Pro DJ Link is big-endian, so that is the only
//! byte order these offer.

use core::net::Ipv4Addr;

use crate::error::CodecError;
use crate::wire::{Bpm, FixedStr, MacAddr, Pitch};

/// Reads fields sequentially out of a packet.
///
/// Every read is bounds-checked and returns [`CodecError::UnexpectedEof`]
/// rather than panicking, because the input is untrusted network traffic.
#[derive(Debug, Clone)]
pub struct ReadCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ReadCursor<'a> {
    /// Starts reading at the beginning of `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        ReadCursor { data, offset: 0 }
    }

    /// Bytes not yet consumed.
    pub const fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    /// How far in the cursor has read.
    pub const fn position(&self) -> usize {
        self.offset
    }

    /// Whether every byte has been consumed.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < len {
            return Err(CodecError::UnexpectedEof {
                needed: len,
                remaining: self.remaining(),
            });
        }
        let slice = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    /// Discards `len` bytes.
    pub fn skip(&mut self, len: usize) -> Result<(), CodecError> {
        self.take(len).map(|_| ())
    }

    /// Moves the cursor to an absolute offset from the start of the packet.
    ///
    /// The status packet is a sparse structure of fields at documented
    /// offsets with large uncharted gaps between them, so seeking is clearer
    /// there than counting out skips.
    pub fn seek(&mut self, offset: usize) -> Result<(), CodecError> {
        if offset > self.data.len() {
            return Err(CodecError::UnexpectedEof {
                needed: offset,
                remaining: self.data.len(),
            });
        }
        self.offset = offset;
        Ok(())
    }

    /// Borrows the next `len` bytes.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        self.take(len)
    }

    /// Borrows everything left.
    pub fn read_rest(&mut self) -> &'a [u8] {
        let rest = &self.data[self.offset..];
        self.offset = self.data.len();
        rest
    }

    /// Borrows the next `N` bytes as an array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    /// Reads one byte.
    pub fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    /// Reads a big-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    /// Reads a big-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    /// Reads a big-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    /// Reads four octets as an IPv4 address.
    pub fn read_ipv4(&mut self) -> Result<Ipv4Addr, CodecError> {
        Ok(Ipv4Addr::from(self.read_array::<4>()?))
    }

    /// Reads six octets as a MAC address.
    pub fn read_mac(&mut self) -> Result<MacAddr, CodecError> {
        Ok(MacAddr(self.read_array::<6>()?))
    }

    /// Reads a 32-bit fixed-point pitch.
    pub fn read_pitch(&mut self) -> Result<Pitch, CodecError> {
        Ok(Pitch::from_raw(self.read_u32()?))
    }

    /// Reads a 16-bit tempo, mapping the sentinel to `None`.
    pub fn read_bpm(&mut self) -> Result<Option<Bpm>, CodecError> {
        Ok(Bpm::from_raw(self.read_u16()?))
    }

    /// Reads a NUL-padded ASCII field of exactly `len` bytes.
    pub fn read_ascii<const N: usize>(
        &mut self,
        len: usize,
        field: &'static str,
    ) -> Result<FixedStr<N>, CodecError> {
        FixedStr::from_ascii_padded(self.take(len)?, field)
    }

    /// Reads a NUL-padded big-endian UTF-16 field of exactly `len` *bytes*.
    pub fn read_utf16<const N: usize>(
        &mut self,
        len: usize,
        field: &'static str,
    ) -> Result<FixedStr<N>, CodecError> {
        FixedStr::from_utf16_padded(self.take(len)?, field)
    }

    /// Reads the ten-byte magic prefix, failing if it is not `Qspt1WmJOL`.
    pub fn read_magic(&mut self) -> Result<(), CodecError> {
        if self.read_array::<10>()? == crate::constants::MAGIC {
            Ok(())
        } else {
            Err(CodecError::InvalidMagic)
        }
    }
}

/// Writes fields sequentially into a caller-supplied buffer.
///
/// The buffer never grows: encoding into a fixed `[u8; MAX_PACKET_LEN]` is what
/// keeps the send path free of allocation. Running out of room is
/// [`CodecError::BufferOverflow`].
#[derive(Debug)]
pub struct WriteCursor<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> WriteCursor<'a> {
    /// Starts writing at the beginning of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        WriteCursor { buf, offset: 0 }
    }

    /// Bytes written so far.
    pub const fn position(&self) -> usize {
        self.offset
    }

    /// Bytes still available.
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.offset
    }

    fn take(&mut self, len: usize) -> Result<&mut [u8], CodecError> {
        if self.remaining() < len {
            return Err(CodecError::BufferOverflow {
                needed: self.offset + len,
                capacity: self.buf.len(),
            });
        }
        let slice = &mut self.buf[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    /// Writes raw bytes.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        self.take(bytes.len())?.copy_from_slice(bytes);
        Ok(())
    }

    /// Writes `len` zero bytes.
    pub fn write_zeros(&mut self, len: usize) -> Result<(), CodecError> {
        self.take(len)?.fill(0);
        Ok(())
    }

    /// Writes one byte.
    pub fn write_u8(&mut self, value: u8) -> Result<(), CodecError> {
        self.write_bytes(&[value])
    }

    /// Writes a big-endian `u16`.
    pub fn write_u16(&mut self, value: u16) -> Result<(), CodecError> {
        self.write_bytes(&value.to_be_bytes())
    }

    /// Writes a big-endian `u32`.
    pub fn write_u32(&mut self, value: u32) -> Result<(), CodecError> {
        self.write_bytes(&value.to_be_bytes())
    }

    /// Writes a big-endian `u64`.
    pub fn write_u64(&mut self, value: u64) -> Result<(), CodecError> {
        self.write_bytes(&value.to_be_bytes())
    }

    /// Writes an IPv4 address as four octets.
    pub fn write_ipv4(&mut self, addr: Ipv4Addr) -> Result<(), CodecError> {
        self.write_bytes(&addr.octets())
    }

    /// Writes a MAC address as six octets.
    pub fn write_mac(&mut self, mac: MacAddr) -> Result<(), CodecError> {
        self.write_bytes(&mac.0)
    }

    /// Writes a 32-bit fixed-point pitch.
    pub fn write_pitch(&mut self, pitch: Pitch) -> Result<(), CodecError> {
        self.write_u32(pitch.to_raw())
    }

    /// Writes a 16-bit tempo, using the sentinel for `None`.
    pub fn write_bpm(&mut self, bpm: Option<Bpm>) -> Result<(), CodecError> {
        self.write_u16(crate::wire::numeric::bpm_to_raw(bpm))
    }

    /// Writes a NUL-padded ASCII field occupying exactly `len` bytes.
    pub fn write_ascii<const N: usize>(
        &mut self,
        value: &FixedStr<N>,
        len: usize,
        field: &'static str,
    ) -> Result<(), CodecError> {
        let slot = self.take(len)?;
        value.write_ascii_padded(slot, field)
    }

    /// Writes a NUL-padded big-endian UTF-16 field occupying exactly `len`
    /// *bytes*.
    pub fn write_utf16<const N: usize>(
        &mut self,
        value: &FixedStr<N>,
        len: usize,
        field: &'static str,
    ) -> Result<(), CodecError> {
        let slot = self.take(len)?;
        value.write_utf16_padded(slot, field)
    }

    /// Writes the ten-byte magic prefix.
    pub fn write_magic(&mut self) -> Result<(), CodecError> {
        self.write_bytes(&crate::constants::MAGIC)
    }

    /// Overwrites a big-endian `u16` at an already-written offset.
    ///
    /// Several packets carry a length field ahead of the data it measures;
    /// this lets the encoder reserve the slot and fill it in once the real
    /// length is known.
    pub fn patch_u16(&mut self, offset: usize, value: u16) -> Result<(), CodecError> {
        if offset + 2 > self.offset {
            return Err(CodecError::BufferOverflow {
                needed: offset + 2,
                capacity: self.offset,
            });
        }
        self.buf[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Pads with zeros out to an absolute offset.
    ///
    /// The status packet is mostly uncharted space between known fields; this
    /// is how an encoder jumps to the next one it knows about.
    pub fn pad_to(&mut self, offset: usize) -> Result<(), CodecError> {
        if offset < self.offset {
            return Err(CodecError::InvalidField {
                field: "cursor.pad_to",
                reason: "target offset is behind the cursor",
            });
        }
        self.write_zeros(offset - self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian() {
        let mut cursor = ReadCursor::new(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(cursor.read_u8().unwrap(), 0x01);
        assert_eq!(cursor.read_u16().unwrap(), 0x0203);
        assert_eq!(cursor.remaining(), 2);
    }

    #[test]
    fn short_reads_report_eof_rather_than_panicking() {
        let mut cursor = ReadCursor::new(&[0x01, 0x02]);
        assert_eq!(
            cursor.read_u32(),
            Err(CodecError::UnexpectedEof {
                needed: 4,
                remaining: 2
            })
        );
        // The failed read must not have consumed anything.
        assert_eq!(cursor.remaining(), 2);
    }

    #[test]
    fn magic_is_checked() {
        assert_eq!(ReadCursor::new(b"Qspt1WmJOL\x06").read_magic(), Ok(()));
        assert_eq!(
            ReadCursor::new(b"NotTheMagi\x06").read_magic(),
            Err(CodecError::InvalidMagic)
        );
    }

    #[test]
    fn writes_big_endian_and_refuses_to_overflow() {
        let mut buf = [0u8; 4];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u16(0x0102).unwrap();
        cursor.write_u8(0x03).unwrap();
        assert_eq!(cursor.position(), 3);
        assert_eq!(
            cursor.write_u16(0x0405),
            Err(CodecError::BufferOverflow {
                needed: 5,
                capacity: 4
            })
        );
    }

    #[test]
    fn patch_rewrites_an_earlier_field() {
        let mut buf = [0u8; 6];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u16(0).unwrap();
        cursor.write_u32(0xdeadbeef).unwrap();
        cursor.patch_u16(0, 0x1234).unwrap();
        assert_eq!(buf, [0x12, 0x34, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn patch_beyond_written_data_is_rejected() {
        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u16(0).unwrap();
        assert!(cursor.patch_u16(4, 1).is_err());
    }

    #[test]
    fn pad_to_refuses_to_move_backwards() {
        let mut buf = [0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor.write_u32(0).unwrap();
        assert!(cursor.pad_to(2).is_err());
        cursor.pad_to(6).unwrap();
        assert_eq!(cursor.position(), 6);
    }

    #[test]
    fn seek_cannot_leave_the_packet() {
        let mut cursor = ReadCursor::new(&[0u8; 4]);
        assert!(cursor.seek(4).is_ok());
        assert!(cursor.seek(5).is_err());
    }
}
