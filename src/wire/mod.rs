//! The byte-level codec primitives every packet module is built from.
//!
//! Nothing here knows about Pro DJ Link semantics: it is bounds-checked
//! big-endian reads and writes over borrowed slices, plus the three scalar
//! types the protocol uses that are not plain integers.

mod cursor;
mod mac;
mod numeric;
mod string;

pub use cursor::{ReadCursor, WriteCursor};
pub use mac::MacAddr;
pub use numeric::{Bpm, Pitch};
pub use string::FixedStr;
