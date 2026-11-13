//! Machinery for enums that survive meeting a value they have never seen.

/// Defines a `u8`-backed enum with a catch-all `Unknown` variant.
///
/// Rejecting an unrecognised discriminant would mean a firmware update that
/// adds one new device type makes every packet from that device undecodable.
/// Preserving it instead means the rest of the packet still parses, the value
/// survives a round-trip unchanged, and a human can see what the number was.
macro_rules! tolerant_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:expr
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
            /// A discriminant this library does not recognise, preserved so it
            /// survives a decode/encode round-trip.
            Unknown(u8),
        }

        impl $name {
            /// Decodes a raw discriminant. Never fails.
            $vis const fn from_u8(raw: u8) -> Self {
                match raw {
                    $($value => $name::$variant,)*
                    other => $name::Unknown(other),
                }
            }

            /// The raw discriminant.
            $vis const fn to_u8(self) -> u8 {
                match self {
                    $($name::$variant => $value,)*
                    $name::Unknown(other) => other,
                }
            }

            /// Whether this value was recognised.
            $vis const fn is_known(self) -> bool {
                !matches!(self, $name::Unknown(_))
            }
        }

        impl From<u8> for $name {
            fn from(raw: u8) -> Self {
                $name::from_u8(raw)
            }
        }

        impl From<$name> for u8 {
            fn from(value: $name) -> u8 {
                value.to_u8()
            }
        }
    };
}
