use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// A 20-byte EVM-style address. Parsing here is deliberately
/// checksum-agnostic (case-insensitive hex) — this type is used for
/// matching against signature configs and internal bookkeeping, not for
/// signing or submitting on-chain calls. EIP-55 checksum validation
/// happens at the `chain-adapter` boundary, where addresses cross from
/// `alloy`'s own checksum-aware type into this one — a checksummed-vs-
/// actual mismatch is caught there, before it ever reaches this type.
/// Keeping that validation out of this crate is a deliberate scope
/// decision: `tripwire-core` has no chain-specific dependency at all,
/// which is what lets `detection` stay chain-agnostic (ARCHITECTURE.md §3.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address([u8; 20]);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressParseError {
    #[error("address must start with 0x")]
    MissingPrefix,
    #[error("address must be exactly 40 hex characters after 0x, got {0}")]
    WrongLength(usize),
    #[error("invalid hex character in address")]
    InvalidHex,
}

impl Address {
    pub const ZERO: Address = Address([0u8; 20]);

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_part = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .ok_or(AddressParseError::MissingPrefix)?;
        if hex_part.len() != 40 {
            return Err(AddressParseError::WrongLength(hex_part.len()));
        }
        let mut bytes = [0u8; 20];
        for (i, chunk) in hex_part.as_bytes().chunks(2).enumerate() {
            let byte_str = std::str::from_utf8(chunk).map_err(|_| AddressParseError::InvalidHex)?;
            bytes[i] =
                u8::from_str_radix(byte_str, 16).map_err(|_| AddressParseError::InvalidHex)?;
        }
        Ok(Address(bytes))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Address::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_address() {
        let a = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(a.as_bytes()[19], 1);
    }

    #[test]
    fn round_trips_display() {
        let s = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let a = Address::from_str(s).unwrap();
        assert_eq!(a.to_string(), s);
    }

    #[test]
    fn is_case_insensitive_for_equality() {
        let lower = Address::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        let upper = Address::from_str("0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD").unwrap();
        assert_eq!(lower, upper);
    }

    #[test]
    fn rejects_missing_prefix() {
        assert_eq!(
            Address::from_str("1234"),
            Err(AddressParseError::MissingPrefix)
        );
    }

    #[test]
    fn rejects_wrong_length_too_short() {
        assert_eq!(
            Address::from_str("0x1234"),
            Err(AddressParseError::WrongLength(4))
        );
    }

    #[test]
    fn rejects_wrong_length_too_long() {
        let too_long = format!("0x{}", "ab".repeat(21));
        assert_eq!(
            Address::from_str(&too_long),
            Err(AddressParseError::WrongLength(42))
        );
    }

    #[test]
    fn rejects_invalid_hex() {
        assert_eq!(
            Address::from_str("0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            Err(AddressParseError::InvalidHex)
        );
    }

    #[test]
    fn zero_constant_parses_as_all_zero_bytes() {
        assert_eq!(Address::ZERO.as_bytes(), &[0u8; 20]);
    }

    #[test]
    fn serde_round_trip() {
        let a = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let json = serde_json::to_string(&a).unwrap();
        let back: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn serde_rejects_malformed_address() {
        let result: Result<Address, _> = serde_json::from_str("\"not-an-address\"");
        assert!(result.is_err());
    }
}
