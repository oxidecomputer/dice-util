// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This crate provides types that represent a Barcode. A barcode is a string
//! that's made up of a number of substrings separated by a `:` char. Of the
//! known prefixes each contains:
//! - prefix: A string (typically 4 characters) that identify the format of the
//!   rest of the barcode.
//! - part number: A string of variable length that identifies the type of the
//!   part.
//! - revision number: In most cases this will be a 3 digit unsigned integer.
//!   For the platform identity v2 barcode we use a string of "RRR" since the
//!   actual revision number may change after the platform identity
//!   certificate was issued.
//! - serial number: A string of varying length, made up of characters that
//!   uniquely identify the part, and may encode some information.
//!
//! Use the `Barcode` type to parse the known barcode strings into their
//! components. This type is available in both the `std` and `no_std`
//! configuration.
//!
//! The `BaseboardId` type (only available with the `std` feature) is used to
//! extract the part and serial numbers that uniquely identify a platform.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use const_oid::db::rfc4519::COMMON_NAME;
use core::{fmt, num::ParseIntError};
#[cfg(feature = "std")]
use slog_error_chain::SlogInlineError;
#[cfg(feature = "std")]
use x509_cert::{
    PkiPath,
    der::{Error as DerError, asn1::Utf8StringRef},
};

/// The dictionary of ASCII characters that are base 10 digits.
const DIGITS: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

/// The dictionary of ASCII characters that are allowed in 0xide defined
/// serial numbers (RFD 219).
const SNV2_DICT: [char; 28] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'C', 'D', 'E', 'F',
    'G', 'H', 'J', 'K', 'M', 'N', 'P', 'R', 'T', 'V', 'W', 'X', 'Y',
];

/// This character is used to separate the various components of a `Barcode`
pub const SEPARATOR: &str = ":";

/// This type holds information about invalid characters found in our various
/// identifiers. We provide both the index of the character in the string and
/// the offending character.
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub struct InvalidChar {
    pub index: usize,
    pub character: char,
}

impl InvalidChar {
    pub fn new(index: usize, character: char) -> Self {
        InvalidChar { index, character }
    }
}

impl fmt::Display for InvalidChar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Invalid character: {{ index = {}, char = \'{}\' }}",
            self.index, self.character
        )
    }
}

/// String prefix identifying the first version of the 0xide barcode string
/// format
pub const PREFIX_0XV1: &str = "0XV1";

/// String prefix identifying the second version of the 0xide barcode string
/// format
pub const PREFIX_0XV2: &str = "0XV2";

/// String prefix identifying the first version of the 0xide platform identity
/// string format
pub const PREFIX_PDV1: &str = "PDV1";

/// String prefix identifying the second version of the 0xide platform
/// identity string format
pub const PREFIX_PDV2: &str = "PDV2";

/// This type identifies the possible errors encountered while parsing the
/// prefix extracted from a barcode / identity string
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum PrefixError {
    #[error("Invalid prefix")]
    Invalid,
}

/// A type representing all supported barcode string prefixes
#[derive(Debug, PartialEq)]
pub enum Prefix {
    ZeroXV1,
    ZeroXV2,
    PDV1,
    PDV2,
}

impl Prefix {
    /// Get the string representation for the `Prefix` variant
    pub fn as_str(&self) -> &str {
        match self {
            Prefix::ZeroXV1 => PREFIX_0XV1,
            Prefix::ZeroXV2 => PREFIX_0XV2,
            Prefix::PDV1 => PREFIX_PDV1,
            Prefix::PDV2 => PREFIX_PDV2,
        }
    }
}

impl TryFrom<&str> for Prefix {
    type Error = PrefixError;

    /// Construct an instance of the `Prefix` type for the given string
    fn try_from(s: &str) -> Result<Prefix, Self::Error> {
        Ok(match s {
            PREFIX_0XV1 => Prefix::ZeroXV1,
            PREFIX_0XV2 => Prefix::ZeroXV2,
            PREFIX_PDV1 => Prefix::PDV1,
            PREFIX_PDV2 => Prefix::PDV2,
            _ => return Err(Self::Error::Invalid),
        })
    }
}

/// This is a utility function to check that each character in the string `s`
/// is in the dictionary `dict`. If a character is found that is not in `dict`
/// then we return the offending index & char as `Some(InvalidChar)`.
/// Otherwise return `None` indicating that all characters in `s` are in `dict`.
fn find_invalid_char_in_dict(s: &str, dict: &[char]) -> Option<InvalidChar> {
    for (i, c) in s.chars().enumerate() {
        if !dict.contains(&c) {
            return Some(InvalidChar::new(i, c));
        }
    }

    None
}

/// A type representing the errors that can be encountered while parsing a v1
/// part number.
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum PartV1Error {
    #[error("Length of string is not 10 characters")]
    InvalidLength,
    #[cfg_attr(
        not(feature = "std"),
        error("v1 part number has invalid character: {0}")
    )]
    #[cfg_attr(feature = "std", error("v1 part number has invalid character"))]
    InvalidChar(#[source] InvalidChar),
}

/// This is a utility function to check the validity of a string holding a v1 /
/// 0XV1 part number.
fn pn_fmt_check_0xv1(s: &str) -> Result<&str, PartV1Error> {
    if s.len() != 10 {
        return Err(PartV1Error::InvalidLength);
    }

    if let Some(t) = find_invalid_char_in_dict(s, &DIGITS) {
        Err(PartV1Error::InvalidChar(t))
    } else {
        Ok(s)
    }
}

/// A type representing a v1 / 0XV1 part number
#[derive(Debug, PartialEq)]
pub struct PartV1<'a>(&'a str);

impl<'a> PartV1<'a> {
    /// Get the v2 part number as a string
    fn as_str(&'a self) -> &'a str {
        self.0
    }

    /// Get the v1 part number string as a byte slice
    fn as_bytes(&'a self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

impl<'a> TryFrom<&'a str> for PartV1<'a> {
    type Error = PartV1Error;

    /// Attempt to construct a `PartV1` type from a string
    fn try_from(s: &'a str) -> Result<PartV1<'a>, Self::Error> {
        Ok(PartV1(pn_fmt_check_0xv1(s)?))
    }
}

/// A type representing the errors that can be encountered while parsing a v2
/// part number.
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum PartV2Error {
    #[error("Length of string is not 11 characters")]
    InvalidLength,
    #[cfg_attr(
        not(feature = "std"),
        error("v2 part number has invalid character: {0}")
    )]
    #[cfg_attr(feature = "std", error("v2 part number has invalid character"))]
    InvalidChar(#[source] InvalidChar),
    #[error("Missing hyphen character at index 3")]
    NoHyphen,
}

/// This is a utility function to check the validity of a string holding a v2 /
/// 0XV2 part number. A v2 PN is a v1 PN with a '-' inserted as the 4th
/// character.
fn pn_fmt_check_0xv2(s: &str) -> Result<&str, PartV2Error> {
    if s.len() != 11 {
        return Err(PartV2Error::InvalidLength);
    }

    if s.chars().nth(3) != Some('-') {
        return Err(PartV2Error::NoHyphen);
    }

    // all remaining characters must be ascii digits
    if let Some(t) = find_invalid_char_in_dict(&s[..3], &DIGITS) {
        return Err(PartV2Error::InvalidChar(t));
    }

    // NOTE: When checking the second half of the PN when we run
    // into an invalid character we must shift its offset by 4 to
    // account for the length of the full PN.
    if let Some(t) = find_invalid_char_in_dict(&s[4..], &DIGITS) {
        let t = InvalidChar::new(t.index + 4, t.character);
        Err(PartV2Error::InvalidChar(t))
    } else {
        Ok(s)
    }
}

/// A type representing a v2 / 0XV2 part number
#[derive(Debug, PartialEq)]
pub struct PartV2<'a>(&'a str);

impl<'a> PartV2<'a> {
    /// Get the v2 part number as a string
    fn as_str(&'a self) -> &'a str {
        self.0
    }

    /// Get the v2 part number string as a byte slice
    fn as_bytes(&'a self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

impl<'a> TryFrom<&'a str> for PartV2<'a> {
    type Error = PartV2Error;

    /// Attempt to construct a `PartV2` type from a string
    fn try_from(s: &'a str) -> Result<PartV2<'a>, Self::Error> {
        Ok(PartV2(pn_fmt_check_0xv2(s)?))
    }
}

/// A type representing the errors that can be encountered while parsing a
/// Terra part number.
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum PartTerraError {
    #[error("Length of string is not 7 characters")]
    InvalidLength,
    #[cfg_attr(
        not(feature = "std"),
        error("Terra part number has invalid character: {0}")
    )]
    #[cfg_attr(
        feature = "std",
        error("Terra part number has invalid character")
    )]
    InvalidChar(#[source] InvalidChar),
    #[error("Leading digit is 0")]
    LeadingZero,
}

/// This is a utility function to check the validity of a string holding a
/// part number formatted for Terra. A Terra PN is a string of 7 ASCII digits
/// with the first digit != 0.
fn pn_fmt_check_terra(s: &str) -> Result<&str, PartTerraError> {
    if s.len() != 7 {
        return Err(PartTerraError::InvalidLength);
    }

    if s.starts_with('0') {
        return Err(PartTerraError::LeadingZero);
    }

    if let Some(t) = find_invalid_char_in_dict(s, &DIGITS) {
        Err(PartTerraError::InvalidChar(t))
    } else {
        Ok(s)
    }
}

/// A type representing a Terra part number
#[derive(Debug, PartialEq)]
pub struct PartTerra<'a>(&'a str);

impl<'a> PartTerra<'a> {
    /// Get the Terra part number as a string
    fn as_str(&'a self) -> &'a str {
        self.0
    }

    /// Get the Terra part number string as a byte slice
    fn as_bytes(&'a self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

impl<'a> TryFrom<&'a str> for PartTerra<'a> {
    type Error = PartTerraError;

    /// Attempt to construct a `PartTerra` type from a string
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Ok(PartTerra(pn_fmt_check_terra(s)?))
    }
}

/// A type representing the errors that can be encountered while parsing our
/// various part number formats. This type wraps the error types from `PartV1`,
/// `PartV2`, and `Terra` formatted part numbers.
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum PartError {
    #[error("Part str is the wrong length")]
    InvalidLength,
    #[cfg_attr(
        not(feature = "std"),
        error("Failed to parse v1 part number: {0}")
    )]
    #[cfg_attr(feature = "std", error("Failed to parse v1 part number"))]
    PartV1(#[from] PartV1Error),
    #[cfg_attr(
        not(feature = "std"),
        error("Failed to parse v2 part number: {0}")
    )]
    #[cfg_attr(feature = "std", error("Failed to parse v2 part number"))]
    PartV2(#[from] PartV2Error),
    #[cfg_attr(
        not(feature = "std"),
        error("Failed to parse Terra part number: {0}")
    )]
    #[cfg_attr(feature = "std", error("Failed to parse Terra part number"))]
    PartTerra(#[from] PartTerraError),
}

/// A data bearing enum wrapping part number strings
#[derive(Debug, PartialEq)]
pub enum Part<'a> {
    V1(PartV1<'a>),
    V2(PartV2<'a>),
    Terra(PartTerra<'a>),
}

impl<'a> Part<'a> {
    /// Get the part number as a string
    pub fn as_str(&'a self) -> &'a str {
        match self {
            Part::V1(p) => p.as_str(),
            Part::V2(p) => p.as_str(),
            Part::Terra(p) => p.as_str(),
        }
    }

    /// Get the part number string as a byte slice
    pub fn as_bytes(&'a self) -> &'a [u8] {
        match self {
            Part::V1(p) => p.as_bytes(),
            Part::V2(p) => p.as_bytes(),
            Part::Terra(p) => p.as_bytes(),
        }
    }
}

impl<'a> TryFrom<&'a str> for Part<'a> {
    type Error = PartError;

    /// Attempt to construct a `Part` type from a string
    fn try_from(s: &'a str) -> Result<Part<'a>, Self::Error> {
        match s.len() {
            7 => Ok(Part::Terra(PartTerra::try_from(s)?)),
            10 => Ok(Part::V1(PartV1::try_from(s)?)),
            11 => Ok(Part::V2(PartV2::try_from(s)?)),
            _ => Err(Self::Error::InvalidLength),
        }
    }
}

/// This is a utility function to check the validity of a string holding a
/// revision number. A revision number is a string of 3 ASCII digits.
fn rev_fmt_check(s: &str) -> Result<&str, RevisionError> {
    if s.len() != 3 {
        return Err(RevisionError::InvalidLength);
    }

    if let Some(t) = find_invalid_char_in_dict(s, &DIGITS) {
        Err(RevisionError::InvalidChar(t))
    } else {
        Ok(s)
    }
}

/// A type representing the errors that can be encountered while parsing a
/// revision number string.
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum RevisionError {
    #[cfg_attr(
        not(feature = "std"),
        error("revision number has invalid character: {0}")
    )]
    #[cfg_attr(feature = "std", error("revision number has invalid character"))]
    InvalidChar(#[source] InvalidChar),
    #[error("Part str is the wrong length")]
    InvalidLength,
}

/// A type representing a revision number
#[derive(Debug, PartialEq)]
pub struct RevisionNumber<'a>(&'a str);

impl<'a> TryFrom<&'a str> for RevisionNumber<'a> {
    type Error = RevisionError;

    /// Attempt to construct a `Part` type from a string
    fn try_from(s: &'a str) -> Result<RevisionNumber<'a>, Self::Error> {
        Ok(Self(rev_fmt_check(s)?))
    }
}

impl<'a> RevisionNumber<'a> {
    /// Get the serial number as a string
    pub fn as_str(&'a self) -> &'a str {
        self.0
    }

    /// Get the serial number string as a byte slice
    pub fn as_bytes(&'a self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

const REV_NULL: &str = "RRR";

/// This is a utility function to check the validity of a string holding a
/// NULL revision number.
fn rev_null_fmt_check(s: &str) -> Result<&str, RevisionError> {
    if s.len() != 3 {
        return Err(RevisionError::InvalidLength);
    }

    // we could just compare the input string to REV_NULL but this gives the
    // caller better info: the first invalid character
    if let Some(t) = find_invalid_char_in_dict(s, &['R']) {
        Err(RevisionError::InvalidChar(t))
    } else {
        Ok(s)
    }
}

/// A type representing a NULL revision number. A NULL revision number became
/// necessary when we realized that the process implemented at our
/// manufacturer may result in a revision number change after the platform
/// identity had been issued. As a work around we simply replace the revision
/// number w/ the string "RRR".
#[derive(Debug, PartialEq)]
pub struct RevisionNull;

impl TryFrom<&str> for RevisionNull {
    type Error = RevisionError;

    /// Attempt to construct a `Part` type from a string
    fn try_from(s: &str) -> Result<RevisionNull, Self::Error> {
        rev_null_fmt_check(s)?;
        Ok(Self)
    }
}

impl RevisionNull {
    /// Get the serial number as a string
    pub fn as_str(&self) -> &str {
        REV_NULL
    }

    /// Get the serial number string as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        REV_NULL.as_bytes()
    }
}

/// A data bearing enum wrapping the possible part number strings
#[derive(Debug, PartialEq)]
pub enum Revision<'a> {
    Number(RevisionNumber<'a>),
    Null(RevisionNull),
}

impl<'a> Revision<'a> {
    /// Get the serial number as a string
    pub fn as_str(&'a self) -> &'a str {
        match self {
            Revision::Number(s) => s.as_str(),
            Revision::Null(s) => s.as_str(),
        }
    }

    /// Get the serial number string as a byte slice
    pub fn as_bytes(&'a self) -> &'a [u8] {
        match self {
            Revision::Number(s) => s.as_bytes(),
            Revision::Null(s) => s.as_bytes(),
        }
    }
}

impl<'a> TryFrom<&'a str> for Revision<'a> {
    type Error = RevisionError;

    /// Attempt to construct a `Revision` instance from a string
    fn try_from(s: &'a str) -> Result<Revision<'a>, Self::Error> {
        if rev_null_fmt_check(s).is_ok() {
            return Ok(Self::Null(RevisionNull));
        }

        match rev_fmt_check(s) {
            Ok(s) => Ok(Self::Number(RevisionNumber(s))),
            Err(e) => Err(e),
        }
    }
}

/// A type representing errors that can be encountered while parsing a v1
/// serial number string.
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum SerialV1Error {
    #[error("Serial number v1 str is the wrong length")]
    InvalidLength,
    #[error("Invalid serial number v1 location")]
    InvalidLocation,
    #[cfg_attr(
        not(feature = "std"),
        error("v1 serial number is not an integer: {0}")
    )]
    #[cfg_attr(feature = "std", error("v1 serial number is not an integer"))]
    InvalidYear(#[source] ParseIntError),
    #[error("invalid serial number v1 week")]
    InvalidWeek,
    #[cfg_attr(
        not(feature = "std"),
        error("v1 serial number has an invalid character: {0}")
    )]
    #[cfg_attr(
        feature = "std",
        error("v1 serial number has an invalid character")
    )]
    InvalidWeekChar(#[source] ParseIntError),
    #[error("Serial number v1 contains an invalid unique id")]
    InvalidId,
}

/// This utility function checks the validity of a string holding a v1 serial
/// number
fn snv1_fmt_check(s: &str) -> Result<&str, SerialV1Error> {
    // v1 serial numbers must be 11 characters long
    if s.len() != 11 {
        return Err(SerialV1Error::InvalidLength);
    }

    // first 3 characters are `BRM`
    if &s[..3] != "BRM" {
        return Err(SerialV1Error::InvalidLocation);
    }

    // 3-4 are a two digit week of manufacture `00`
    let week: u32 = s[3..5].parse().map_err(SerialV1Error::InvalidWeekChar)?;
    if !(1..=53).contains(&week) {
        return Err(SerialV1Error::InvalidWeek);
    }

    // 5-6 are a two digit year of manufacture `25`
    let _: u32 = s[5..7].parse().map_err(SerialV1Error::InvalidYear)?;

    // 7-11 are 4 character unique value
    if !s[7..].is_ascii() {
        Err(SerialV1Error::InvalidId)
    } else {
        Ok(s)
    }
}

/// This type represents a v1 serial number
#[derive(Debug, PartialEq)]
pub struct SerialV1<'a>(&'a str);

impl<'a> SerialV1<'a> {
    /// Get the v1 serial number as a string
    fn as_str(&'a self) -> &'a str {
        self.0
    }

    /// Get the v1 serial number string as a byte slice
    fn as_bytes(&'a self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

impl<'a> TryFrom<&'a str> for SerialV1<'a> {
    type Error = SerialV1Error;

    /// Attempt to construct a `SerialV1` type from a string
    fn try_from(s: &'a str) -> Result<SerialV1<'a>, Self::Error> {
        Ok(SerialV1(snv1_fmt_check(s)?))
    }
}

/// A type representing errors that can be encountered while parsing a v2
/// serial number string.
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum SerialV2Error {
    #[cfg_attr(
        not(feature = "std"),
        error("v2 serial number has an invalid character: {0}")
    )]
    #[cfg_attr(
        feature = "std",
        error("v2 serial number has an invalid character")
    )]
    InvalidChar(#[source] InvalidChar),
    #[error("Serial number v2 str is the wrong length")]
    InvalidLength,
    #[error("Serial number v2 str has the wrong leading digit")]
    WrongVersion,
}

/// This utility function checks the validity of a string holding a v2 serial
/// number
fn snv2_fmt_check(s: &str) -> Result<&str, SerialV2Error> {
    // v2 serial numbers must be 8 characters long
    if s.len() != 8 {
        return Err(SerialV2Error::InvalidLength);
    }

    // the first digit indicates the version
    if !s.starts_with('2') {
        return Err(SerialV2Error::WrongVersion);
    }

    // the remaining 7 characters must be in the defined dictionary
    if let Some(t) = find_invalid_char_in_dict(s, &SNV2_DICT) {
        Err(SerialV2Error::InvalidChar(t))
    } else {
        Ok(s)
    }
}

/// This type represents a v2 serial number
#[derive(Debug, PartialEq)]
pub struct SerialV2<'a>(&'a str);

impl<'a> SerialV2<'a> {
    /// Get the v2 serial number as a string
    fn as_str(&'a self) -> &'a str {
        self.0
    }

    /// Get the v2 serial number string as a byte slice
    fn as_bytes(&'a self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

impl<'a> TryFrom<&'a str> for SerialV2<'a> {
    type Error = SerialV2Error;

    /// Attempt to construct a `SerialV2` instance from a string
    fn try_from(s: &'a str) -> Result<SerialV2<'a>, Self::Error> {
        Ok(SerialV2(snv2_fmt_check(s)?))
    }
}

/// A type representing the errors that can be encountered while parsing a
/// serial number string.
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum SerialError {
    #[error("Serial number is the wrong length")]
    InvalidLength,
    #[cfg_attr(
        not(feature = "std"),
        error("Failed to parse v1 serial number: {0}")
    )]
    #[cfg_attr(feature = "std", error("Failed to parse v1 serial number"))]
    SerialV1(#[from] SerialV1Error),
    #[cfg_attr(
        not(feature = "std"),
        error("Failed to parse v2 serial number: {0}")
    )]
    #[cfg_attr(feature = "std", error("Failed to parse v2 serial number"))]
    SerialV2(#[from] SerialV2Error),
}

/// A data bearing enum wrapping the possible serial number strings
#[derive(Debug, PartialEq)]
pub enum Serial<'a> {
    V1(SerialV1<'a>),
    V2(SerialV2<'a>),
}

impl<'a> Serial<'a> {
    /// Get the serial number as a string
    pub fn as_str(&'a self) -> &'a str {
        match self {
            Serial::V1(s) => s.as_str(),
            Serial::V2(s) => s.as_str(),
        }
    }

    /// Get the serial number string as a byte slice
    pub fn as_bytes(&'a self) -> &'a [u8] {
        match self {
            Serial::V1(s) => s.as_bytes(),
            Serial::V2(s) => s.as_bytes(),
        }
    }
}

impl<'a> TryFrom<&'a str> for Serial<'a> {
    type Error = SerialError;

    /// Attempt to construct a `Serial` instance from a string
    fn try_from(s: &'a str) -> Result<Serial<'a>, Self::Error> {
        match s.len() {
            8 => Ok(Serial::V2(SerialV2::try_from(s)?)),
            11 => Ok(Serial::V1(SerialV1::try_from(s)?)),
            _ => Err(Self::Error::InvalidLength),
        }
    }
}

/// A type representing the errors that can be encountered while parsing a
/// barcode string
#[derive(Debug, thiserror::Error, PartialEq)]
#[cfg_attr(feature = "std", derive(SlogInlineError))]
pub enum BarcodeError {
    #[error("The input string has no delimiters")]
    NoDelim,
    #[error("The input string has no part number")]
    NoPartNumber,
    #[error("The input string has no revision number")]
    NoRevisionNumber,
    #[error("The input string has no serial number")]
    NoSerialNumber,
    #[error("Barcodes with the 0XV1 or PDV1 prefix must have v1 part numbers")]
    PartNotV1,
    #[error("Barcodes with the 0XV2 prefix must have v2 part numbers")]
    PartNotV2,
    #[cfg_attr(not(feature = "std"), error("Part number is invalid: {0}"))]
    #[cfg_attr(feature = "std", error("Part number is invalid"))]
    Part(#[from] PartError),
    #[cfg_attr(not(feature = "std"), error("Prefix is invalid: {0}"))]
    #[cfg_attr(feature = "std", error("Prefix is invalid"))]
    Prefix(#[from] PrefixError),
    #[cfg_attr(not(feature = "std"), error("Revision is invalid: {0}"))]
    #[cfg_attr(feature = "std", error("Revision is invalid"))]
    Revision(#[from] RevisionError),
    #[error("Barcode has NULL revision but prefix requires a revision number")]
    RevisionIsNull,
    #[error("Barcode has revision number but prefix requires a NULL revision")]
    RevisionNotNull,
    #[cfg_attr(not(feature = "std"), error("Serial number is invalid: {0}"))]
    #[cfg_attr(feature = "std", error("Serial number is invalid"))]
    Serial(#[from] SerialError),
    #[error(
        "Barcodes with the 0XV1 or PDV1 prefix must have v1 serial numbers"
    )]
    SerialNotV1,
}

/// Barcodes consist of 4 parts, all are ASCII strings, separated by a ':'
/// character. The `Barcode` type wraps these four parts in instances of the
/// `Prefix`, `Part`, `Revision`, and `Serial` types.
#[derive(Debug, PartialEq)]
pub struct Barcode<'a> {
    pub prefix: Prefix,
    pub part: Part<'a>,
    pub revision: Revision<'a>,
    pub serial: Serial<'a>,
}

impl<'a> TryFrom<&'a str> for Barcode<'a> {
    type Error = BarcodeError;

    /// Attempt to construct a `Barcode` instance from a string
    fn try_from(s: &'a str) -> Result<Barcode<'a>, Self::Error> {
        let mut split = s.split(SEPARATOR);

        // the first time we `next` the iterator it will return something even
        // if the string is empty
        let prefix = split.next().unwrap();

        // After calling `next` once, if the string returned is the same as the
        // one provided then the pattern we `split` on isn't in the string
        if s == prefix {
            return Err(Self::Error::NoDelim);
        }

        let prefix = Prefix::try_from(prefix)?;

        let part = split.next().ok_or(Self::Error::NoPartNumber)?;
        let part = Part::try_from(part)?;

        // the prefix determines permitted formats for the part number
        match prefix {
            // 0XV1 must be in v1 format
            Prefix::ZeroXV1 => match part {
                Part::V1(_) => (),
                _ => return Err(Self::Error::PartNotV1),
            },
            // 0XV1, 0XV2 and PDV2 must be in v2 format
            Prefix::PDV1 | Prefix::ZeroXV2 | Prefix::PDV2 => match part {
                Part::V2(_) => (),
                _ => return Err(Self::Error::PartNotV2),
            },
        }

        let revision = split.next().ok_or(Self::Error::NoRevisionNumber)?;
        let revision = Revision::try_from(revision)?;

        // the prefix determines the permitted formats for the revision number
        match prefix {
            Prefix::PDV2 => match revision {
                Revision::Null(_) => (),
                _ => return Err(Self::Error::RevisionNotNull),
            },
            _ => match revision {
                Revision::Number(_) => (),
                _ => return Err(Self::Error::RevisionIsNull),
            },
        }

        let serial = split.next().ok_or(Self::Error::NoSerialNumber)?;
        let serial = Serial::try_from(serial)?;

        // the prefix determines permitted formats for the serial number
        match prefix {
            // 0XV1 or PDV1: must be in v1 format
            Prefix::ZeroXV1 | Prefix::PDV1 => match serial {
                Serial::V1(_) => (),
                _ => return Err(Self::Error::SerialNotV1),
            },
            // 0XV2 or PDV2: may be in v1 or v2 format
            Prefix::ZeroXV2 | Prefix::PDV2 => match serial {
                Serial::V1(_) | Serial::V2(_) => (),
            },
        }

        Ok(Barcode {
            prefix,
            part,
            revision,
            serial,
        })
    }
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq)]
pub struct BaseboardId {
    pub part_number: String,
    pub serial_number: String,
}

#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error, PartialEq, SlogInlineError)]
pub enum BaseboardIdPkiPathError {
    #[cfg_attr(
        not(feature = "std"),
        error("Failed to decode CountryName: {0}")
    )]
    #[cfg_attr(feature = "std", error("Failed to decode CountryName"))]
    CountryNameDecode(#[source] DerError),
    #[error("Expected CountryName \"US\", got {0}")]
    InvalidCountryName(String),
    #[cfg_attr(
        not(feature = "std"),
        error("Failed to decode OrganizationName: {0}")
    )]
    #[cfg_attr(feature = "std", error("Failed to decode OrganizationName"))]
    OrganizationNameDecode(#[source] DerError),
    #[error("Expected CountryName \"US\", got {0}")]
    InvalidOrganizationName(String),
    #[cfg_attr(not(feature = "std"), error("Failed to decode CommonName: {0}"))]
    #[cfg_attr(feature = "std", error("Failed to decode CommonName"))]
    CommonNameDecode(#[source] DerError),
    #[error("More than one PlatformId found in PkiPath")]
    MultiplePlatformIds,
    #[error("No PlatformId found in PkiPath")]
    NoPlatformId,
}

#[cfg(feature = "std")]
impl TryFrom<&str> for BaseboardId {
    type Error = BarcodeError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let barcode = Barcode::try_from(s)?;

        Ok(BaseboardId {
            part_number: barcode.part.as_str().to_owned(),
            serial_number: barcode.serial.as_str().to_owned(),
        })
    }
}

#[cfg(feature = "std")]
impl TryFrom<&PkiPath> for BaseboardId {
    type Error = BaseboardIdPkiPathError;

    // Find the PlatformId in the provided cert chain. This value is stored
    // in cert's `Subject` field. The PlatformId string is stored in the
    // Subject CN / commonName. A PkiPath with more than one PlatformId in
    // it produces an error.
    fn try_from(pki_path: &PkiPath) -> Result<Self, Self::Error> {
        let mut baseboard_id: Option<BaseboardId> = None;
        for cert in pki_path {
            for elm in &cert.tbs_certificate.subject.0 {
                for atav in elm.0.iter() {
                    if atav.oid == COMMON_NAME {
                        let common = Utf8StringRef::try_from(&atav.value)
                            .map_err(Self::Error::CommonNameDecode)?;
                        let common: &str = common.as_ref();
                        // our common name is a fixed 32 bytes, but trailing
                        // characters may be NUL so we trim
                        let common = common.trim_end_matches('\0');

                        // We intentionally ignore the error here as a crude
                        // way to filter out certs in the PkiPath w/ CNs that
                        // aren't valid barcodes
                        if let Ok(id) = BaseboardId::try_from(common) {
                            if baseboard_id.is_none() {
                                baseboard_id = Some(id);
                            } else {
                                return Err(Self::Error::MultiplePlatformIds);
                            }
                        }
                    }
                }
            }
        }

        baseboard_id.ok_or(Self::Error::NoPlatformId)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // empty prefix string is invalid
    #[test]
    fn prefix_empty() {
        let result = Prefix::try_from("");
        assert_eq!(result, Err(PrefixError::Invalid));
    }

    // not one of the supported prefixes
    #[test]
    fn prefix_invalid() {
        let result = Prefix::try_from("FOO");
        assert_eq!(result, Err(PrefixError::Invalid));
    }

    // not many prefixes so we can test exhaustively
    #[test]
    fn prefix_0xv1() {
        let result = Prefix::try_from("0XV1");
        assert_eq!(result, Ok(Prefix::ZeroXV1));
    }

    #[test]
    fn prefix_0xv2() {
        let result = Prefix::try_from("0XV2");
        assert_eq!(result, Ok(Prefix::ZeroXV2));
    }

    #[test]
    fn prefix_pdv1() {
        let result = Prefix::try_from(PREFIX_PDV1);
        assert_eq!(result, Ok(Prefix::PDV1));
    }

    #[test]
    fn prefix_pdv2() {
        let result = Prefix::try_from("PDV2");
        assert_eq!(result, Ok(Prefix::PDV2));
    }

    const PN_V1_BAD_CHAR: &str = "913-000019";
    #[test]
    fn pn_0xv1_bad_char() {
        let result = PartV1::try_from(PN_V1_BAD_CHAR);
        assert_eq!(
            result,
            Err(PartV1Error::InvalidChar(InvalidChar::new(3, '-')))
        );
    }

    const PN_V1_GOOD: &str = "9130000019";
    #[test]
    fn pn_0xv1_good() {
        let result = PartV1::try_from(PN_V1_GOOD);
        assert!(result.is_ok());
    }

    const PN_V2_NO_HYPHEN: &str = "91300000019";
    #[test]
    fn pn_0xv2_no_hyphen() {
        let result = PartV2::try_from(PN_V2_NO_HYPHEN);
        assert_eq!(result, Err(PartV2Error::NoHyphen));
    }

    const PN_V2_BAD_CHAR_PREFIX: &str = "9a3-0000019";
    #[test]
    fn pn_0xv2_bad_char_prefix() {
        let result = PartV2::try_from(PN_V2_BAD_CHAR_PREFIX);
        assert_eq!(
            result,
            Err(PartV2Error::InvalidChar(InvalidChar::new(1, 'a')))
        );
    }

    const PN_V2_BAD_CHAR_SUFFIX: &str = "913-000_019";
    #[test]
    fn pn_0xv2_bad_char_suffix() {
        let result = PartV2::try_from(PN_V2_BAD_CHAR_SUFFIX);
        assert_eq!(
            result,
            Err(PartV2Error::InvalidChar(InvalidChar::new(7, '_')))
        );
    }

    // tests for Terra CPNs: 7 digits, leading digit must be > 0
    const PN_TERRA_LEADING_ZERO: &str = "0000000";
    #[test]
    fn pn_terra_leading_zero() {
        let result = PartTerra::try_from(PN_TERRA_LEADING_ZERO);
        assert_eq!(result, Err(PartTerraError::LeadingZero));
    }

    const PN_TERRA_ALPHA: &str = "300A000";
    #[test]
    fn pn_terra_alpha() {
        let result = PartTerra::try_from(PN_TERRA_ALPHA);
        assert_eq!(
            result,
            Err(PartTerraError::InvalidChar(InvalidChar::new(3, 'A')))
        );
    }

    const PN_TERRA_GOOD: &str = "3000000";
    #[test]
    fn pn_terra_good() {
        let result = PartTerra::try_from(PN_TERRA_GOOD);
        assert!(result.is_ok());
    }

    const REV_LONG: &str = "6666";
    #[test]
    fn rev_long() {
        let result = Revision::try_from(REV_LONG);
        assert_eq!(result, Err(RevisionError::InvalidLength));
    }

    const REV_SHORT: &str = "66";
    #[test]
    fn rev_short() {
        let result = Revision::try_from(REV_SHORT);
        assert_eq!(result, Err(RevisionError::InvalidLength));
    }

    const REV_INVALID_CHAR: &str = "66a";
    #[test]
    fn rev_invalid_char() {
        let result = Revision::try_from(REV_INVALID_CHAR);
        assert_eq!(
            result,
            Err(RevisionError::InvalidChar(InvalidChar::new(2, 'a')))
        );
    }

    const REV_GOOD: &str = "012";
    #[test]
    fn rev_good() {
        let result = Revision::try_from(REV_GOOD);
        assert!(result.is_ok());
    }

    const SNV1_BAD_LENGTH: &str = "BRZ0125FFFFG";
    #[test]
    fn snv1_bad_length() {
        let result = SerialV1::try_from(SNV1_BAD_LENGTH);
        assert_eq!(result, Err(SerialV1Error::InvalidLength));
    }

    const SNV1_BAD_LOCATION: &str = "BRZ0125FFFF";
    #[test]
    fn snv1_bad_location() {
        let result = SerialV1::try_from(SNV1_BAD_LOCATION);
        assert_eq!(result, Err(SerialV1Error::InvalidLocation));
    }

    use core::num::IntErrorKind::InvalidDigit;

    const SNV1_BAD_WEEK: &str = "BRM0f25FFFF";
    #[test]
    fn snv1_bad_week() {
        let result = SerialV1::try_from(SNV1_BAD_WEEK);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            SerialV1Error::InvalidWeekChar(p) => {
                assert_eq!(p.kind(), &InvalidDigit)
            }
            e => panic!(
                "Expected SerialV1Error::InvalidWeekChar(ParseIntError, got {e}"
            ),
        }
    }

    const SNV1_BAD_YEAR: &str = "BRM01f5FFFF";
    #[test]
    fn snv1_bad_year() {
        let result = SerialV1::try_from(SNV1_BAD_YEAR);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            SerialV1Error::InvalidYear(p) => {
                assert_eq!(p.kind(), &InvalidDigit)
            }
            e => panic!(
                "Expected SerialV1Error::InvalidYear(ParseIntError), got {e}"
            ),
        }
    }

    const SNV1_BAD_ID: &str = "BRM0125😒";
    #[test]
    fn snv1_bad_id() {
        let result = SerialV1::try_from(SNV1_BAD_ID);
        assert_eq!(result, Err(SerialV1Error::InvalidId));
    }

    const SNV2_BAD_LENGTH: &str = "2555555";
    #[test]
    fn snv2_bad_length() {
        let result = SerialV2::try_from(SNV2_BAD_LENGTH);
        assert_eq!(result, Err(SerialV2Error::InvalidLength));
    }

    const SNV2_BAD_VERSION: &str = "15555555";
    #[test]
    fn snv2_bad_version() {
        let result = SerialV2::try_from(SNV2_BAD_VERSION);
        assert_eq!(result, Err(SerialV2Error::WrongVersion));
    }

    const SNV2_INVALID_CHAR: &str = "2555U555";
    #[test]
    fn snv2_bad_char() {
        let result = SerialV2::try_from(SNV2_INVALID_CHAR);
        assert_eq!(
            result,
            Err(SerialV2Error::InvalidChar(InvalidChar::new(4, 'U')))
        );
    }

    #[cfg(feature = "std")]
    use anyhow::Context;
    #[cfg(feature = "std")]
    use x509_cert::Certificate;

    // a self signed cert with a platform id string in the the Subject
    // commonName
    #[cfg(feature = "std")]
    const PLATFORM_ID_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBtTCCAWegAwIBAgIBADAFBgMrZXAwWTELMAkGA1UEBhMCVVMxHzAdBgNVBAoM
Fk94aWRlIENvbXB1dGVyIENvbXBhbnkxKTAnBgNVBAMMIFBEVjI6OTEzLTAwMDAw
MTk6UlJSOkJSTTAxMjVTU1NTMCAXDTI1MTAwNTIwMjUzNVoYDzk5OTkxMjMxMjM1
OTU5WjBZMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWT3hpZGUgQ29tcHV0ZXIgQ29t
cGFueTEpMCcGA1UEAwwgUERWMjo5MTMtMDAwMDAxOTpSUlI6QlJNMDEyNVNTU1Mw
KjAFBgMrZXADIQBMG83tJtwLBZUEWEvqdmArDurS99oWBzqRuwGWVOwygqNSMFAw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwLQYDVR0gAQH/BCMwITAJ
BgdngQUFBGQGMAkGB2eBBQUEZAgwCQYHZ4EFBQRkDDAFBgMrZXADQQDct3PXbNNr
580BdDFF0xijkWVPuNwTcmPtbweFwHyjKmrMnsPoH0SGdXPnNPBQaxIQRRUBlsll
I1Dpq9liDQgB
-----END CERTIFICATE-----
"#;

    #[cfg(feature = "std")]
    #[test]
    fn pid_from_pki_path() -> anyhow::Result<()> {
        let bytes = PLATFORM_ID_PEM.as_bytes();
        let cert_chain: PkiPath = Certificate::load_pem_chain(bytes)
            .context("Certificate from PLATFORM_ID_PEM")?;

        let baseboard_id = BaseboardId::try_from(&cert_chain)
            .context("PlatformId from cert chain")?;

        assert_eq!(baseboard_id.part_number, "913-0000019");
        Ok(assert_eq!(baseboard_id.serial_number, "BRM0125SSSS"))
    }

    #[cfg(feature = "std")]
    const PLATFORM_ID_V2_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBrzCCAWGgAwIBAgIBADAFBgMrZXAwVjELMAkGA1UEBhMCVVMxHzAdBgNVBAoM
Fk94aWRlIENvbXB1dGVyIENvbXBhbnkxJjAkBgNVBAMMHVBEVjI6OTEzLTAwMDAw
MTk6UlJSOjIwMDAwMDAxMCAXDTI1MTAwNTIwNDAxNVoYDzk5OTkxMjMxMjM1OTU5
WjBWMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWT3hpZGUgQ29tcHV0ZXIgQ29tcGFu
eTEmMCQGA1UEAwwdUERWMjo5MTMtMDAwMDAxOTpSUlI6MjAwMDAwMDEwKjAFBgMr
ZXADIQAGu+YOb+jCK2ym7VbkqLFow84N63eGReFvUjFjFY4hDqNSMFAwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwLQYDVR0gAQH/BCMwITAJBgdngQUF
BGQGMAkGB2eBBQUEZAgwCQYHZ4EFBQRkDDAFBgMrZXADQQAZl2L55J+mR16GvdJ3
RbTFWQP529efGPuONazpoynDoFBadsoB+9h2COjtba45BogaXG1mfc+gThY/byGN
pngE
-----END CERTIFICATE-----
"#;

    #[cfg(feature = "std")]
    #[test]
    fn pid_from_pki_path_v2() -> anyhow::Result<()> {
        let bytes = PLATFORM_ID_V2_PEM.as_bytes();
        let cert_chain: PkiPath = Certificate::load_pem_chain(bytes)
            .context("Certificate from PLATFORM_ID_PEM")?;

        let baseboard_id = BaseboardId::try_from(&cert_chain)
            .context("PlatformId from cert chain")?;

        assert_eq!(baseboard_id.part_number, "913-0000019");
        Ok(assert_eq!(baseboard_id.serial_number, "20000001"))
    }

    #[cfg(feature = "std")]
    #[test]
    fn pid_from_pki_path_multiple() -> anyhow::Result<()> {
        // Create a cert chain w/ multiple PlatformIds. This chain is invalid
        // but it's useful for testing and a good example of why we need to
        // verify the signatures through the chain before pulling out data
        // like the PlatformId.
        let mut certs: String = PLATFORM_ID_PEM.to_owned();
        certs.push_str(PLATFORM_ID_PEM);

        let cert_chain: PkiPath = Certificate::load_pem_chain(certs.as_bytes())
            .context("Certificate from two istances of PLATFORM_ID_PEM")?;

        let baseboard_id = BaseboardId::try_from(&cert_chain);

        Ok(assert_eq!(
            baseboard_id,
            Err(BaseboardIdPkiPathError::MultiplePlatformIds)
        ))
    }

    #[cfg(feature = "std")]
    const NO_PLATFORM_ID_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBADCBs6ADAgECAgEAMAUGAytlcDApMQswCQYDVQQGEwJVUzEMMAoGA1UECgwD
Zm9vMQwwCgYDVQQDDANiYXIwIBcNMjUwNDI5MDUyMzE5WhgPOTk5OTEyMzEyMzU5
NTlaMCkxCzAJBgNVBAYTAlVTMQwwCgYDVQQKDANmb28xDDAKBgNVBAMMA2JhcjAq
MAUGAytlcAMhALcL3kNks3jo9ExtQYeCZ+BoCy1Or5ybLPqSsi9XZXiSMAUGAytl
cANBAFleiVB2JzLpysPIJkia4DYodkTc0KuelpNqV0ycemgQqD30O085W7xZ+c/X
+AqBlWPcwiy+hq3aaWCa586hUQ8=
-----END CERTIFICATE-----
"#;

    #[cfg(feature = "std")]
    #[test]
    fn pid_from_pki_path_none() -> anyhow::Result<()> {
        let bytes = NO_PLATFORM_ID_PEM.as_bytes();
        let cert_chain: PkiPath = Certificate::load_pem_chain(bytes)
            .context("Certificate from NO_PLATFORM_ID_PEM")?;

        let baseboard_id = BaseboardId::try_from(&cert_chain);

        Ok(assert_eq!(
            baseboard_id,
            Err(BaseboardIdPkiPathError::NoPlatformId)
        ))
    }
}
