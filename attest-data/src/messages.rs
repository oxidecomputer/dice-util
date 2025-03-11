// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{NONCE_SIZE, SHA3_256_DIGEST_SIZE};
use hubpack::error::Error as HubpackError;
use hubpack::SerializedSize;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Magic value for [`Header::magic`]
pub const ATTEST_MAGIC: u32 = 0xA77E5700;

/// Right now `Attest` and `TqSign` are the only commands that take data
/// argumenets. They happen to be the same length right now but this also
/// catches anything silly
const fn const_max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}
pub const MAX_DATA_LEN: usize = const_max(NONCE_SIZE, SHA3_256_DIGEST_SIZE);

pub const MAX_REQUEST_SIZE: usize =
    HostRotHeader::MAX_SIZE + HostToRotCommand::MAX_SIZE + MAX_DATA_LEN;

pub mod version {
    pub const V1: u32 = 1;
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, SerializedSize,
)]
pub struct HostRotHeader {
    magic: u32,
    version: u32,
}

impl Default for HostRotHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl HostRotHeader {
    pub fn new() -> Self {
        Self {
            magic: ATTEST_MAGIC,
            version: version::V1,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, SerializedSize,
)]
#[repr(u32)]
pub enum HostToRotCommand {
    /// Returns the certificate chain associated with the RoT
    GetCertificates,
    /// Returns the measurement log
    GetMeasurementLog,
    /// Calculates sign(sha3_256(hubpack(measurement_log) | nonce))
    /// and returns the result.
    Attest,
    /// Returns the certificate chain associated with TQ
    GetTqCertificates,
    /// Signs a 32 byte message with the TQ key
    TqSign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
//#[repr(u32)]
pub enum HostToRotError {
    _Unused,
    /// Header magic was incorrect
    MagicMismatch,
    /// Mismatch of protocol versions
    VersionMismatch,
    /// Message failed to deserialize
    Deserialize,
    /// Wrong length of data arguments (expected no data or incorrect length)
    IncorrectDataLen,
    /// Unexpected command returned
    UnexpectedCommand,
    /// Error return from the sprot command
    SprotError(RecvSprotError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[repr(u32)]
// Errors returned from the hubris side. This is _so many_
pub enum RecvSprotError {
    // protocol
    /// CRC check failed.
    ProtocolInvalidCrc,
    /// FIFO overflow/underflow
    ProtocolFlowError,
    /// Unsupported protocol version
    ProtocolUnsupportedProtocol,
    /// Unknown message
    ProtocolBadMessageType,
    /// Transfer size is outside of maximum and minimum lenghts for message type.
    ProtocolBadMessageLength,
    // We cannot assert chip select
    ProtocolCannotAssertCSn,
    // The request timed out
    ProtocolTimeout,
    // Hubpack error
    ProtocolDeserialization,
    // The RoT has not de-asserted ROT_IRQ
    ProtocolRotIrqRemainsAsserted,
    // An unexpected response was received.
    // This should basically be impossible. We only include it so we can
    // return this error when unpacking a RspBody in idol calls.
    ProtocolUnexpectedResponse,
    // Failed to load update status
    ProtocolBadUpdateStatus,
    // Used for mapping From<idol_runtime::ServerDeath>
    ProtocolTaskRestarted,
    // The SP and RoT did not agree on whether the SP is sending
    // a request or waiting for a reply.
    ProtocolDesynchronized,

    // Spi
    SpiBadTransferSize,
    SpiTaskRestarted,

    // Update -- this should not get returned
    UpdateError,
    // Sprockets is deprecated but we still keep the error type
    SprocketsError,
    // Watchdog error, we should not get this
    WatchdogError,

    // Attest errors
    AttestCertTooBig,
    AttestInvalidCertIndex,
    AttestNoCerts,
    AttestOutOfRange,
    AttestLogFull,
    AttestLogTooBig,
    AttestTaskRestarted,
    AttestBadLease,
    AttestUnsupportedAlgorithm,
    AttestSerializeLog,
    AttestSerializeSignature,
    AttestSignatureTooBig,
    // Handle some host-sp-comms errors
    CommsBufTooSmall,
    AttestLogSlotReserved,
}

impl From<HubpackError> for HostToRotError {
    fn from(_: HubpackError) -> Self {
        Self::Deserialize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum RotToHost {
    HostToRotError(HostToRotError),
    RotCertificates,
    RotMeasurementLog,
    RotAttestation,
    RotTqCertificates,
    RotTqSign,
}

impl From<RecvSprotError> for RotToHost {
    fn from(e: RecvSprotError) -> Self {
        RotToHost::HostToRotError(HostToRotError::SprotError(e))
    }
}

fn deserialize<T: DeserializeOwned>(
    data: &[u8],
) -> Result<(HostRotHeader, T, &[u8]), HostToRotError> {
    let (header, leftover) = hubpack::deserialize::<HostRotHeader>(data)?;
    let (command, leftover) = hubpack::deserialize::<T>(leftover)?;

    Ok((header, command, leftover))
}

/// Parse a message sent from the Host to the SP
pub fn parse_message(
    buf: &[u8],
) -> Result<(HostToRotCommand, &[u8]), HostToRotError> {
    let (header, command, leftover) = deserialize::<HostToRotCommand>(buf)?;

    if header.magic != ATTEST_MAGIC {
        return Err(HostToRotError::MagicMismatch);
    }

    if header.version != version::V1 {
        return Err(HostToRotError::VersionMismatch);
    }

    match command {
        // These commands don't take data
        HostToRotCommand::GetCertificates
        | HostToRotCommand::GetMeasurementLog
        | HostToRotCommand::GetTqCertificates => {
            if !leftover.is_empty() {
                return Err(HostToRotError::IncorrectDataLen);
            }
        }
        HostToRotCommand::Attest => {
            if leftover.len() != NONCE_SIZE {
                return Err(HostToRotError::IncorrectDataLen);
            }
        }
        HostToRotCommand::TqSign => {
            if leftover.len() != SHA3_256_DIGEST_SIZE {
                return Err(HostToRotError::IncorrectDataLen);
            }
        }
    }

    Ok((command, leftover))
}

/// Parse a response from the SP to the Host
pub fn parse_response(
    buf: &[u8],
    expected: RotToHost,
) -> Result<&[u8], HostToRotError> {
    let (header, command, leftover) = deserialize::<RotToHost>(buf)?;

    if header.magic != ATTEST_MAGIC {
        return Err(HostToRotError::MagicMismatch);
    }

    if header.version != version::V1 {
        return Err(HostToRotError::VersionMismatch);
    }

    match command {
        RotToHost::HostToRotError(e) => return Err(e),
        c => {
            if c != expected {
                return Err(HostToRotError::UnexpectedCommand);
            }
        }
    }
    Ok(leftover)
}

fn raw_serialize<F, S>(
    out: &mut [u8],
    header: &HostRotHeader,
    command: &S,
    fill_data: F,
) -> Result<usize, HubpackError>
where
    F: FnOnce(&mut [u8]) -> Result<usize, S>,
    S: Serialize,
{
    let header_len = hubpack::serialize(out, header)?;
    let mut n = header_len;

    let out_data_end = out.len();

    n += hubpack::serialize(&mut out[n..out_data_end], command)?;

    match fill_data(&mut out[n..out_data_end]) {
        Ok(data_this_message) => {
            assert!(data_this_message <= out_data_end - n);
            n += data_this_message;
        }
        Err(e) => {
            n = header_len;
            n += hubpack::serialize(&mut out[n..out_data_end], &e)?;
        }
    }

    Ok(n)
}

pub fn try_serialize<F, S>(
    out: &mut [u8],
    command: &S,
    fill_data: F,
) -> Result<usize, HubpackError>
where
    F: FnOnce(&mut [u8]) -> Result<usize, S>,
    S: Serialize,
{
    let header = HostRotHeader {
        magic: ATTEST_MAGIC,
        version: version::V1,
    };

    raw_serialize(out, &header, command, fill_data)
}

pub fn serialize<F>(
    out: &mut [u8],
    command: &impl Serialize,
    fill_data: F,
) -> Result<usize, HubpackError>
where
    F: FnOnce(&mut [u8]) -> usize,
{
    let header = HostRotHeader {
        magic: ATTEST_MAGIC,
        version: version::V1,
    };

    raw_serialize(out, &header, command, |buf| Ok(fill_data(buf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_to_rot_cmd() {
        let mut out = [0; 3];

        let command: [HostToRotCommand; 3] = [
            HostToRotCommand::GetCertificates,
            HostToRotCommand::GetMeasurementLog,
            HostToRotCommand::Attest,
        ];

        let expected = vec![0, 1, 2];

        let n = hubpack::serialize(&mut out, &command).unwrap();
        assert_eq!(
            expected,
            &out[..n],
            "incorrect serialization for HostToRotCommand"
        );
    }

    #[test]
    fn host_to_rot_error() {
        let mut out = [0; 4];

        let command: [(HostToRotError, [u8; 4]); 37] = [
            (HostToRotError::_Unused, [0, 0, 0, 0]),
            (HostToRotError::MagicMismatch, [1, 0, 0, 0]),
            (HostToRotError::VersionMismatch, [2, 0, 0, 0]),
            (HostToRotError::Deserialize, [3, 0, 0, 0]),
            (HostToRotError::IncorrectDataLen, [4, 0, 0, 0]),
            (HostToRotError::UnexpectedCommand, [5, 0, 0, 0]),
            (
                HostToRotError::SprotError(RecvSprotError::ProtocolInvalidCrc),
                [6, 0, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::ProtocolFlowError),
                [6, 1, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolUnsupportedProtocol,
                ),
                [6, 2, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolBadMessageType,
                ),
                [6, 3, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolBadMessageLength,
                ),
                [6, 4, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolCannotAssertCSn,
                ),
                [6, 5, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::ProtocolTimeout),
                [6, 6, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolDeserialization,
                ),
                [6, 7, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolRotIrqRemainsAsserted,
                ),
                [6, 8, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolUnexpectedResponse,
                ),
                [6, 9, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolBadUpdateStatus,
                ),
                [6, 10, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolTaskRestarted,
                ),
                [6, 11, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::ProtocolDesynchronized,
                ),
                [6, 12, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::SpiBadTransferSize),
                [6, 13, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::SpiTaskRestarted),
                [6, 14, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::UpdateError),
                [6, 15, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::SprocketsError),
                [6, 16, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::WatchdogError),
                [6, 17, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::AttestCertTooBig),
                [6, 18, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::AttestInvalidCertIndex,
                ),
                [6, 19, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::AttestNoCerts),
                [6, 20, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::AttestOutOfRange),
                [6, 21, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::AttestLogFull),
                [6, 22, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::AttestLogTooBig),
                [6, 23, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::AttestTaskRestarted),
                [6, 24, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::AttestBadLease),
                [6, 25, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::AttestUnsupportedAlgorithm,
                ),
                [6, 26, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::AttestSerializeLog),
                [6, 27, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::AttestSerializeSignature,
                ),
                [6, 28, 0, 0],
            ),
            (
                HostToRotError::SprotError(
                    RecvSprotError::AttestSignatureTooBig,
                ),
                [6, 29, 0, 0],
            ),
            (
                HostToRotError::SprotError(RecvSprotError::CommsBufTooSmall),
                [6, 30, 0, 0],
            ),
        ];

        for (c, e) in command {
            let n = hubpack::serialize(&mut out, &c).unwrap();

            assert_eq!(&e[..n], &out[..n], "incorrect serialization on {c:?}");
        }
    }

    #[test]
    fn rot_to_host_result() {
        let mut out = [0; 4];

        let command: [(RotToHost, [u8; 4]); 4] = [
            // The HostToRotErrors are tested elsewhere
            (
                RotToHost::HostToRotError(HostToRotError::_Unused),
                [0, 0, 0, 0],
            ),
            (RotToHost::RotCertificates, [1, 0, 0, 0]),
            (RotToHost::RotMeasurementLog, [2, 0, 0, 0]),
            (RotToHost::RotAttestation, [3, 0, 0, 0]),
        ];

        for (c, e) in command {
            let n = hubpack::serialize(&mut out, &c).unwrap();

            assert_eq!(&e[..n], &out[..n], "incorrect serialization on {c:?}");
        }
    }

    #[test]
    fn host_to_rot_messages() {
        // Test bad magic
        let bad_magic =
            [0x1, 0x2, 0x3, 0x4, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0];

        assert_eq!(
            parse_message(&bad_magic),
            Err(HostToRotError::MagicMismatch)
        );

        // Test bad version -- right now we only support v1
        let bad_version = [
            0x00, 0x57, 0x7e, 0xa7, 0xff, 0xff, 0xff, 0xff, 0x1, 0x0, 0x0, 0x0,
        ];

        assert_eq!(
            parse_message(&bad_version),
            Err(HostToRotError::VersionMismatch)
        );

        // Test wrong data len
        let bad_get_cert = [
            0x00, 0x57, 0x7e, 0xa7, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0,
        ];

        assert_eq!(
            parse_message(&bad_get_cert),
            Err(HostToRotError::IncorrectDataLen)
        );

        let bad_get_cert = [
            0x00, 0x57, 0x7e, 0xa7, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0,
        ];

        assert_eq!(
            parse_message(&bad_get_cert),
            Err(HostToRotError::IncorrectDataLen)
        );

        let bad_get_cert = [
            0x00, 0x57, 0x7e, 0xa7, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0,
        ];

        assert_eq!(
            parse_message(&bad_get_cert),
            Err(HostToRotError::IncorrectDataLen)
        );
    }

    #[test]
    fn rot_to_host_messages() {
        // Test bad magic
        let bad_magic =
            [0x1, 0x2, 0x3, 0x4, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0];

        assert_eq!(
            parse_response(&bad_magic, RotToHost::RotAttestation),
            Err(HostToRotError::MagicMismatch)
        );

        // Test bad version -- right now we only support v1
        let bad_version = [
            0x00, 0x57, 0x7e, 0xa7, 0xff, 0xff, 0xff, 0xff, 0x1, 0x0, 0x0, 0x0,
        ];

        assert_eq!(
            parse_response(&bad_version, RotToHost::RotAttestation),
            Err(HostToRotError::VersionMismatch)
        );

        // didn't get the command we expected
        let bad_version = [
            0x00, 0x57, 0x7e, 0xa7, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
        ];

        assert_eq!(
            parse_response(&bad_version, RotToHost::RotAttestation),
            Err(HostToRotError::UnexpectedCommand)
        );
    }

    #[test]
    fn round_trip() {
        // GetCertificates
        let mut out: [u8; MAX_REQUEST_SIZE] = [0; MAX_REQUEST_SIZE];
        let n = serialize(&mut out, &HostToRotCommand::GetCertificates, |_| 0)
            .unwrap();
        assert_eq!(
            parse_message(&out[..n]),
            Ok((HostToRotCommand::GetCertificates, [].as_slice()))
        );

        // GetMeasurementLog
        let n =
            serialize(&mut out, &HostToRotCommand::GetMeasurementLog, |_| 0)
                .unwrap();
        assert_eq!(
            parse_message(&out[..n]),
            Ok((HostToRotCommand::GetMeasurementLog, [].as_slice()))
        );

        // Attest
        let n = serialize(&mut out, &HostToRotCommand::Attest, |_| 32).unwrap();
        assert_eq!(
            parse_message(&out[..n]),
            Ok((HostToRotCommand::Attest, [0; 32].as_slice()))
        );

        // Responses
        let n =
            serialize(&mut out, &RotToHost::RotCertificates, |_| 32).unwrap();
        assert_eq!(
            parse_response(&out[..n], RotToHost::RotCertificates),
            Ok([0; 32].as_slice())
        );

        // GetMeasurementLog
        let n =
            serialize(&mut out, &RotToHost::RotMeasurementLog, |_| 32).unwrap();
        assert_eq!(
            parse_response(&out[..n], RotToHost::RotMeasurementLog),
            Ok([0; 32].as_slice())
        );

        // Attest
        let n =
            serialize(&mut out, &RotToHost::RotAttestation, |_| 32).unwrap();
        assert_eq!(
            parse_response(&out[..n], RotToHost::RotAttestation),
            Ok([0; 32].as_slice())
        );
    }
}
