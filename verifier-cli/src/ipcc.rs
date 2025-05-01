// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Result};
use attest_data::{
    messages::{HostToRotCommand, RotToHost},
    Attestation, Log, Nonce,
};
use libipcc::IpccHandle;
use x509_cert::{
    der::{self, Decode, Encode, Reader},
    Certificate, PkiPath,
};

use crate::Attest;

// A slight hack. These are only defined right now in the `ffi` part
// of libipcc which isn't available on non-illumos targets. Probably
// indicates those constants belong elsewhere...
const IPCC_MAX_DATA_SIZE: usize = 4123 - 19;

pub struct AttestIpcc {
    handle: IpccHandle,
}

impl AttestIpcc {
    /// Creates a new `Ipcc` instance.
    pub fn new() -> Result<Self> {
        let handle =
            IpccHandle::new().map_err(|e| anyhow!("Ipcc error {}", e))?;
        Ok(Self { handle })
    }
}

impl Attest for AttestIpcc {
    fn get_measurement_log(&self) -> Result<Log> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetMeasurementLog,
            |_| 0,
        )
        .map_err(|e| anyhow!("serialize {}", e))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotMeasurementLog,
        )
        .map_err(|e| anyhow!("bad response {:?}", e))?;

        let (log, _): (Log, _) = hubpack::deserialize(data)
            .map_err(|e| anyhow!("Failed to deserialize Log: {}", e))?;

        Ok(log)
    }

    fn get_certificates(&self) -> Result<PkiPath> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetCertificates,
            |_| 0,
        )
        .map_err(|e| anyhow!("serialize {}", e))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let cert_chain_bytes = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotCertificates,
        )
        .map_err(|e| anyhow!("bad response {:?}", e))?;

        let mut idx = 0;

        let mut certs = PkiPath::new();
        // Turn the DER chain into something we can actually use
        while idx < cert_chain_bytes.len() {
            let reader = der::SliceReader::new(&cert_chain_bytes[idx..])?;
            let header = reader.peek_header()?;
            // DER certificates are supposed to be a `Sequence`.
            // We could check that here but we're going to get better
            // error messages by letting the cert parsing code say
            // exactly what went wrong
            let seq_len: usize = header.length.try_into()?;
            let tag_len: usize = header.encoded_len()?.try_into()?;
            // Total len = length from the sequence plus the tag itself
            let end = idx + seq_len + tag_len;

            certs.push(Certificate::from_der(&cert_chain_bytes[idx..end])?);
            idx += seq_len + tag_len;
        }

        Ok(certs)
    }

    fn attest(&self, nonce: &Nonce) -> Result<Attestation> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::Attest,
            |buf| {
                buf[..nonce.0.len()].copy_from_slice(nonce.as_ref());
                32
            },
        )
        .map_err(|e| anyhow!("serialize {}", e))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotAttestation,
        )
        .map_err(|e| anyhow!("bad response {:?}", e))?;

        let (attestation, _): (Attestation, _) = hubpack::deserialize(data)
            .map_err(|e| anyhow!("Failed to deserialize Attestation: {}", e))?;

        Ok(attestation)
    }
}
