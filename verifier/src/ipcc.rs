// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{
    messages::{HostToRotCommand, RotToHost},
    Attestation, Log, Nonce, Nonce32,
};
pub use libipcc::IpccError;
use libipcc::{IpccHandle, IPCC_MAX_DATA_SIZE};
use x509_cert::{
    der::{self, Decode, Encode, Reader},
    Certificate, PkiPath,
};

use crate::{Attest, AttestError};

/// The `AttestIpcc` type communicates with the RoT `Attest` task through the
/// IPCC interface / <https://github.com/oxidecomputer/ipcc-rs>.
///
/// The actual handle to the IPCC interface is created and released on-demand.
pub struct AttestIpcc {}

impl AttestIpcc {
    /// Creates a new `Ipcc` instance.
    pub fn new() -> Self {
        Self {}
    }

    // Doing an actual RoT request is mildly interesting, so this is a function to
    // describe the interestingness once.
    async fn do_rot_request(
        &self,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, IpccError> {
        // `spawn_blocking` for the request because it is possible the RoT is
        // otherwise occupied and opening or doing the request will
        // synchronously block for some amount of time.
        let req = tokio::task::spawn_blocking(move || {
            let handle = IpccHandle::new()?;
            let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
            let len = handle.rot_request(message.as_slice(), &mut rot_resp)?;
            rot_resp.truncate(len);
            Ok(rot_resp)
        });
        req.await
            .expect("handle is not aborted, and we propagate panics")
    }
}

#[async_trait::async_trait]
impl Attest for AttestIpcc {
    async fn get_measurement_log(&self) -> Result<Log, AttestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetMeasurementLog,
            |_| 0,
        )
        .map_err(AttestError::Serialize)?;
        rot_message.truncate(len);
        let rot_resp = self.do_rot_request(rot_message).await?;
        let data = attest_data::messages::parse_response(
            &rot_resp,
            RotToHost::RotMeasurementLog,
        )
        .map_err(AttestError::HostToRot)?;

        let (log, _): (Log, _) =
            hubpack::deserialize(data).map_err(AttestError::Deserialize)?;

        Ok(log)
    }

    async fn get_certificates(&self) -> Result<PkiPath, AttestError> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetCertificates,
            |_| 0,
        )
        .map_err(AttestError::Serialize)?;
        rot_message.truncate(len);
        let rot_resp = self.do_rot_request(rot_message).await?;
        let cert_chain_bytes = attest_data::messages::parse_response(
            &rot_resp,
            RotToHost::RotCertificates,
        )
        .map_err(AttestError::HostToRot)?;

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

    async fn attest(&self, nonce: &Nonce) -> Result<Attestation, AttestError> {
        let nonce: &Nonce32 = nonce.try_into()?;
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::Attest,
            |buf| {
                buf[..Nonce32::LENGTH].copy_from_slice(nonce.as_ref());
                Nonce32::LENGTH
            },
        )
        .map_err(AttestError::Serialize)?;
        rot_message.truncate(len);
        let rot_resp = self.do_rot_request(rot_message).await?;
        let data = attest_data::messages::parse_response(
            &rot_resp,
            RotToHost::RotAttestation,
        )
        .map_err(AttestError::HostToRot)?;

        let (attestation, _): (Attestation, _) =
            hubpack::deserialize(data).map_err(AttestError::Deserialize)?;

        Ok(attestation)
    }
}
