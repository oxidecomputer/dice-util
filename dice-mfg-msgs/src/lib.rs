#![cfg_attr(not(test), no_std)]

use hubpack::SerializedSize;
//use serde_big_array::BigArray;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize, SerializedSize)]
pub struct CommsCheck(pub [u8; 32]);

// large variants in enum is intentional: this is how we do serialization
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Deserialize, Serialize, SerializedSize)]
pub enum Msgs {
    Break,
    HowYouDoin(CommsCheck),
    NotGreat,
    NotBad,
}

#[derive(Debug, PartialEq, Deserialize, Serialize, SerializedSize)]
pub struct Msg {
    pub id: u32,
    pub msg: Msgs,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    Decode,
    Deserialize,
    Serialize,
}

impl Msg {
    pub const MAX_ENCODED_SIZE: usize =
        corncobs::max_encoded_len(Msg::MAX_SIZE);

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut buf = [0u8; Msg::MAX_SIZE];

        let size =
            corncobs::decode_buf(data, &mut buf).map_err(|_| Error::Decode)?;
        let (msg, _) = hubpack::deserialize::<Msg>(&buf[..size])
            .map_err(|_| Error::Deserialize)?;

        Ok(msg)
    }

    pub fn encode(
        &self,
        dst: &mut [u8; Msg::MAX_ENCODED_SIZE],
    ) -> Result<usize, Error> {
        let mut buf = [0xFFu8; Msg::MAX_ENCODED_SIZE];

        let size =
            hubpack::serialize(&mut buf, self).map_err(|_| Error::Serialize)?;

        Ok(corncobs::encode_buf(&buf[..size], dst))
    }
}
