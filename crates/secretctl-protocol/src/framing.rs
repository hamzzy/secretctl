use crate::error::ProtocolError;
use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

pub const DEFAULT_MAX_AGENT_PAYLOAD_BYTES: usize = 1024 * 1024; // 1 MiB
pub const DEFAULT_MAX_EXECUTOR_PAYLOAD_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

pub struct LengthPrefixedCodec {
    max_payload_bytes: usize,
}

impl LengthPrefixedCodec {
    pub fn new(max_payload_bytes: usize) -> Self {
        Self { max_payload_bytes }
    }

    pub fn for_agent() -> Self {
        Self::new(DEFAULT_MAX_AGENT_PAYLOAD_BYTES)
    }

    pub fn for_executor() -> Self {
        Self::new(DEFAULT_MAX_EXECUTOR_PAYLOAD_BYTES)
    }
}

impl Decoder for LengthPrefixedCodec {
    type Item = Vec<u8>;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length > self.max_payload_bytes {
            return Err(ProtocolError::MessageTooLarge {
                limit: self.max_payload_bytes,
                actual: length,
            });
        }

        if src.len() < 4 + length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        src.advance(4);
        let data = src.split_to(length).to_vec();
        Ok(Some(data))
    }
}

impl Encoder<Vec<u8>> for LengthPrefixedCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.len() > self.max_payload_bytes {
            return Err(ProtocolError::MessageTooLarge {
                limit: self.max_payload_bytes,
                actual: item.len(),
            });
        }

        dst.reserve(4 + item.len());
        dst.put_u32(item.len() as u32);
        dst.put_slice(&item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_roundtrip() {
        let mut codec = LengthPrefixedCodec::for_agent();
        let mut buffer = BytesMut::new();

        let payload = b"{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"ping\"}".to_vec();
        codec.encode(payload.clone(), &mut buffer).unwrap();

        let decoded = codec
            .decode(&mut buffer)
            .unwrap()
            .expect("should decode frame");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_oversize_payload_rejected() {
        let mut codec = LengthPrefixedCodec::new(10);
        let mut buffer = BytesMut::new();

        let payload = vec![0u8; 20];
        assert!(codec.encode(payload, &mut buffer).is_err());
    }
}
