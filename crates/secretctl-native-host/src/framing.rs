use bytes::{Buf, BufMut, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

pub const MAX_CHROME_MSG_BYTES: usize = 1024 * 1024; // 1 MiB

pub struct ChromeNativeMessagingCodec;

impl Decoder for ChromeNativeMessagingCodec {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        if length > MAX_CHROME_MSG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Message length {} exceeds max {}",
                    length, MAX_CHROME_MSG_BYTES
                ),
            ));
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

impl Encoder<Vec<u8>> for ChromeNativeMessagingCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.len() > MAX_CHROME_MSG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Message length {} exceeds max {}",
                    item.len(),
                    MAX_CHROME_MSG_BYTES
                ),
            ));
        }

        dst.reserve(4 + item.len());
        dst.put_u32_le(item.len() as u32);
        dst.put_slice(&item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome_native_codec_roundtrip() {
        let mut codec = ChromeNativeMessagingCodec;
        let mut buffer = BytesMut::new();
        let payload = b"{\"text\":\"hello chrome\"}".to_vec();

        codec.encode(payload.clone(), &mut buffer).unwrap();
        assert_eq!(buffer.len(), 4 + payload.len());

        let decoded = codec.decode(&mut buffer).unwrap().expect("decoded");
        assert_eq!(decoded, payload);
    }
}
