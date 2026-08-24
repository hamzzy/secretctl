use bytes::BytesMut;
use secretctl_native_host::framing::ChromeNativeMessagingCodec;
use secretctl_protocol::LengthPrefixedCodec;
use tokio_util::codec::{Decoder, Encoder};

#[test]
fn test_framing_conversion_le_to_be() {
    let mut chrome_codec = ChromeNativeMessagingCodec;
    let mut broker_codec = LengthPrefixedCodec::for_executor();

    let json_payload =
        b"{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"executor.prepare\"}".to_vec();

    // 1. Chrome encodes as 32-bit Little Endian
    let mut chrome_buf = BytesMut::new();
    chrome_codec
        .encode(json_payload.clone(), &mut chrome_buf)
        .unwrap();

    // 2. Decode from Chrome buffer
    let decoded_from_chrome = chrome_codec.decode(&mut chrome_buf).unwrap().unwrap();
    assert_eq!(decoded_from_chrome, json_payload);

    // 3. Broker encodes as 32-bit Big Endian
    let mut broker_buf = BytesMut::new();
    broker_codec
        .encode(decoded_from_chrome, &mut broker_buf)
        .unwrap();

    // 4. Decode on broker side
    let decoded_on_broker = broker_codec.decode(&mut broker_buf).unwrap().unwrap();
    assert_eq!(decoded_on_broker, json_payload);
}
