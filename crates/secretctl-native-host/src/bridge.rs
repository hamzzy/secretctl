use crate::framing::ChromeNativeMessagingCodec;
use futures::{SinkExt, StreamExt};
use secretctl_protocol::LengthPrefixedCodec;
use std::path::Path;
use tokio::io::{stdin, stdout};
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use tracing::{error, info};

pub async fn run_stdio_bridge(executor_sock_path: impl AsRef<Path>) -> anyhow::Result<()> {
    info!(
        "Connecting native host bridge to broker at {:?}",
        executor_sock_path.as_ref()
    );

    let socket_stream = UnixStream::connect(executor_sock_path.as_ref()).await?;
    let socket_framed = Framed::new(socket_stream, LengthPrefixedCodec::for_executor());

    let stdin_framed = Framed::new(stdin(), ChromeNativeMessagingCodec);
    let stdout_framed = Framed::new(stdout(), ChromeNativeMessagingCodec);

    let (mut socket_sink, mut socket_source) = socket_framed.split();
    let (mut chrome_sink, mut chrome_source) = (stdout_framed, stdin_framed);

    let chrome_to_broker = tokio::spawn(async move {
        while let Some(msg_res) = chrome_source.next().await {
            match msg_res {
                Ok(msg_bytes) => {
                    if let Err(e) = socket_sink.send(msg_bytes).await {
                        error!("Failed to send frame to broker: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Error reading from Chrome stdin: {}", e);
                    break;
                }
            }
        }
    });

    let broker_to_chrome = tokio::spawn(async move {
        while let Some(msg_res) = socket_source.next().await {
            match msg_res {
                Ok(msg_bytes) => {
                    if let Err(e) = chrome_sink.send(msg_bytes).await {
                        error!("Failed to send frame to Chrome stdout: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Error reading from broker socket: {}", e);
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = chrome_to_broker => {},
        _ = broker_to_chrome => {},
    }

    Ok(())
}
