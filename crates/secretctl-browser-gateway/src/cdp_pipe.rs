use crate::{CdpFilter, GatewayError};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const MAX_CDP_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct CdpPipe {
    reader: Arc<Mutex<BufReader<Box<dyn Read + Send>>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    next_id: Arc<AtomicU64>,
}

impl CdpPipe {
    pub fn new(reader: impl Read + Send + 'static, writer: impl Write + Send + 'static) -> Self {
        Self {
            reader: Arc::new(Mutex::new(BufReader::new(Box::new(reader)))),
            writer: Arc::new(Mutex::new(Box::new(writer))),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn request(
        &self,
        filter: &CdpFilter,
        method: &str,
        tab_id: Option<u32>,
        params: Value,
    ) -> Result<Value, GatewayError> {
        self.request_with_session(filter, method, tab_id, None, params)
    }

    pub fn request_with_session(
        &self,
        filter: &CdpFilter,
        method: &str,
        tab_id: Option<u32>,
        session_id: Option<&str>,
        params: Value,
    ) -> Result<Value, GatewayError> {
        filter.validate_cdp_command(method, tab_id)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut command = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        if let Some(session_id) = session_id {
            command["sessionId"] = Value::String(session_id.to_string());
        }
        let message = serde_json::to_vec(&command)?;
        if message.len() > MAX_CDP_MESSAGE_BYTES {
            return Err(GatewayError::Transport(
                "CDP command exceeds limit".to_string(),
            ));
        }
        {
            let mut writer = self
                .writer
                .lock()
                .map_err(|_| GatewayError::Transport("CDP writer lock poisoned".to_string()))?;
            writer.write_all(&message)?;
            writer.write_all(&[0])?;
            writer.flush()?;
        }

        loop {
            let mut frame = Vec::new();
            let bytes_read = self
                .reader
                .lock()
                .map_err(|_| GatewayError::Transport("CDP reader lock poisoned".to_string()))?
                .read_until(0, &mut frame)?;
            if bytes_read == 0 {
                return Err(GatewayError::ProcessTerminated);
            }
            if frame.len() > MAX_CDP_MESSAGE_BYTES + 1 {
                return Err(GatewayError::Transport(
                    "CDP response exceeds limit".to_string(),
                ));
            }
            if frame.last() == Some(&0) {
                frame.pop();
            }
            let mut response: Value = serde_json::from_slice(&frame)?;
            let response_method = response
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or(method)
                .to_string();
            filter.sanitize_cdp_response(&response_method, &mut response);
            if response.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(error) = response.get("error") {
                    return Err(GatewayError::Transport(format!(
                        "Chrome rejected {method}: {}",
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown CDP error")
                    )));
                }
                return Ok(response.get("result").cloned().unwrap_or(Value::Null));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn pipe_frames_with_nul_and_redacts_responses() {
        let response = b"{\"id\":1,\"result\":{\"authorization\":\"canary\",\"ok\":true}}\0";
        let written = Arc::new(Mutex::new(Vec::new()));
        struct SharedWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let pipe = CdpPipe::new(Cursor::new(response), SharedWriter(written.clone()));
        let result = pipe
            .request(&CdpFilter::new(), "Browser.getVersion", None, json!({}))
            .unwrap();
        assert_eq!(result["authorization"], "[REDACTED]");
        assert_eq!(written.lock().unwrap().last(), Some(&0));
    }
}
