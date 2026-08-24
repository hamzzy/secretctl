use crate::cdp_filter::CdpFilter;
use crate::error::GatewayError;
use secretctl_domain::BrowserSessionId;
use serde_json::Value;
use std::sync::Arc;

pub struct BrowserGateway {
    pub session_id: BrowserSessionId,
    pub filter: Arc<CdpFilter>,
    pub listening_addr: String,
}

impl BrowserGateway {
    pub fn new(session_id: BrowserSessionId, listening_addr: impl Into<String>) -> Self {
        Self {
            session_id,
            filter: Arc::new(CdpFilter::new()),
            listening_addr: listening_addr.into(),
        }
    }

    pub fn process_cdp_command(
        &self,
        method: &str,
        tab_id: Option<u32>,
    ) -> Result<(), GatewayError> {
        self.filter.validate_cdp_command(method, tab_id)
    }

    pub fn process_cdp_response(&self, method: &str, payload: &mut Value) {
        self.filter.sanitize_cdp_response(method, payload);
    }
}
