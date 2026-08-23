use secretctl_domain::BrowserSessionId;

pub struct BrowserGateway {
    pub session_id: BrowserSessionId,
    pub listening_addr: String,
}

impl BrowserGateway {
    pub fn new(session_id: BrowserSessionId, listening_addr: String) -> Self {
        Self {
            session_id,
            listening_addr,
        }
    }
}
