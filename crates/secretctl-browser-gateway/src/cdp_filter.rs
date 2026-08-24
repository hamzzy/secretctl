use crate::error::GatewayError;
use secretctl_crypto::contains_prohibited_key_name;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::RwLock;

const PROHIBITED_CDP_METHODS: &[&str] = &[
    "Runtime.evaluate",
    "Runtime.callFunctionOn",
    "Network.getAllCookies",
    "Network.getCookies",
    "Network.setCookie",
    "Network.deleteCookies",
    "Storage.getCookies",
    "Storage.setCookies",
    "Storage.clearDataForOrigin",
    "DOMStorage.getDOMStorageItems",
    "IndexedDB.requestData",
    "IndexedDB.requestDatabaseNames",
    "Network.getResponseBody",
    "Network.getRequestPostData",
    "DOM.getOuterHTML",
    "Browser.getBrowserCommandLine",
    "Browser.setDownloadBehavior",
    "Page.setDownloadBehavior",
];

const ALLOWED_CDP_METHODS: &[&str] = &[
    "Browser.getVersion",
    "Extensions.getExtensions",
    "Extensions.loadUnpacked",
    "DOM.describeNode",
    "DOM.getBoxModel",
    "DOM.getDocument",
    "DOM.querySelector",
    "DOM.querySelectorAll",
    "DOM.focus",
    "Input.dispatchKeyEvent",
    "Input.dispatchMouseEvent",
    "Input.insertText",
    "Page.getNavigationHistory",
    "Page.navigate",
    "Page.navigateToHistoryEntry",
    "Page.reload",
    "Page.stopLoading",
    "Target.activateTarget",
    "Target.closeTarget",
    "Target.createTarget",
    "Target.getTargets",
    "Target.attachToTarget",
];

const SENSITIVE_WINDOW_BLOCKED_METHODS: &[&str] = &[
    "Page.captureScreenshot",
    "Page.startScreencast",
    "Page.printToPDF",
    "DOMSnapshot.captureSnapshot",
    "Accessibility.getFullAXTree",
    "Accessibility.getRootAXNode",
    "Tracing.start",
];

const REDACTED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
];

pub struct CdpFilter {
    active_sensitive_tabs: RwLock<HashSet<u32>>,
}

impl CdpFilter {
    pub fn new() -> Self {
        Self {
            active_sensitive_tabs: RwLock::new(HashSet::new()),
        }
    }

    pub fn enter_sensitive_window(&self, tab_id: u32) {
        let mut tabs = self.active_sensitive_tabs.write().unwrap();
        tabs.insert(tab_id);
    }

    pub fn exit_sensitive_window(&self, tab_id: u32) {
        let mut tabs = self.active_sensitive_tabs.write().unwrap();
        tabs.remove(&tab_id);
    }

    pub fn is_tab_in_sensitive_window(&self, tab_id: u32) -> bool {
        let tabs = self.active_sensitive_tabs.read().unwrap();
        tabs.contains(&tab_id)
    }

    pub fn has_sensitive_window(&self) -> bool {
        !self.active_sensitive_tabs.read().unwrap().is_empty()
    }

    pub fn validate_cdp_command(
        &self,
        method: &str,
        tab_id: Option<u32>,
    ) -> Result<(), GatewayError> {
        // 1. Check globally prohibited methods
        for &prohibited in PROHIBITED_CDP_METHODS {
            if method == prohibited
                || method.starts_with("Storage.")
                || method.starts_with("DOMStorage.")
                || method.starts_with("IndexedDB.")
            {
                return Err(GatewayError::CommandDenied(format!(
                    "CDP method '{}' is prohibited by secretctl security policy",
                    method
                )));
            }
        }

        if !ALLOWED_CDP_METHODS.contains(&method)
            && !SENSITIVE_WINDOW_BLOCKED_METHODS.contains(&method)
        {
            return Err(GatewayError::CommandDenied(format!(
                "Unknown CDP method '{}' is denied by default",
                method
            )));
        }

        // 2. Check sensitive window restrictions
        if tab_id.is_some_and(|tid| self.is_tab_in_sensitive_window(tid))
            || (tab_id.is_none() && self.has_sensitive_window())
        {
            for &blocked in SENSITIVE_WINDOW_BLOCKED_METHODS {
                if method == blocked {
                    return Err(GatewayError::SensitiveWindowBlocked(format!(
                        "CDP method '{}' is blocked during an active authentication window",
                        method
                    )));
                }
            }
        }

        Ok(())
    }

    pub fn sanitize_cdp_response(&self, method: &str, payload: &mut Value) {
        match method {
            "Network.requestWillBeSent" | "Network.responseReceived" => {
                Self::sanitize_network_headers(payload);
            }
            "DOM.getOuterHTML" | "DOM.getDocument" | "DOMSnapshot.captureSnapshot" => {
                Self::sanitize_dom_nodes(payload);
            }
            _ => {
                Self::sanitize_generic_json(payload);
            }
        }
    }

    fn sanitize_network_headers(payload: &mut Value) {
        if let Some(req_headers) = payload.pointer_mut("/params/request/headers") {
            if let Some(obj) = req_headers.as_object_mut() {
                for &redacted in REDACTED_HEADERS {
                    for (k, v) in obj.iter_mut() {
                        if k.to_ascii_lowercase() == redacted {
                            *v = Value::String("[REDACTED_BY_SECRETCTL]".to_string());
                        }
                    }
                }
            }
        }
        if let Some(resp_headers) = payload.pointer_mut("/params/response/headers") {
            if let Some(obj) = resp_headers.as_object_mut() {
                for &redacted in REDACTED_HEADERS {
                    for (k, v) in obj.iter_mut() {
                        if k.to_ascii_lowercase() == redacted {
                            *v = Value::String("[REDACTED_BY_SECRETCTL]".to_string());
                        }
                    }
                }
            }
        }
    }

    fn sanitize_dom_nodes(payload: &mut Value) {
        match payload {
            Value::Object(map) => {
                if let Some(node_name) = map.get("nodeName").and_then(|v| v.as_str()) {
                    if node_name.eq_ignore_ascii_case("INPUT") {
                        if let Some(attrs) =
                            map.get_mut("attributes").and_then(|v| v.as_array_mut())
                        {
                            let mut is_password = false;
                            for chunk in attrs.chunks(2) {
                                if chunk.len() == 2
                                    && chunk[0].as_str() == Some("type")
                                    && chunk[1].as_str() == Some("password")
                                {
                                    is_password = true;
                                    break;
                                }
                            }
                            if is_password {
                                if let Some(val) = map.get_mut("nodeValue") {
                                    *val = Value::String("[REDACTED]".to_string());
                                }
                            }
                        }
                    }
                }
                for (_, v) in map.iter_mut() {
                    Self::sanitize_dom_nodes(v);
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    Self::sanitize_dom_nodes(item);
                }
            }
            _ => {}
        }
    }

    fn sanitize_generic_json(payload: &mut Value) {
        match payload {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    let k_lower = k.to_ascii_lowercase();
                    if contains_prohibited_key_name(&k_lower) {
                        *v = Value::String("[REDACTED]".to_string());
                    } else {
                        Self::sanitize_generic_json(v);
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    Self::sanitize_generic_json(item);
                }
            }
            _ => {}
        }
    }
}

impl Default for CdpFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdp_filter_blocks_cookies() {
        let filter = CdpFilter::new();
        assert!(
            filter
                .validate_cdp_command("Network.getAllCookies", None)
                .is_err()
        );
        assert!(
            filter
                .validate_cdp_command("Storage.getCookies", None)
                .is_err()
        );
        assert!(filter.validate_cdp_command("Page.navigate", None).is_ok());
        assert!(
            filter
                .validate_cdp_command("Runtime.evaluate", None)
                .is_err()
        );
        assert!(
            filter
                .validate_cdp_command("Network.getResponseBody", None)
                .is_err()
        );
        assert!(
            filter
                .validate_cdp_command("MadeUp.readSecrets", None)
                .is_err()
        );
    }

    #[test]
    fn test_sensitive_window_blocks_screenshots() {
        let filter = CdpFilter::new();
        let tab_id = 42;

        // Outside sensitive window -> screenshot allowed
        assert!(
            filter
                .validate_cdp_command("Page.captureScreenshot", Some(tab_id))
                .is_ok()
        );

        // Inside sensitive window -> screenshot blocked!
        filter.enter_sensitive_window(tab_id);
        assert!(
            filter
                .validate_cdp_command("Page.captureScreenshot", Some(tab_id))
                .is_err()
        );

        filter.exit_sensitive_window(tab_id);
        assert!(
            filter
                .validate_cdp_command("Page.captureScreenshot", Some(tab_id))
                .is_ok()
        );
    }

    #[test]
    fn test_redact_authorization_headers() {
        let filter = CdpFilter::new();
        let mut json = serde_json::json!({
            "params": {
                "request": {
                    "headers": {
                        "Authorization": "Bearer secret-token-xyz",
                        "Accept": "text/html"
                    }
                }
            }
        });

        filter.sanitize_cdp_response("Network.requestWillBeSent", &mut json);
        let auth_val = json
            .pointer("/params/request/headers/Authorization")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(auth_val, "[REDACTED_BY_SECRETCTL]");
    }
}
