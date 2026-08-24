use secretctl_browser_gateway::cdp_filter::CdpFilter;
use serde_json::json;

#[test]
fn test_cdp_side_channel_denials() {
    let filter = CdpFilter::new();

    // Storage and cookie extraction methods denied
    assert!(filter.validate_cdp_command("Network.getAllCookies", None).is_err());
    assert!(filter.validate_cdp_command("Network.getCookies", None).is_err());
    assert!(filter.validate_cdp_command("Storage.getCookies", None).is_err());
    assert!(filter.validate_cdp_command("DOMStorage.getDOMStorageItems", None).is_err());
    assert!(filter.validate_cdp_command("IndexedDB.requestData", None).is_err());

    // Normal navigation/input allowed outside sensitive window
    assert!(filter.validate_cdp_command("Page.navigate", None).is_ok());
    assert!(filter.validate_cdp_command("Input.dispatchMouseEvent", None).is_ok());
}

#[test]
fn test_sensitive_window_isolation() {
    let filter = CdpFilter::new();
    let tab_id = 99;

    // Before sensitive window
    assert!(filter.validate_cdp_command("Page.captureScreenshot", Some(tab_id)).is_ok());
    assert!(filter.validate_cdp_command("Accessibility.getFullAXTree", Some(tab_id)).is_ok());

    // Enter sensitive window during credential injection
    filter.enter_sensitive_window(tab_id);
    assert!(filter.validate_cdp_command("Page.captureScreenshot", Some(tab_id)).is_err());
    assert!(filter.validate_cdp_command("Page.startScreencast", Some(tab_id)).is_err());
    assert!(filter.validate_cdp_command("Accessibility.getFullAXTree", Some(tab_id)).is_err());
    assert!(filter.validate_cdp_command("DOMSnapshot.captureSnapshot", Some(tab_id)).is_err());

    // Exit sensitive window
    filter.exit_sensitive_window(tab_id);
    assert!(filter.validate_cdp_command("Page.captureScreenshot", Some(tab_id)).is_ok());
}

#[test]
fn test_header_and_cookie_redaction() {
    let filter = CdpFilter::new();
    let mut payload = json!({
        "params": {
            "request": {
                "headers": {
                    "Authorization": "Bearer sensitive-jwt-token-12345",
                    "Cookie": "session_id=secret_session_abc",
                    "User-Agent": "Mozilla/5.0"
                }
            }
        }
    });

    filter.sanitize_cdp_response("Network.requestWillBeSent", &mut payload);

    let auth_header = payload.pointer("/params/request/headers/Authorization").unwrap().as_str().unwrap();
    let cookie_header = payload.pointer("/params/request/headers/Cookie").unwrap().as_str().unwrap();
    let ua_header = payload.pointer("/params/request/headers/User-Agent").unwrap().as_str().unwrap();

    assert_eq!(auth_header, "[REDACTED_BY_SECRETCTL]");
    assert_eq!(cookie_header, "[REDACTED_BY_SECRETCTL]");
    assert_eq!(ua_header, "Mozilla/5.0");
}
