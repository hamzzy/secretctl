use secretctl_domain::BrowserSessionId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserSessionParams {
    pub session_id: BrowserSessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserTabParams {
    pub session_id: BrowserSessionId,
    pub tab_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserNavigateParams {
    pub session_id: BrowserSessionId,
    pub tab_id: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserOpenTabParams {
    pub session_id: BrowserSessionId,
    #[serde(default = "default_blank_url")]
    pub url: String,
}

fn default_blank_url() -> String {
    "about:blank".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageLocatorParams {
    pub session_id: BrowserSessionId,
    pub tab_id: String,
    pub locator: SafeLocator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageTypePublicParams {
    pub session_id: BrowserSessionId,
    pub tab_id: String,
    pub locator: SafeLocator,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSelectParams {
    pub session_id: BrowserSessionId,
    pub tab_id: String,
    pub locator: SafeLocator,
    pub label: String,
}

/// How an agent names an element.
///
/// `Ref` is the intended path: `page.snapshot_safe` hands back opaque
/// references, and the agent acts on what it was shown. `Role` and `Text`
/// exist so an agent can name a control the way a person would. `Css` and
/// `TestId` remain for callers that already know the page.
///
/// No variant accepts JavaScript, an XPath, or a node handle. A locator is a
/// description the broker resolves; it is never an expression the agent gets
/// to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SafeLocator {
    Css {
        value: String,
    },
    TestId {
        value: String,
    },
    /// A reference previously returned by `page.snapshot_safe`.
    Ref {
        value: String,
    },
    /// Exactly one element with this role and accessible name.
    Role {
        role: String,
        name: String,
    },
    /// Exactly one element with this accessible name, any role.
    Text {
        value: String,
    },
}

impl SafeLocator {
    /// Whether this locator is resolved by CSS selection or by projecting the
    /// page and matching against it.
    pub fn is_css_based(&self) -> bool {
        matches!(self, Self::Css { .. } | Self::TestId { .. })
    }

    pub fn css(&self) -> Result<String, &'static str> {
        let value = match self {
            Self::Css { value } => value.clone(),
            Self::TestId { value } => format!("[data-testid={}]", css_string(value)?),
            _ => return Err("locator is not selector-based"),
        };
        if value.is_empty()
            || value.len() > 512
            || value.contains(":has(")
            || value.contains("input[type=password]")
            || value.contains("[type=password]")
        {
            return Err("unsafe locator");
        }
        Ok(value)
    }
}

fn css_string(value: &str) -> Result<String, &'static str> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
    {
        return Err("unsafe test ID");
    }
    Ok(format!("\"{value}\""))
}

/// Bounded read of a page's visible text.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageReadTextParams {
    pub session_id: BrowserSessionId,
    pub tab_id: String,
    /// Restrict the read to one element's subtree. Absent reads the document.
    #[serde(default)]
    pub locator: Option<SafeLocator>,
    #[serde(default)]
    pub max_chars: Option<usize>,
}

/// Bounded structural view of a page's interactable elements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSnapshotParams {
    pub session_id: BrowserSessionId,
    pub tab_id: String,
    #[serde(default)]
    pub max_nodes: Option<usize>,
    /// Confirm layout visibility through the box model. Costs one round trip
    /// per element, so it is capped and defaults on.
    #[serde(default)]
    pub check_visibility: Option<bool>,
}

/// Conditions the broker will poll for on the agent's behalf.
///
/// Polling happens inside the broker rather than as an agent retry loop so the
/// wait is bounded, auditable, and cannot become a navigation hammer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WaitCondition {
    LocatorPresent { locator: SafeLocator },
    LocatorAbsent { locator: SafeLocator },
    TextPresent { value: String },
    UrlPrefix { value: String },
    UrlChangedFrom { value: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageWaitForParams {
    pub session_id: BrowserSessionId,
    pub tab_id: String,
    pub condition: WaitCondition,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_based_locators_reject_password_targeting() {
        let locator = SafeLocator::Css {
            value: "input[type=password]".to_string(),
        };
        assert!(locator.css().is_err());
    }

    #[test]
    fn projection_locators_have_no_css_form() {
        // A role locator must never be coerced into a selector: that would
        // reintroduce agent-authored selection through the back door.
        let locator = SafeLocator::Role {
            role: "button".to_string(),
            name: "Sign in".to_string(),
        };
        assert!(!locator.is_css_based());
        assert!(locator.css().is_err());
    }

    #[test]
    fn unknown_locator_fields_are_rejected() {
        let raw = r#"{"kind":"role","role":"button","name":"Go","script":"alert(1)"}"#;
        assert!(serde_json::from_str::<SafeLocator>(raw).is_err());
    }

    #[test]
    fn unknown_locator_kinds_are_rejected() {
        let raw = r#"{"kind":"xpath","value":"//input"}"#;
        assert!(serde_json::from_str::<SafeLocator>(raw).is_err());
    }
}
