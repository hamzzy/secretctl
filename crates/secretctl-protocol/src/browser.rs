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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SafeLocator {
    Css { value: String },
    TestId { value: String },
}

impl SafeLocator {
    pub fn css(&self) -> Result<String, &'static str> {
        let value = match self {
            Self::Css { value } => value.clone(),
            Self::TestId { value } => format!("[data-testid={}]", css_string(value)?),
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
