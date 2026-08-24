//! Bounded structural projection of a page, computed inside the trusted broker.
//!
//! The agent is never handed a DOM. It is handed the output of this module: a
//! capped list of interactable elements and a capped run of visible text, with
//! protected subtrees elided before anything is serialized. That distinction is
//! the whole point — an agent that can see enough to operate a page must not be
//! able to see a credential that was typed into it.
//!
//! This module is deliberately pure. It takes a `DOM.getDocument` or
//! `DOM.describeNode` result and returns a projection, with no I/O and no
//! browser. That makes the redaction rules — the part that must not be wrong —
//! testable without Chrome.

use serde::Serialize;
use serde_json::Value;

/// Element roles the projection is willing to name. Anything it cannot place
/// confidently becomes `Generic`, which is never interactable.
const INTERACTABLE_ROLES: &[&str] = &[
    "link", "button", "textbox", "checkbox", "radio", "combobox",
];

/// Attribute-name fragments that mark a field as credential-bearing. Kept in
/// one place so `page.type_public`, the projection, and the executor cannot
/// drift apart about what "protected" means.
const PROTECTED_NAME_FRAGMENTS: &[&str] =
    &["password", "passwd", "otp", "totp", "secret", "token", "cvv", "cvc"];

const PROTECTED_AUTOCOMPLETE: &[&str] = &["current-password", "new-password", "one-time-code"];

/// Containers whose text is markup or metadata rather than page content.
const NON_CONTENT_TAGS: &[&str] = &["script", "style", "noscript", "template", "head", "svg"];

#[derive(Debug, Clone, Copy)]
pub struct ViewLimits {
    pub max_nodes: usize,
    pub max_chars: usize,
    pub max_name_chars: usize,
}

impl Default for ViewLimits {
    fn default() -> Self {
        Self {
            max_nodes: 100,
            max_chars: 4_000,
            max_name_chars: 120,
        }
    }
}

impl ViewLimits {
    /// Clamp caller-supplied limits into a range the broker is willing to
    /// serve. An agent cannot widen its own view by asking for more.
    pub fn clamped(max_nodes: Option<usize>, max_chars: Option<usize>) -> Self {
        let defaults = Self::default();
        Self {
            max_nodes: max_nodes.unwrap_or(defaults.max_nodes).clamp(1, 250),
            max_chars: max_chars.unwrap_or(defaults.max_chars).clamp(1, 20_000),
            max_name_chars: defaults.max_name_chars,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProjectedNode {
    /// Opaque handle the agent passes back to act on this element. Carries a
    /// digest of the element's identity so a stale handle is rejected rather
    /// than silently resolving to whatever now occupies that position.
    pub reference: String,
    pub tag: String,
    pub role: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
    /// True when this element is credential-bearing. Protected elements appear
    /// in the projection — an agent needs to know a password field exists — but
    /// never carry a name derived from their value, and never carry text.
    pub protected: bool,
    pub disabled: bool,
    /// Structural hiding only (`hidden`, `type=hidden`, `aria-hidden`, inline
    /// `display:none`). Layout-level visibility is confirmed separately by the
    /// caller through the box model; `None` means it was not checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible: Option<bool>,
    #[serde(skip)]
    pub node_id: u64,
    #[serde(skip)]
    pub structurally_hidden: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PageProjection {
    pub nodes: Vec<ProjectedNode>,
    pub text: String,
    pub text_truncated: bool,
    pub nodes_truncated: bool,
}

/// Why a locator did not resolve. Kept coarse on purpose: a locator failure
/// must not become an oracle for what a page contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    NotFound,
    Ambiguous,
    Stale,
    Protected,
}

struct Walker<'a> {
    limits: &'a ViewLimits,
    nodes: Vec<ProjectedNode>,
    text: String,
    text_truncated: bool,
    nodes_truncated: bool,
    /// Document-order index of interactables, which is what a reference names.
    interactable_index: usize,
}

impl PageProjection {
    /// Project a CDP node subtree. `node` is the `root` of a `DOM.getDocument`
    /// result or the `node` of a `DOM.describeNode` result.
    pub fn from_node(node: &Value, limits: &ViewLimits) -> Self {
        let mut walker = Walker {
            limits,
            nodes: Vec::new(),
            text: String::new(),
            text_truncated: false,
            nodes_truncated: false,
            interactable_index: 0,
        };
        walker.visit(node, false);
        let mut text = walker.text;
        // Trailing separator from the last text run carries no information.
        while text.ends_with(' ') {
            text.pop();
        }
        Self {
            nodes: walker.nodes,
            text,
            text_truncated: walker.text_truncated,
            nodes_truncated: walker.nodes_truncated,
        }
    }

    /// Resolve an agent-supplied reference back to a live node id.
    ///
    /// The reference encodes both a position and a digest of the element that
    /// occupied it. Re-projecting and checking both means a page that changed
    /// under the agent produces `Stale` rather than an action against the wrong
    /// element, which is the failure that actually matters here.
    pub fn resolve_reference(&self, reference: &str) -> Result<&ProjectedNode, ResolveError> {
        let node = self
            .nodes
            .iter()
            .find(|node| node.reference == reference)
            .ok_or(ResolveError::Stale)?;
        Ok(node)
    }

    /// Resolve a role/name locator. Exactly one match is required; ambiguity is
    /// an error rather than a first-match guess.
    pub fn resolve_role(&self, role: &str, name: &str) -> Result<&ProjectedNode, ResolveError> {
        let wanted_role = role.trim().to_ascii_lowercase();
        let wanted_name = normalize_for_match(name);
        let mut matches = self.nodes.iter().filter(|node| {
            node.role == wanted_role && normalize_for_match(&node.name) == wanted_name
        });
        let first = matches.next().ok_or(ResolveError::NotFound)?;
        if matches.next().is_some() {
            return Err(ResolveError::Ambiguous);
        }
        Ok(first)
    }

    /// Resolve by visible accessible name alone, across any role.
    pub fn resolve_text(&self, name: &str) -> Result<&ProjectedNode, ResolveError> {
        let wanted = normalize_for_match(name);
        let mut matches = self
            .nodes
            .iter()
            .filter(|node| normalize_for_match(&node.name) == wanted);
        let first = matches.next().ok_or(ResolveError::NotFound)?;
        if matches.next().is_some() {
            return Err(ResolveError::Ambiguous);
        }
        Ok(first)
    }
}

impl<'a> Walker<'a> {
    fn visit(&mut self, node: &Value, inherited_protection: bool) {
        let node_type = node.get("nodeType").and_then(Value::as_u64).unwrap_or(0);
        match node_type {
            // Text node.
            3 => {
                if !inherited_protection {
                    if let Some(value) = node.get("nodeValue").and_then(Value::as_str) {
                        self.push_text(value);
                    }
                }
                return;
            }
            // Element, document, document fragment.
            1 | 9 | 11 => {}
            // Comments, CDATA, doctype: never content.
            _ => return,
        }

        let tag = node
            .get("nodeName")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if NON_CONTENT_TAGS.contains(&tag.as_str()) {
            return;
        }

        let attributes = Attributes::from_node(node);
        let protected = inherited_protection || attributes.is_protected();

        if node_type == 1 {
            self.record_element(node, &tag, &attributes, protected);
        }

        if let Some(children) = node.get("children").and_then(Value::as_array) {
            for child in children {
                self.visit(child, protected);
            }
        }
        // A frame's document hangs off `contentDocument`, not `children`. It is
        // deliberately not descended into: cross-document text belongs to a
        // different origin, and merging it here would let an iframe's content
        // masquerade as the top page's.
    }

    fn record_element(
        &mut self,
        node: &Value,
        tag: &str,
        attributes: &Attributes,
        protected: bool,
    ) {
        let role = derive_role(tag, attributes);
        if !INTERACTABLE_ROLES.contains(&role.as_str()) {
            return;
        }
        if self.nodes.len() >= self.limits.max_nodes {
            self.nodes_truncated = true;
            return;
        }

        // A protected element never contributes a name derived from page state:
        // its value, placeholder, or label could carry the credential back out.
        let name = if protected {
            String::new()
        } else {
            truncate_chars(
                &collapse_whitespace(&accessible_name(node, tag, attributes)),
                self.limits.max_name_chars,
            )
        };
        let node_id = node.get("nodeId").and_then(Value::as_u64).unwrap_or(0);
        let index = self.interactable_index;
        self.interactable_index += 1;

        self.nodes.push(ProjectedNode {
            reference: make_reference(index, tag, &role, &name),
            tag: tag.to_string(),
            role,
            name,
            input_type: attributes.get("type").map(str::to_string),
            protected,
            disabled: attributes.has("disabled") || attributes.value_is("aria-disabled", "true"),
            visible: None,
            node_id,
            structurally_hidden: attributes.is_structurally_hidden(tag),
        });
    }

    fn push_text(&mut self, raw: &str) {
        if self.text_truncated {
            return;
        }
        let collapsed = collapse_whitespace(raw);
        if collapsed.is_empty() {
            return;
        }
        if !self.text.is_empty() && !self.text.ends_with(' ') {
            self.text.push(' ');
        }
        for character in collapsed.chars() {
            if self.text.chars().count() >= self.limits.max_chars {
                self.text_truncated = true;
                return;
            }
            self.text.push(character);
        }
    }
}

/// Flat CDP attribute array (`[name, value, name, value, ...]`) with the
/// lookups this module needs.
struct Attributes {
    pairs: Vec<(String, String)>,
}

impl Attributes {
    fn from_node(node: &Value) -> Self {
        let mut pairs = Vec::new();
        if let Some(list) = node.get("attributes").and_then(Value::as_array) {
            for chunk in list.chunks(2) {
                if let (Some(name), Some(value)) = (
                    chunk.first().and_then(Value::as_str),
                    chunk.get(1).and_then(Value::as_str),
                ) {
                    pairs.push((name.to_ascii_lowercase(), value.to_string()));
                }
            }
        }
        Self { pairs }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn has(&self, name: &str) -> bool {
        self.pairs.iter().any(|(key, _)| key == name)
    }

    fn value_is(&self, name: &str, expected: &str) -> bool {
        self.get(name)
            .is_some_and(|value| value.eq_ignore_ascii_case(expected))
    }

    /// The single definition of "this element carries credential material".
    fn is_protected(&self) -> bool {
        if self.value_is("type", "password") {
            return true;
        }
        if let Some(autocomplete) = self.get("autocomplete") {
            let autocomplete = autocomplete.to_ascii_lowercase();
            if PROTECTED_AUTOCOMPLETE
                .iter()
                .any(|candidate| autocomplete.contains(candidate))
            {
                return true;
            }
        }
        for key in ["name", "id", "data-testid"] {
            if let Some(value) = self.get(key) {
                let value = value.to_ascii_lowercase();
                if PROTECTED_NAME_FRAGMENTS
                    .iter()
                    .any(|fragment| value.contains(fragment))
                {
                    return true;
                }
            }
        }
        false
    }

    fn is_structurally_hidden(&self, tag: &str) -> bool {
        if self.has("hidden") || self.value_is("aria-hidden", "true") {
            return true;
        }
        if tag == "input" && self.value_is("type", "hidden") {
            return true;
        }
        if let Some(style) = self.get("style") {
            let style = style.to_ascii_lowercase().replace(' ', "");
            if style.contains("display:none") || style.contains("visibility:hidden") {
                return true;
            }
        }
        false
    }
}

fn derive_role(tag: &str, attributes: &Attributes) -> String {
    if let Some(explicit) = attributes.get("role") {
        let explicit = explicit.trim().to_ascii_lowercase();
        if INTERACTABLE_ROLES.contains(&explicit.as_str()) {
            return explicit;
        }
    }
    match tag {
        "a" if attributes.has("href") => "link".to_string(),
        "button" => "button".to_string(),
        "select" => "combobox".to_string(),
        "textarea" => "textbox".to_string(),
        "input" => match attributes.get("type").unwrap_or("text").to_ascii_lowercase().as_str() {
            "button" | "submit" | "reset" | "image" => "button".to_string(),
            "checkbox" => "checkbox".to_string(),
            "radio" => "radio".to_string(),
            "hidden" => "generic".to_string(),
            _ => "textbox".to_string(),
        },
        _ => "generic".to_string(),
    }
}

/// Best-effort accessible name, in the order a screen reader would prefer.
///
/// `value` is read only for button-like inputs, where it is the label. It is
/// never read for a text input, because that is where a filled credential
/// would live.
fn accessible_name(node: &Value, tag: &str, attributes: &Attributes) -> String {
    for key in ["aria-label", "placeholder", "title", "alt"] {
        if let Some(value) = attributes.get(key) {
            if !value.trim().is_empty() {
                return value.to_string();
            }
        }
    }
    if tag == "input" {
        let input_type = attributes
            .get("type")
            .unwrap_or("text")
            .to_ascii_lowercase();
        if matches!(input_type.as_str(), "button" | "submit" | "reset") {
            if let Some(value) = attributes.get("value") {
                if !value.trim().is_empty() {
                    return value.to_string();
                }
            }
        }
        return attributes.get("name").unwrap_or_default().to_string();
    }
    descendant_text(node, 0)
}

/// Text of an element's own subtree, used as its accessible name. Bounded in
/// depth so a deeply nested control cannot cost an unbounded walk per element.
fn descendant_text(node: &Value, depth: usize) -> String {
    if depth > 4 {
        return String::new();
    }
    let mut collected = String::new();
    if let Some(children) = node.get("children").and_then(Value::as_array) {
        for child in children {
            match child.get("nodeType").and_then(Value::as_u64) {
                Some(3) => {
                    if let Some(value) = child.get("nodeValue").and_then(Value::as_str) {
                        collected.push_str(value);
                        collected.push(' ');
                    }
                }
                Some(1) => {
                    let tag = child
                        .get("nodeName")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if NON_CONTENT_TAGS.contains(&tag.as_str()) {
                        continue;
                    }
                    if Attributes::from_node(child).is_protected() {
                        continue;
                    }
                    collected.push_str(&descendant_text(child, depth + 1));
                }
                _ => {}
            }
            if collected.len() > 512 {
                break;
            }
        }
    }
    collected
}

/// `e{index}.{digest}` — position plus a digest of identity, so a reference
/// that no longer names the same element is rejected instead of followed.
fn make_reference(index: usize, tag: &str, role: &str, name: &str) -> String {
    let material = format!("{tag}\u{1f}{role}\u{1f}{}", normalize_for_match(name));
    let digest = secretctl_crypto::sha256_digest(material.as_bytes());
    format!(
        "e{index}.{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2]
    )
}

fn collapse_whitespace(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut pending_space = false;
    for character in raw.chars() {
        if character.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        // Control and format characters (including bidi overrides) are dropped
        // rather than rendered: text reaching an agent or a log must not be
        // able to reorder what a human later reads.
        if character.is_control() || matches!(character, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(character);
    }
    out
}

fn normalize_for_match(value: &str) -> String {
    collapse_whitespace(value).trim().to_lowercase()
}

fn truncate_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn element(tag: &str, node_id: u64, attributes: &[(&str, &str)], children: Value) -> Value {
        let attrs: Vec<Value> = attributes
            .iter()
            .flat_map(|(name, value)| {
                [Value::String((*name).into()), Value::String((*value).into())]
            })
            .collect();
        json!({
            "nodeId": node_id,
            "nodeType": 1,
            "nodeName": tag.to_uppercase(),
            "attributes": attrs,
            "children": children,
        })
    }

    fn text(value: &str) -> Value {
        json!({"nodeType": 3, "nodeValue": value})
    }

    fn login_page() -> Value {
        element(
            "body",
            1,
            &[],
            json!([
                element("h1", 2, &[], json!([text("Sign in to Example")])),
                element(
                    "form",
                    3,
                    &[],
                    json!([
                        element(
                            "input",
                            4,
                            &[("type", "text"), ("name", "username"), ("placeholder", "Username")],
                            json!([])
                        ),
                        element(
                            "input",
                            5,
                            &[("type", "password"), ("name", "password")],
                            json!([])
                        ),
                        element(
                            "button",
                            6,
                            &[("type", "submit")],
                            json!([text("Sign in")])
                        ),
                    ])
                ),
                element("a", 7, &[("href", "/reset")], json!([text("Forgot password?")])),
            ]),
        )
    }

    #[test]
    fn projects_interactables_with_roles_and_names() {
        let projection = PageProjection::from_node(&login_page(), &ViewLimits::default());
        let described: Vec<(&str, &str)> = projection
            .nodes
            .iter()
            .map(|node| (node.role.as_str(), node.name.as_str()))
            .collect();
        assert_eq!(
            described,
            vec![
                ("textbox", "Username"),
                ("textbox", ""),
                ("button", "Sign in"),
                ("link", "Forgot password?"),
            ]
        );
    }

    #[test]
    fn password_field_is_marked_protected_and_unnamed() {
        let projection = PageProjection::from_node(&login_page(), &ViewLimits::default());
        let password = &projection.nodes[1];
        assert!(password.protected);
        assert_eq!(password.name, "");
        assert_eq!(password.input_type.as_deref(), Some("password"));
    }

    #[test]
    fn protected_subtree_text_never_reaches_the_projection() {
        // A page that echoes a filled credential back into visible text is the
        // canonical leak. Anything inside a protected element is elided.
        let page = element(
            "div",
            1,
            &[],
            json!([
                element("p", 2, &[], json!([text("Welcome back")])),
                element(
                    "div",
                    3,
                    &[("data-testid", "totp-debug")],
                    json!([text("CANARY-123456")])
                ),
            ]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_eq!(projection.text, "Welcome back");
        assert!(!projection.text.contains("CANARY"));
    }

    #[test]
    fn protected_input_value_is_never_used_as_a_name() {
        let page = element(
            "input",
            1,
            &[
                ("type", "password"),
                ("name", "password"),
                ("value", "CANARY-SECRET"),
                ("aria-label", "CANARY-SECRET"),
            ],
            json!([]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_eq!(projection.nodes.len(), 1);
        assert!(projection.nodes[0].protected);
        assert_eq!(projection.nodes[0].name, "");
    }

    #[test]
    fn text_input_value_attribute_is_never_used_as_a_name() {
        // Even on an unprotected field, `value` is page state rather than a
        // label, and a site may write a submitted credential back into it.
        let page = element(
            "input",
            1,
            &[("type", "text"), ("name", "code"), ("value", "CANARY-123456")],
            json!([]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_eq!(projection.nodes[0].name, "code");
        assert!(!projection.nodes[0].name.contains("CANARY"));
    }

    #[test]
    fn autocomplete_one_time_code_is_protected() {
        let page = element(
            "input",
            1,
            &[("type", "text"), ("autocomplete", "one-time-code")],
            json!([]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert!(projection.nodes[0].protected);
    }

    #[test]
    fn script_and_style_text_is_not_page_content() {
        let page = element(
            "body",
            1,
            &[],
            json!([
                element("script", 2, &[], json!([text("var secret = 'CANARY';")])),
                element("style", 3, &[], json!([text("body{color:red}")])),
                element("p", 4, &[], json!([text("Hello")])),
            ]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_eq!(projection.text, "Hello");
    }

    #[test]
    fn text_is_capped_and_reports_truncation() {
        let page = element("p", 1, &[], json!([text(&"a ".repeat(5_000))]));
        let limits = ViewLimits::clamped(None, Some(50));
        let projection = PageProjection::from_node(&page, &limits);
        assert!(projection.text_truncated);
        assert_eq!(projection.text.chars().count(), 50);
    }

    #[test]
    fn node_count_is_capped_and_reports_truncation() {
        let children: Vec<Value> = (0..40)
            .map(|index| element("button", index + 2, &[], json!([text("Go")])))
            .collect();
        let page = element("div", 1, &[], Value::Array(children));
        let limits = ViewLimits::clamped(Some(5), None);
        let projection = PageProjection::from_node(&page, &limits);
        assert_eq!(projection.nodes.len(), 5);
        assert!(projection.nodes_truncated);
    }

    #[test]
    fn agent_supplied_limits_cannot_exceed_the_broker_ceiling() {
        let limits = ViewLimits::clamped(Some(100_000), Some(10_000_000));
        assert_eq!(limits.max_nodes, 250);
        assert_eq!(limits.max_chars, 20_000);
    }

    #[test]
    fn references_resolve_and_reject_a_changed_element() {
        let projection = PageProjection::from_node(&login_page(), &ViewLimits::default());
        let submit = projection.resolve_role("button", "Sign in").unwrap();
        let reference = submit.reference.clone();

        // Same page: the reference still names the same element.
        let again = PageProjection::from_node(&login_page(), &ViewLimits::default());
        assert_eq!(again.resolve_reference(&reference).unwrap().node_id, 6);

        // The button is relabelled. Position is unchanged, identity is not, so
        // the reference must fail rather than click the new control.
        let mutated = element(
            "div",
            1,
            &[],
            json!([element("button", 6, &[], json!([text("Delete account")]))]),
        );
        let mutated = PageProjection::from_node(&mutated, &ViewLimits::default());
        assert_eq!(
            mutated.resolve_reference(&reference),
            Err(ResolveError::Stale)
        );
    }

    #[test]
    fn ambiguous_locators_are_an_error_rather_than_a_first_match_guess() {
        let page = element(
            "div",
            1,
            &[],
            json!([
                element("button", 2, &[], json!([text("Continue")])),
                element("button", 3, &[], json!([text("Continue")])),
            ]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_eq!(
            projection.resolve_role("button", "Continue"),
            Err(ResolveError::Ambiguous)
        );
        assert_eq!(
            projection.resolve_text("Continue"),
            Err(ResolveError::Ambiguous)
        );
    }

    #[test]
    fn role_matching_ignores_case_and_surrounding_whitespace() {
        let projection = PageProjection::from_node(&login_page(), &ViewLimits::default());
        assert!(projection.resolve_role("BUTTON", "  sign IN ").is_ok());
    }

    #[test]
    fn structural_hiding_is_recorded() {
        let page = element(
            "div",
            1,
            &[],
            json!([
                element("button", 2, &[("hidden", "")], json!([text("A")])),
                element(
                    "button",
                    3,
                    &[("style", "display: none")],
                    json!([text("B")])
                ),
                element("button", 4, &[], json!([text("C")])),
            ]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert!(projection.nodes[0].structurally_hidden);
        assert!(projection.nodes[1].structurally_hidden);
        assert!(!projection.nodes[2].structurally_hidden);
    }

    #[test]
    fn bidi_and_control_characters_are_stripped_from_text() {
        // Page text is rendered in a terminal and in the approval UI. Direction
        // overrides let a page reorder what a human reads, so they never
        // survive projection.
        let page = element(
            "p",
            1,
            &[],
            json!([text("safe\u{202e}reversed\u{202c}\u{0007}text")]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert_eq!(projection.text, "safereversedtext");
    }

    #[test]
    fn iframe_content_documents_are_not_merged_into_the_top_page() {
        let mut frame = element("iframe", 2, &[], json!([]));
        frame["contentDocument"] = element(
            "body",
            3,
            &[],
            json!([element("button", 4, &[], json!([text("Inside frame")]))]),
        );
        let page = element("div", 1, &[], json!([frame]));
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert!(projection.nodes.is_empty());
        assert_eq!(projection.text, "");
    }

    #[test]
    fn disabled_controls_are_reported_as_disabled() {
        let page = element(
            "button",
            1,
            &[("disabled", "")],
            json!([text("Submit")]),
        );
        let projection = PageProjection::from_node(&page, &ViewLimits::default());
        assert!(projection.nodes[0].disabled);
    }

    #[test]
    fn a_projected_node_serializes_without_internal_fields() {
        let projection = PageProjection::from_node(&login_page(), &ViewLimits::default());
        let serialized = serde_json::to_value(&projection.nodes[0]).unwrap();
        assert!(serialized.get("node_id").is_none());
        assert!(serialized.get("structurally_hidden").is_none());
        assert!(serialized.get("reference").is_some());
    }
}
