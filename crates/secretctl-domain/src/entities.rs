use crate::actions::ActionKind;
use crate::id::{
    AgentId, ApprovalId, BrowserInstanceId, BrowserSessionId, CapabilityId, CredentialId, EventId,
    ExecutionId, FlowId, FlowStepId, GrantId, RecipeId, RequestId, RuleId,
};
use crate::origin::CanonicalOrigin;
use crate::states::{ActionRequestState, BrowserSessionState, CapabilityState, ExecutionState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPrincipal {
    pub agent_id: AgentId,
    pub role: String,
    pub public_key: Vec<u8>,
    pub display_name: String,
    pub peer_uid: Option<u32>,
    pub executable_path: Option<String>,
    pub executable_hash: Option<Vec<u8>>,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    pub credential_id: CredentialId,
    pub name: String,
    pub kind: String,
    pub provider: String,
    pub provider_locator: String,
    pub allowed_actions: Vec<ActionKind>,
    pub metadata_json: String,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeField {
    pub role: String,
    pub selector: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub clear_first: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeSubmit {
    pub selector: Option<String>,
    #[serde(default)]
    pub auto_submit: bool,
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeSuccessIndicators {
    pub navigation_origin: Option<String>,
    pub selector_present: Option<String>,
    pub selector_absent: Option<String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeMatch {
    pub top_origin: CanonicalOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_origin: Option<CanonicalOrigin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteRecipe {
    pub recipe_id: RecipeId,
    pub version: u32,
    pub name: String,
    pub action: ActionKind,
    #[serde(rename = "match")]
    pub match_rule: RecipeMatch,
    pub fields: Vec<RecipeField>,
    pub submit: Option<RecipeSubmit>,
    pub success_indicators: Option<RecipeSuccessIndicators>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthRecipe>,
    #[serde(skip, default)]
    pub content_hash: Vec<u8>,
    #[serde(skip, default = "default_recipe_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthRecipe {
    pub issuer: CanonicalOrigin,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub allowed_scopes: Vec<String>,
}

impl OAuthRecipe {
    /// Validate the portions of the OAuth configuration that are security
    /// invariants before any navigation or token exchange is attempted.
    pub fn validate(&self) -> Result<(), crate::DomainError> {
        let parse_endpoint = |value: &str| {
            let url = url::Url::parse(value).map_err(|_| {
                crate::DomainError::SecurityInvariantViolation("OAuth URL is invalid".into())
            })?;
            if url.scheme() != "https"
                || url.username() != ""
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(crate::DomainError::SecurityInvariantViolation(
                    "OAuth endpoints must be HTTPS URLs without credentials, query, or fragment"
                        .into(),
                ));
            }
            Ok(url)
        };
        let authorization = parse_endpoint(&self.authorization_endpoint)?;
        let token = parse_endpoint(&self.token_endpoint)?;
        let authorization_origin = CanonicalOrigin::parse(
            authorization.origin().ascii_serialization().as_str(),
        )
        .map_err(|_| {
            crate::DomainError::SecurityInvariantViolation("OAuth issuer is invalid".into())
        })?;
        let token_origin = CanonicalOrigin::parse(token.origin().ascii_serialization().as_str())
            .map_err(|_| {
                crate::DomainError::SecurityInvariantViolation("OAuth issuer is invalid".into())
            })?;
        if !authorization_origin.matches(&self.issuer) || !token_origin.matches(&self.issuer) {
            return Err(crate::DomainError::SecurityInvariantViolation(
                "OAuth endpoints must match the configured issuer".into(),
            ));
        }
        let redirect = url::Url::parse(&self.redirect_uri).map_err(|_| {
            crate::DomainError::SecurityInvariantViolation("OAuth redirect URI is invalid".into())
        })?;
        if redirect.scheme() != "https"
            || redirect.username() != ""
            || redirect.password().is_some()
            || redirect.query().is_some()
            || redirect.fragment().is_some()
        {
            return Err(crate::DomainError::SecurityInvariantViolation(
                "OAuth redirect must be an exact HTTPS origin/path".into(),
            ));
        }
        if self.client_id.trim().is_empty() || self.allowed_scopes.is_empty() {
            return Err(crate::DomainError::SecurityInvariantViolation(
                "OAuth client ID and scopes are required".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        if self.allowed_scopes.iter().any(|scope| {
            scope.is_empty() || scope.chars().any(char::is_whitespace) || !seen.insert(scope)
        }) {
            return Err(crate::DomainError::SecurityInvariantViolation(
                "OAuth scopes must be unique non-empty names".into(),
            ));
        }
        Ok(())
    }
}

fn default_recipe_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInstance {
    pub instance_id: BrowserInstanceId,
    pub launcher_nonce: String,
    pub binary_hash: Option<Vec<u8>>,
    pub extension_key_id: String,
    pub private_cdp_endpoint: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    pub session_id: BrowserSessionId,
    pub instance_id: BrowserInstanceId,
    pub extension_key_id: String,
    pub profile_id: String,
    pub assurance: String,
    pub state: BrowserSessionState,
    pub last_heartbeat_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageContext {
    pub tab_id: u32,
    pub frame_id: u32,
    pub top_origin: CanonicalOrigin,
    pub frame_origin: CanonicalOrigin,
    pub navigation_epoch: u64,
    pub document_id: String,
    /// Trusted, executor-measured path used only for authorization matching.
    /// Audit records retain `path_sha256` instead of this value.
    pub path: String,
    pub path_sha256: String,
    pub tls: bool,
    pub incognito: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub credential_id: CredentialId,
    pub action: ActionKind,
    pub target_origin: CanonicalOrigin,
    pub path_prefix: Option<String>,
    pub browser_session_id: BrowserSessionId,
    pub tab_hint: Option<u32>,
    pub reason: String,
    pub state: ActionRequestState,
    pub policy_hash: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    pub risk_level: RiskLevel,
    pub rule_id: Option<RuleId>,
    pub policy_hash: Vec<u8>,
    pub require_user_presence: bool,
    pub max_uses: u32,
    /// How long the runtime has to prepare, commit, and receive the secret.
    /// A hard security deadline: short, and expiring before consumption proves
    /// no secret was released.
    pub consume_ttl_seconds: u64,
    /// How long the resulting login is allowed to take, measured from
    /// consumption. Deliberately longer and deliberately separate: a two-step
    /// login routinely exceeds the secret-release window in wall clock, and
    /// collapsing the two forces a choice between an unsafely long secret
    /// window and a login that always times out.
    pub execution_ttl_seconds: u64,
}

/// The four deadlines a capability carries, expressed as durations at mint time.
///
/// They are passed together, and named, so that a caller cannot accidentally
/// supply the secret-release window where the completion window was meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityDeadlines {
    pub consume_ttl_seconds: u64,
    pub execution_ttl_seconds: u64,
    pub step_ttl_seconds: Option<u64>,
}

impl CapabilityDeadlines {
    pub fn from_policy(decision: &PolicyDecision) -> Self {
        Self {
            consume_ttl_seconds: decision.consume_ttl_seconds,
            execution_ttl_seconds: decision.execution_ttl_seconds,
            step_ttl_seconds: None,
        }
    }

    pub fn with_step(mut self, step_ttl_seconds: Option<u64>) -> Self {
        self.step_ttl_seconds = step_ttl_seconds;
        self
    }
}

/// Which flow step a capability belongs to, when it belongs to one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowBinding {
    pub flow_id: FlowId,
    pub step_id: FlowStepId,
}

/// Default completion window for a consumed action, in seconds.
///
/// Provisional. Real login durations have not been measured, and this number is
/// expected to move once they are.
pub const DEFAULT_EXECUTION_TTL_SECONDS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approval_id: ApprovalId,
    pub request_id: RequestId,
    pub decision: String,
    pub actor: Option<String>,
    pub presence: Option<String>,
    pub context_digest: Vec<u8>,
    pub decided_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub capability_id: CapabilityId,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub credential_id: CredentialId,
    pub action: ActionKind,
    pub top_origin: CanonicalOrigin,
    pub frame_origin: CanonicalOrigin,
    pub browser_session_id: BrowserSessionId,
    pub extension_key_id: String,
    pub tab_id: u32,
    pub frame_id: u32,
    pub document_id: String,
    pub navigation_epoch: u64,
    pub recipe_id: RecipeId,
    pub recipe_hash: Vec<u8>,
    pub policy_hash: Vec<u8>,
    pub token_hash: Vec<u8>,
    pub state: CapabilityState,
    pub max_uses: u32,
    pub used_count: u32,
    pub issued_at: DateTime<Utc>,
    /// Deadline for prepare, commit, and secret release. Expiry *before*
    /// consumption is proof that no secret was used, and is safe to report as a
    /// clean failure.
    pub consume_deadline: DateTime<Utc>,
    /// Deadline for the action to finish, measured from consumption. Expiry
    /// *after* consumption proves nothing about the destination: the outcome is
    /// indeterminate, never a failure.
    pub execution_deadline: DateTime<Utc>,
    /// Optional per-step budget inside a multi-step flow.
    pub step_deadline: Option<DateTime<Utc>>,
    /// The authentication flow this capability is a step of, when it belongs to
    /// one. A flow's steps each consume their own capability.
    pub flow_id: Option<FlowId>,
    pub step_id: Option<FlowStepId>,
    pub revoked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySummary {
    pub capability_id: CapabilityId,
    pub request_id: RequestId,
    pub state: String,
    pub max_uses: u32,
    pub used_count: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_reason: Option<String>,
    pub signing_key_id: String,
}

impl Capability {
    /// Whether this capability may still be consumed.
    ///
    /// Only the consume deadline is checked. The execution deadline governs a
    /// window that has not started yet, and letting it block consumption would
    /// be a category error.
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        (self.state == CapabilityState::Issued || self.state == CapabilityState::Active)
            && now <= self.consume_deadline
            && self.used_count < self.max_uses
    }

    /// Whether the post-consumption completion window has elapsed.
    ///
    /// Callers must map this to an indeterminate outcome. It is never grounds
    /// for reporting that the action did not happen: by this point the
    /// destination may already have accepted the credential.
    pub fn execution_window_elapsed(&self, now: DateTime<Utc>) -> bool {
        now > self.execution_deadline
    }

    /// Whether the current step's budget has elapsed. Same rule as above: after
    /// consumption this is indeterminate, not failure.
    pub fn step_window_elapsed(&self, now: DateTime<Utc>) -> bool {
        self.step_deadline.is_some_and(|deadline| now > deadline)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    pub execution_id: ExecutionId,
    pub capability_id: CapabilityId,
    pub state: ExecutionState,
    pub prepared_context_digest: Option<Vec<u8>>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthGrant {
    pub grant_id: GrantId,
    pub credential_id: CredentialId,
    pub provider_locator: String,
    pub scopes: Vec<String>,
    pub subject_hint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub event_id: EventId,
    pub event_type: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub event_json: String,
    pub audit_key_version: u32,
    pub previous_hash: Vec<u8>,
    pub event_hash: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub sequence: u64,
    pub event_hash: Vec<u8>,
    pub audit_key_version: u32,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod recipe_tests {
    use super::*;

    #[test]
    fn recipe_deserializes_from_the_published_shape_with_safe_defaults() {
        let recipe: SiteRecipe = serde_json::from_value(serde_json::json!({
            "recipe_id": "rcp_github_login",
            "version": 1,
            "name": "GitHub login",
            "action": "authenticate.password",
            "match": {
                "top_origin": "https://github.com",
                "path_prefix": "/login"
            },
            "fields": [{
                "role": "password",
                "selector": "input[type=password]"
            }]
        }))
        .expect("schema-shaped recipe must deserialize");

        assert_eq!(recipe.match_rule.path_prefix.as_deref(), Some("/login"));
        assert!(recipe.enabled);
        assert!(!recipe.fields[0].optional);
        assert!(!recipe.fields[0].clear_first);
        assert!(recipe.content_hash.is_empty());

        let serialized = serde_json::to_value(recipe).expect("recipe must serialize");
        assert!(serialized.get("match").is_some());
        assert!(serialized.get("content_hash").is_none());
        assert!(serialized.get("enabled").is_none());
    }

    #[test]
    fn recipe_rejects_unknown_configuration_fields() {
        let result = serde_json::from_value::<SiteRecipe>(serde_json::json!({
            "recipe_id": "rcp_github_login",
            "version": 1,
            "name": "GitHub login",
            "action": "authenticate.password",
            "match": { "top_origin": "https://github.com" },
            "fields": [{
                "role": "password",
                "selector": "input[type=password]",
                "unexpected": true
            }]
        }));

        assert!(result.is_err());
    }

    #[test]
    fn oauth_recipe_requires_exact_https_issuer_and_scopes() {
        let recipe = OAuthRecipe {
            issuer: CanonicalOrigin::parse("https://idp.example").unwrap(),
            authorization_endpoint: "https://idp.example/authorize".into(),
            token_endpoint: "https://idp.example/token".into(),
            client_id: "client-1".into(),
            redirect_uri: "https://app.example/oauth/callback".into(),
            allowed_scopes: vec!["openid".into(), "profile".into()],
        };
        recipe.validate().unwrap();

        let mut invalid = recipe.clone();
        invalid.authorization_endpoint = "http://idp.example/authorize".into();
        assert!(invalid.validate().is_err());
        invalid = recipe.clone();
        invalid.allowed_scopes.push("openid".into());
        assert!(invalid.validate().is_err());
        invalid = recipe;
        invalid.token_endpoint = "https://other.example/token".into();
        assert!(invalid.validate().is_err());
    }
}

/// A standing grant is the durable, revocable authorization a human creates by
/// choosing "always allow": it names exactly one
/// `(agent, credential, origin, action)` tuple and always expires.
///
/// A grant is never a substitute for the security kernel. It only replaces the
/// interactive approval step, and only up to `risk_ceiling`; every origin,
/// navigation-epoch, recipe, and capability check still runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandingGrant {
    pub grant_id: GrantId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub credential_id: CredentialId,
    pub credential_name: String,
    pub origin: CanonicalOrigin,
    pub action: ActionKind,
    /// Highest risk level this grant may auto-approve. Anything above still
    /// escalates to a human.
    pub risk_ceiling: RiskLevel,
    /// When set, the grant records that the underlying decision demands live
    /// user presence, so it can never auto-approve.
    pub require_presence: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_reason: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub use_count: u64,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Ordering used to compare an evaluated risk against a grant ceiling.
    pub fn rank(&self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }
}

impl std::str::FromStr for RiskLevel {
    type Err = crate::error::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(crate::error::DomainError::InvalidId(format!(
                "unknown risk level '{other}'"
            ))),
        }
    }
}

/// The highest risk a standing grant is ever allowed to carry. Anything above
/// this escalates to a live human decision no matter what the user clicked.
pub const MAX_GRANTABLE_RISK: RiskLevel = RiskLevel::Medium;

/// Longest life a standing grant may be given, in days.
pub const MAX_GRANT_TTL_DAYS: i64 = 90;

impl StandingGrant {
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }

    /// Whether this grant authorizes exactly the tuple being requested.
    ///
    /// Matching is exact on every dimension: a grant for one origin never
    /// covers another, and a grant for one action never covers another.
    pub fn covers(
        &self,
        agent_id: &AgentId,
        credential_name: &str,
        action: ActionKind,
        origin: &CanonicalOrigin,
        risk: RiskLevel,
        now: DateTime<Utc>,
    ) -> bool {
        self.is_active_at(now)
            && !self.require_presence
            && &self.agent_id == agent_id
            && self.credential_name == credential_name
            && self.action == action
            && &self.origin == origin
            && risk.rank() <= self.risk_ceiling.rank()
            && risk.rank() <= MAX_GRANTABLE_RISK.rank()
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;

    fn grant(risk_ceiling: RiskLevel, require_presence: bool) -> StandingGrant {
        StandingGrant {
            grant_id: GrantId::new(),
            agent_id: AgentId::parse("agent_fixed").unwrap(),
            agent_name: "claude".to_string(),
            credential_id: CredentialId::parse("cred_fixed").unwrap(),
            credential_name: "github-work".to_string(),
            origin: CanonicalOrigin::parse("https://github.com").unwrap(),
            action: ActionKind::AuthenticatePassword,
            risk_ceiling,
            require_presence,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(30),
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            use_count: 0,
        }
    }

    fn agent() -> AgentId {
        AgentId::parse("agent_fixed").unwrap()
    }

    fn github() -> CanonicalOrigin {
        CanonicalOrigin::parse("https://github.com").unwrap()
    }

    #[test]
    fn grant_covers_only_its_exact_tuple() {
        let grant = grant(RiskLevel::Medium, false);
        let now = Utc::now();

        assert!(grant.covers(
            &agent(),
            "github-work",
            ActionKind::AuthenticatePassword,
            &github(),
            RiskLevel::Medium,
            now
        ));

        // A different origin is a different grant.
        let evil = CanonicalOrigin::parse("https://evil.example").unwrap();
        assert!(!grant.covers(
            &agent(),
            "github-work",
            ActionKind::AuthenticatePassword,
            &evil,
            RiskLevel::Medium,
            now
        ));

        // A different credential is a different grant.
        assert!(!grant.covers(
            &agent(),
            "aws-prod",
            ActionKind::AuthenticatePassword,
            &github(),
            RiskLevel::Medium,
            now
        ));

        // A different agent is a different grant.
        assert!(!grant.covers(
            &AgentId::parse("agent_other").unwrap(),
            "github-work",
            ActionKind::AuthenticatePassword,
            &github(),
            RiskLevel::Medium,
            now
        ));

        // A different action is a different grant.
        assert!(!grant.covers(
            &agent(),
            "github-work",
            ActionKind::FormSensitiveFill,
            &github(),
            RiskLevel::Medium,
            now
        ));
    }

    #[test]
    fn grant_never_auto_approves_above_medium_risk() {
        // Even a grant that somehow carries a high ceiling cannot auto-approve
        // a high-risk decision: MAX_GRANTABLE_RISK is the hard stop.
        let grant = grant(RiskLevel::Critical, false);
        assert!(!grant.covers(
            &agent(),
            "github-work",
            ActionKind::AuthenticatePassword,
            &github(),
            RiskLevel::High,
            Utc::now()
        ));
    }

    #[test]
    fn presence_bound_and_revoked_and_expired_grants_never_cover() {
        let now = Utc::now();
        let args = |g: &StandingGrant, at: DateTime<Utc>| {
            g.covers(
                &agent(),
                "github-work",
                ActionKind::AuthenticatePassword,
                &github(),
                RiskLevel::Medium,
                at,
            )
        };

        assert!(!args(&grant(RiskLevel::Medium, true), now));

        let mut revoked = grant(RiskLevel::Medium, false);
        revoked.revoked_at = Some(now);
        assert!(!args(&revoked, now));

        let expired = grant(RiskLevel::Medium, false);
        assert!(!args(
            &expired,
            expired.expires_at + chrono::Duration::seconds(1)
        ));
    }
}
