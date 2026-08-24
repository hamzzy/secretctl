use crate::error::PolicyError;
use crate::hash::compute_policy_hash;
use crate::model::PolicyDocument;
use crate::risk::calculate_risk_level;
use secretctl_domain::{ActionKind, AgentId, CanonicalOrigin, PolicyDecision, PolicyEffect};

pub struct PolicyEvaluator {
    document: PolicyDocument,
    policy_hash: Vec<u8>,
}

impl PolicyEvaluator {
    pub fn new(document: PolicyDocument) -> Self {
        let policy_hash = compute_policy_hash(&document);
        Self {
            document,
            policy_hash,
        }
    }

    pub fn policy_hash(&self) -> &[u8] {
        &self.policy_hash
    }

    pub fn evaluate(
        &self,
        agent_id: &AgentId,
        credential_name: &str,
        action: ActionKind,
        target_origin: &CanonicalOrigin,
        path_prefix: Option<&str>,
        browser_assurance: &str,
    ) -> Result<PolicyDecision, PolicyError> {
        let mut matched_allow_rule = None;

        for rule in &self.document.rules {
            // Check principal match
            let principal_match = rule
                .principals
                .iter()
                .any(|p| p == "*" || p == agent_id.as_str());
            if !principal_match {
                continue;
            }

            // Check credential match
            let cred_match = rule
                .credentials
                .iter()
                .any(|c| c == "*" || c == credential_name);
            if !cred_match {
                continue;
            }

            // Check action match
            let action_match = rule.actions.contains(&action);
            if !action_match {
                continue;
            }

            // Check destination match
            let dest_match = rule.destinations.iter().any(|dest| {
                if !dest.origin.matches(target_origin) {
                    return false;
                }
                match (path_prefix, &dest.path_prefix) {
                    (Some(req_path), Some(rule_path)) => req_path.starts_with(rule_path),
                    (None, Some(_)) => false,
                    (_, None) => true,
                }
            });

            if !dest_match {
                continue;
            }

            // Check conditions
            if let Some(required_assurance) = &rule.conditions.browser_assurance {
                if required_assurance != browser_assurance {
                    continue;
                }
            }

            // If deny rule matches, return immediately
            if rule.effect == PolicyEffect::Deny {
                let risk_level = calculate_risk_level(
                    action,
                    rule.conditions.require_user_presence,
                    browser_assurance,
                );
                return Ok(PolicyDecision {
                    effect: PolicyEffect::Deny,
                    risk_level,
                    rule_id: Some(rule.id.clone()),
                    policy_hash: self.policy_hash.clone(),
                    require_user_presence: true,
                    max_uses: 0,
                    ttl_seconds: 0,
                });
            }

            // Record matched allow rule
            if rule.effect == PolicyEffect::Allow && matched_allow_rule.is_none() {
                matched_allow_rule = Some(rule);
            }
        }

        if let Some(rule) = matched_allow_rule {
            let risk_level = calculate_risk_level(
                action,
                rule.conditions.require_user_presence,
                browser_assurance,
            );
            Ok(PolicyDecision {
                effect: PolicyEffect::Allow,
                risk_level,
                rule_id: Some(rule.id.clone()),
                policy_hash: self.policy_hash.clone(),
                require_user_presence: rule.conditions.require_user_presence,
                max_uses: rule.conditions.max_uses,
                ttl_seconds: rule.conditions.max_ttl_seconds,
            })
        } else {
            Err(PolicyError::DefaultDeny)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DestinationRule, PolicyRule, RuleConditions};
    use secretctl_domain::RuleId;

    #[test]
    fn test_policy_evaluation() {
        let origin = CanonicalOrigin::parse("https://github.com:443").unwrap();
        let rule = PolicyRule {
            id: RuleId::parse("rule_github_login").unwrap(),
            description: Some("Allow github login".to_string()),
            effect: PolicyEffect::Allow,
            principals: vec!["*".to_string()],
            credentials: vec!["github-work".to_string()],
            actions: vec![ActionKind::AuthenticatePassword],
            destinations: vec![DestinationRule {
                origin: origin.clone(),
                path_prefix: Some("/login".to_string()),
            }],
            conditions: RuleConditions {
                browser_assurance: Some("managed".to_string()),
                require_user_presence: false,
                max_uses: 1,
                max_ttl_seconds: 30,
            },
        };

        let doc = PolicyDocument {
            version: "1.0".to_string(),
            rules: vec![rule],
        };

        let evaluator = PolicyEvaluator::new(doc);
        let agent_id = AgentId::new();

        let decision = evaluator
            .evaluate(
                &agent_id,
                "github-work",
                ActionKind::AuthenticatePassword,
                &origin,
                Some("/login"),
                "managed",
            )
            .expect("should allow");

        assert_eq!(decision.effect, PolicyEffect::Allow);
        assert_eq!(decision.max_uses, 1);
        assert_eq!(decision.ttl_seconds, 30);

        // Different destination -> default deny
        let other_origin = CanonicalOrigin::parse("https://evil.com").unwrap();
        assert!(
            evaluator
                .evaluate(
                    &agent_id,
                    "github-work",
                    ActionKind::AuthenticatePassword,
                    &other_origin,
                    None,
                    "managed",
                )
                .is_err()
        );

        // Omitting a path must never broaden a path-constrained rule.
        assert!(
            evaluator
                .evaluate(
                    &agent_id,
                    "github-work",
                    ActionKind::AuthenticatePassword,
                    &origin,
                    None,
                    "managed",
                )
                .is_err()
        );
    }
}
