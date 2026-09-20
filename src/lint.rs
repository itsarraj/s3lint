//! Pure bucket-policy linting: given a real AWS-shaped bucket policy
//! JSON document, find statements that grant public access. No network
//! access here — `main.rs` is the only part that fetches a real policy.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Critical,
}

const WRITE_ACTIONS: &[&str] = &[
    "s3:putobject",
    "s3:deleteobject",
    "s3:deletebucket",
    "s3:putbucketpolicy",
    "s3:putbucketacl",
];

pub fn lint_policy(policy_json: &str) -> anyhow::Result<Vec<Finding>> {
    let doc: Value = serde_json::from_str(policy_json)?;
    let statements = doc
        .get("Statement")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut findings = Vec::new();
    for stmt in &statements {
        let effect = stmt.get("Effect").and_then(Value::as_str).unwrap_or("");
        if effect != "Allow" {
            continue;
        }
        if !is_public_principal(stmt.get("Principal")) {
            continue;
        }
        if stmt.get("Condition").is_some() {
            // A Condition (e.g. restricting by source IP) means "*" isn't
            // really unconditional public access — not flagged.
            continue;
        }

        let actions = actions_of(stmt.get("Action"));
        let is_wildcard_action = actions.iter().any(|a| a == "s3:*" || a == "*");
        let is_write =
            is_wildcard_action || actions.iter().any(|a| WRITE_ACTIONS.contains(&a.as_str()));

        if is_write {
            findings.push(Finding {
                severity: Severity::Critical,
                message: format!(
                    "statement allows PUBLIC WRITE/ADMIN access ({}) with no restricting Condition",
                    actions.join(", ")
                ),
            });
        } else {
            findings.push(Finding {
                severity: Severity::Warning,
                message: format!(
                    "statement allows public read access ({}) with no restricting Condition",
                    actions.join(", ")
                ),
            });
        }
    }
    Ok(findings)
}

fn is_public_principal(principal: Option<&Value>) -> bool {
    match principal {
        Some(Value::String(s)) => s == "*",
        Some(Value::Object(map)) => map.values().any(|v| match v {
            Value::String(s) => s == "*",
            Value::Array(arr) => arr.iter().any(|x| x.as_str() == Some("*")),
            _ => false,
        }),
        _ => false,
    }
}

fn actions_of(action: Option<&Value>) -> Vec<String> {
    match action {
        Some(Value::String(s)) => vec![s.to_lowercase()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_lowercase)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_public_read_with_bare_string_wildcard_principal() {
        let policy = r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}
        ]}"#;
        let findings = lint_policy(policy).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn flags_public_write_as_critical() {
        let policy = r#"{"Statement":[
            {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}
        ]}"#;
        let findings = lint_policy(policy).unwrap();
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn flags_wildcard_action_as_critical_even_if_not_named_write() {
        let policy = r#"{"Statement":[
            {"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*"}
        ]}"#;
        let findings = lint_policy(policy).unwrap();
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn does_not_flag_a_specific_principal() {
        let policy = r#"{"Statement":[
            {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}
        ]}"#;
        assert!(lint_policy(policy).unwrap().is_empty());
    }

    #[test]
    fn does_not_flag_deny_statements() {
        let policy = r#"{"Statement":[
            {"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}
        ]}"#;
        assert!(lint_policy(policy).unwrap().is_empty());
    }

    #[test]
    fn a_condition_makes_a_wildcard_principal_not_flagged() {
        let policy = r#"{"Statement":[
            {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*",
             "Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}
        ]}"#;
        assert!(lint_policy(policy).unwrap().is_empty());
    }

    #[test]
    fn handles_an_array_of_actions_flagging_write_if_any_one_is() {
        let policy = r#"{"Statement":[
            {"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::b/*"}
        ]}"#;
        let findings = lint_policy(policy).unwrap();
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn empty_statement_list_produces_no_findings() {
        assert!(lint_policy(r#"{"Statement":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn malformed_json_is_a_clean_error() {
        assert!(lint_policy("not json").is_err());
    }

    #[test]
    fn principal_array_of_arns_including_wildcard_is_flagged() {
        let policy = r#"{"Statement":[
            {"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123:root","*"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}
        ]}"#;
        assert_eq!(lint_policy(policy).unwrap().len(), 1);
    }
}
