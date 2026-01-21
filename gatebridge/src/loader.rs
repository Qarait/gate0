//! YAML policy loader
//!
//! Reads and parses policy files. Nothing fancy.

use std::path::Path;
use crate::ast::PolicyFile;

/// Load a policy file from disk.
pub fn load_policy_file(path: &Path) -> Result<PolicyFile, LoadError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| LoadError::Io(e.to_string()))?;
    
    parse_policy(&contents)
}

/// Parse policy from a YAML string.
pub fn parse_policy(yaml: &str) -> Result<PolicyFile, LoadError> {
    // Handle the "match" keyword issue - serde can't use it directly
    let yaml = yaml.replace("match:", "match_block:");
    
    serde_yaml::from_str(&yaml)
        .map_err(|e| LoadError::Parse(e.to_string()))
}

#[derive(Debug)]
pub enum LoadError {
    Io(String),
    Parse(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "IO error: {}", e),
            LoadError::Parse(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl std::error::Error for LoadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let yaml = r#"
default:
  principals: ["sandbox"]
  max_duration: "15m"
policies: []
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.default.principals, vec!["sandbox"]);
        assert_eq!(policy.default.max_duration, "15m");
    }

    #[test]
    fn test_parse_with_match() {
        let yaml = r#"
default:
  principals: ["sandbox"]
  max_duration: "15m"
policies:
  - name: "AdminAccess"
    match:
      oidc_groups: ["admins"]
    principals: ["root"]
    max_duration: "60m"
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.policies.len(), 1);
        assert_eq!(policy.policies[0].name, "AdminAccess");
        assert_eq!(policy.policies[0].match_block.oidc_groups, vec!["admins"]);
    }
}
