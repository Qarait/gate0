//! No Prefix matcher - intentionally omitted to avoid footguns.

use crate::error::PolicyError;

/// A target specifies which requests a rule applies to.
#[derive(Debug, Clone, PartialEq)]
pub struct Target<'a> {
    /// Matcher for the principal.
    pub principal: Matcher<'a>,
    /// Matcher for the action.
    pub action: Matcher<'a>,
    /// Matcher for the resource.
    pub resource: Matcher<'a>,
}

impl<'a> Target<'a> {
    /// Create a target that matches everything.
    pub fn any() -> Self {
        Target {
            principal: Matcher::Any,
            action: Matcher::Any,
            resource: Matcher::Any,
        }
    }

    /// Check if this target matches the given request fields.
    pub fn matches(&self, principal: &str, action: &str, resource: &str) -> bool {
        self.principal.matches(principal)
            && self.action.matches(action)
            && self.resource.matches(resource)
    }
}

/// A matcher for a single field (principal, action, or resource).
#[derive(Debug, Clone, PartialEq)]
pub enum Matcher<'a> {
    /// Matches any value.
    Any,
    /// Matches exactly the specified string.
    Exact(&'a str),
    /// Matches any value in the list.
    OneOf(&'a [&'a str]),
}

impl<'a> Matcher<'a> {
    /// Check if this matcher matches the given value.
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Matcher::Any => true,
            Matcher::Exact(expected) => value == *expected,
            Matcher::OneOf(options) => options.iter().any(|opt| *opt == value),
        }
    }

    /// Validate that this matcher does not exceed the maximum options
    /// and that all strings are within length limits.
    pub fn validate(&self, max_options: usize, max_string_len: usize) -> Result<(), PolicyError> {
        match self {
            Matcher::Any => Ok(()),
            Matcher::Exact(s) => validate_str(s, max_string_len),
            Matcher::OneOf(options) => {
                if options.len() > max_options {
                    return Err(PolicyError::TooManyMatcherOptions {
                        max: max_options,
                        actual: options.len(),
                    });
                }
                for opt in *options {
                    validate_str(opt, max_string_len)?;
                }
                Ok(())
            }
        }
    }
}

/// Validate that a string does not exceed the maximum allowed length.
fn validate_str(s: &str, max_len: usize) -> Result<(), PolicyError> {
    if s.len() > max_len {
        Err(PolicyError::StringTooLong {
            max: max_len,
            actual: s.len(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_any() {
        let m = Matcher::Any;
        assert!(m.matches("anything"));
        assert!(m.matches(""));
        assert!(m.matches("12345"));
    }

    #[test]
    fn test_matcher_exact() {
        let m = Matcher::Exact("admin");
        assert!(m.matches("admin"));
        assert!(!m.matches("Admin"));
        assert!(!m.matches("administrator"));
        assert!(!m.matches(""));
    }

    #[test]
    fn test_matcher_one_of() {
        let options: &[&str] = &["read", "write", "delete"];
        let m = Matcher::OneOf(options);
        assert!(m.matches("read"));
        assert!(m.matches("write"));
        assert!(m.matches("delete"));
        assert!(!m.matches("execute"));
        assert!(!m.matches("READ"));
    }

    #[test]
    fn test_matcher_one_of_empty() {
        let options: &[&str] = &[];
        let m = Matcher::OneOf(options);
        assert!(!m.matches("anything"));
    }

    #[test]
    fn test_target_any() {
        let t = Target::any();
        assert!(t.matches("alice", "read", "document.txt"));
        assert!(t.matches("", "", ""));
        assert!(t.matches("admin", "delete", "secret"));
    }

    #[test]
    fn test_target_specific() {
        let actions: &[&str] = &["read", "list"];
        let t = Target {
            principal: Matcher::Exact("alice"),
            action: Matcher::OneOf(actions),
            resource: Matcher::Any,
        };

        assert!(t.matches("alice", "read", "anything"));
        assert!(t.matches("alice", "list", "anything"));
        assert!(!t.matches("bob", "read", "anything"));
        assert!(!t.matches("alice", "write", "anything"));
    }

    #[test]
    fn test_target_all_exact() {
        let t = Target {
            principal: Matcher::Exact("service-account"),
            action: Matcher::Exact("invoke"),
            resource: Matcher::Exact("api/v1/health"),
        };

        assert!(t.matches("service-account", "invoke", "api/v1/health"));
        assert!(!t.matches("service-account", "invoke", "api/v1/status"));
        assert!(!t.matches("user", "invoke", "api/v1/health"));
    }

    #[test]
    fn test_matcher_too_many_options() {
        let options = vec!["a", "b", "c"];
        let m = Matcher::OneOf(&options);
        
        // Ok if within limit
        assert!(m.validate(3, 256).is_ok());
        
        // Err if over limit
        let err = m.validate(2, 256).unwrap_err();
        assert!(matches!(err, PolicyError::TooManyMatcherOptions { max: 2, actual: 3 }));
    }
}
