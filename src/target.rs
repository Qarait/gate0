//! Target matching for policy rules.
//!
//! Matchers determine whether a rule applies to a given request.
//! Only three matcher types: Any, Exact, OneOf.
//! No Prefix matcher - intentionally omitted to avoid footguns.

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
}
