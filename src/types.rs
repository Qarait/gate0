//! Core type definitions for the policy engine.
//!
//! All types use borrowed data to avoid allocation in the hot path.

use crate::value::Value;

/// The effect of a policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Access is allowed.
    Allow,
    /// Access is denied.
    Deny,
}

impl Effect {
    /// Returns `true` if this effect is `Allow`.
    #[inline]
    pub fn is_allow(&self) -> bool {
        matches!(self, Effect::Allow)
    }

    /// Returns `true` if this effect is `Deny`.
    #[inline]
    pub fn is_deny(&self) -> bool {
        matches!(self, Effect::Deny)
    }
}

/// A stable reason code for audit logs.
///
/// Maps to external string tables for human-readable messages.
/// Using a numeric code ensures:
/// - Stability across versions
/// - No typos in reason strings
/// - Efficient storage and comparison
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReasonCode(pub u32);

impl ReasonCode {
    /// Create a new reason code.
    #[inline]
    pub const fn new(code: u32) -> Self {
        ReasonCode(code)
    }

    /// Get the numeric value of this reason code.
    #[inline]
    pub const fn value(&self) -> u32 {
        self.0
    }
}

/// Reason code returned when no rules match the request.
pub const NO_MATCHING_RULE: ReasonCode = ReasonCode(0);

/// An authorization request.
///
/// All fields are borrowed to avoid allocation during evaluation.
/// The caller owns the data; the policy engine borrows it.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// The principal (user, service, role) making the request.
    pub principal: &'a str,
    /// The action being requested (read, write, delete, etc.).
    pub action: &'a str,
    /// The resource being accessed.
    pub resource: &'a str,
    /// Additional context attributes as key-value pairs.
    ///
    /// Using a slice instead of HashMap:
    /// - Bounded size (enforced at policy level)
    /// - No heap allocation
    /// - Deterministic iteration order
    pub context: &'a [(&'a str, Value<'a>)],
}

impl<'a> Request<'a> {
    /// Create a new request with no context.
    pub fn new(principal: &'a str, action: &'a str, resource: &'a str) -> Self {
        Request {
            principal,
            action,
            resource,
            context: &[],
        }
    }

    /// Create a new request with context.
    pub fn with_context(
        principal: &'a str,
        action: &'a str,
        resource: &'a str,
        context: &'a [(&'a str, Value<'a>)],
    ) -> Self {
        Request {
            principal,
            action,
            resource,
            context,
        }
    }

    /// Look up a context attribute by name.
    ///
    /// Linear scan is acceptable because context is bounded and small.
    pub fn get_attr(&self, name: &str) -> Option<&Value<'a>> {
        self.context
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
    }
}

/// The result of evaluating a policy against a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// The final effect (Allow or Deny).
    pub effect: Effect,
    /// The reason code explaining the decision.
    pub reason: ReasonCode,
}

impl Decision {
    /// Create a new decision.
    #[inline]
    pub const fn new(effect: Effect, reason: ReasonCode) -> Self {
        Decision { effect, reason }
    }

    /// Create an Allow decision with the given reason.
    #[inline]
    pub const fn allow(reason: ReasonCode) -> Self {
        Decision::new(Effect::Allow, reason)
    }

    /// Create a Deny decision with the given reason.
    #[inline]
    pub const fn deny(reason: ReasonCode) -> Self {
        Decision::new(Effect::Deny, reason)
    }

    /// Returns `true` if this decision allows access.
    #[inline]
    pub fn is_allow(&self) -> bool {
        self.effect.is_allow()
    }

    /// Returns `true` if this decision denies access.
    #[inline]
    pub fn is_deny(&self) -> bool {
        self.effect.is_deny()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effect() {
        assert!(Effect::Allow.is_allow());
        assert!(!Effect::Allow.is_deny());
        assert!(!Effect::Deny.is_allow());
        assert!(Effect::Deny.is_deny());
    }

    #[test]
    fn test_reason_code() {
        let code = ReasonCode::new(42);
        assert_eq!(code.value(), 42);
        assert_eq!(NO_MATCHING_RULE.value(), 0);
    }

    #[test]
    fn test_request_no_context() {
        let req = Request::new("alice", "read", "document.txt");
        assert_eq!(req.principal, "alice");
        assert_eq!(req.action, "read");
        assert_eq!(req.resource, "document.txt");
        assert!(req.context.is_empty());
        assert_eq!(req.get_attr("missing"), None);
    }

    #[test]
    fn test_request_with_context() {
        let ctx: &[(&str, Value)] = &[("role", Value::String("admin")), ("level", Value::Int(5))];
        let req = Request::with_context("bob", "write", "config.yaml", ctx);

        assert_eq!(req.get_attr("role"), Some(&Value::String("admin")));
        assert_eq!(req.get_attr("level"), Some(&Value::Int(5)));
        assert_eq!(req.get_attr("missing"), None);
    }

    #[test]
    fn test_decision() {
        let allow = Decision::allow(ReasonCode(1));
        assert!(allow.is_allow());
        assert!(!allow.is_deny());
        assert_eq!(allow.reason.value(), 1);

        let deny = Decision::deny(ReasonCode(2));
        assert!(!deny.is_allow());
        assert!(deny.is_deny());
        assert_eq!(deny.reason.value(), 2);
    }
}
