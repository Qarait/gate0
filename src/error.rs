//! Error types for the policy engine.
//!
//! Hand-written Display implementation (no thiserror dependency).
//! All errors are explicit and typed - no string-based errors.

use std::fmt;

/// Errors that can occur during policy construction or evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A condition expression exceeds the maximum allowed depth.
    ConditionTooDeep {
        /// The configured maximum depth.
        max: usize,
        /// The actual depth of the condition.
        actual: usize,
    },

    /// The policy contains too many rules.
    TooManyRules {
        /// The configured maximum number of rules.
        max: usize,
        /// The actual number of rules.
        actual: usize,
    },

    /// The request context contains too many attributes.
    ContextTooLarge {
        /// The configured maximum number of context attributes.
        max: usize,
        /// The actual number of context attributes.
        actual: usize,
    },

    /// A required context attribute was not found.
    AttributeNotFound {
        /// The name of the missing attribute.
        attr: &'static str,
    },

    /// A context attribute has an unexpected type.
    TypeMismatch {
        /// The name of the attribute with the wrong type.
        attr: &'static str,
        /// The expected type name.
        expected: &'static str,
        /// The actual type name.
        actual: &'static str,
    },

    /// A matcher (OneOf) contains too many options.
    TooManyMatcherOptions {
        /// The configured maximum number of options.
        max: usize,
        /// The actual number of options.
        actual: usize,
    },

    /// A string (identifier or value) exceeds the maximum allowed length.
    StringTooLong {
        /// The configured maximum length.
        max: usize,
        /// The actual length of the string.
        actual: usize,
    },

    /// Internal invariant violation. Should never occur in correct usage.
    InternalError,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::ConditionTooDeep { max, actual } => {
                write!(
                    f,
                    "condition exceeds maximum depth of {}, got {}",
                    max, actual
                )
            }
            PolicyError::TooManyRules { max, actual } => {
                write!(
                    f,
                    "policy exceeds maximum rule count of {}, got {}",
                    max, actual
                )
            }
            PolicyError::ContextTooLarge { max, actual } => {
                write!(
                    f,
                    "context exceeds maximum attribute count of {}, got {}",
                    max, actual
                )
            }
            PolicyError::AttributeNotFound { attr } => {
                write!(f, "context attribute '{}' not found", attr)
            }
            PolicyError::TypeMismatch {
                attr,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "type mismatch for '{}': expected {}, got {}",
                    attr, expected, actual
                )
            }
            PolicyError::TooManyMatcherOptions { max, actual } => {
                write!(
                    f,
                    "matcher exceeds maximum options of {}, got {}",
                    max, actual
                )
            }
            PolicyError::StringTooLong { max, actual } => {
                write!(
                    f,
                    "string exceeds maximum length of {}, got {}",
                    max, actual
                )
            }
            PolicyError::InternalError => {
                write!(f, "internal error: stack invariant violation")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_too_deep_display() {
        let err = PolicyError::ConditionTooDeep { max: 10, actual: 15 };
        assert_eq!(
            err.to_string(),
            "condition exceeds maximum depth of 10, got 15"
        );
    }

    #[test]
    fn test_too_many_rules_display() {
        let err = PolicyError::TooManyRules {
            max: 1000,
            actual: 1500,
        };
        assert_eq!(
            err.to_string(),
            "policy exceeds maximum rule count of 1000, got 1500"
        );
    }

    #[test]
    fn test_context_too_large_display() {
        let err = PolicyError::ContextTooLarge { max: 64, actual: 100 };
        assert_eq!(
            err.to_string(),
            "context exceeds maximum attribute count of 64, got 100"
        );
    }

    #[test]
    fn test_attribute_not_found_display() {
        let err = PolicyError::AttributeNotFound { attr: "role" };
        assert_eq!(err.to_string(), "context attribute 'role' not found");
    }

    #[test]
    fn test_type_mismatch_display() {
        let err = PolicyError::TypeMismatch {
            attr: "count",
            expected: "Int",
            actual: "String",
        };
        assert_eq!(
            err.to_string(),
            "type mismatch for 'count': expected Int, got String"
        );
    }

    #[test]
    fn test_error_trait() {
        let err: Box<dyn std::error::Error> =
            Box::new(PolicyError::AttributeNotFound { attr: "test" });
        assert!(err.to_string().contains("test"));
    }
}
