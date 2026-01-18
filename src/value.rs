//! Context value types.
//!
//! Minimal set: Bool, Int, String only.
//! No Float, List, or Null - smaller surface = stronger guarantees.

/// A value that can appear in request context.
///
/// Intentionally minimal to reduce complexity and attack surface.
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    /// Boolean value.
    Bool(bool),
    /// 64-bit signed integer.
    Int(i64),
    /// Borrowed string slice.
    String(&'a str),
}

impl<'a> Value<'a> {
    /// Returns `true` if this is a `Bool` variant.
    #[inline]
    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }

    /// Returns `true` if this is an `Int` variant.
    #[inline]
    pub fn is_int(&self) -> bool {
        matches!(self, Value::Int(_))
    }

    /// Returns `true` if this is a `String` variant.
    #[inline]
    pub fn is_string(&self) -> bool {
        matches!(self, Value::String(_))
    }

    /// Returns the boolean value if this is a `Bool`, otherwise `None`.
    #[inline]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the integer value if this is an `Int`, otherwise `None`.
    #[inline]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the string value if this is a `String`, otherwise `None`.
    #[inline]
    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns a string describing the type of this value.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "Bool",
            Value::Int(_) => "Int",
            Value::String(_) => "String",
        }
    }
}

impl<'a> From<&'a str> for Value<'a> {
    fn from(s: &'a str) -> Self {
        Value::String(s)
    }
}

impl From<i64> for Value<'_> {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}

impl From<bool> for Value<'_> {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_bool() {
        let v = Value::Bool(true);
        assert!(v.is_bool());
        assert!(!v.is_int());
        assert!(!v.is_string());
        assert_eq!(v.as_bool(), Some(true));
        assert_eq!(v.as_int(), None);
        assert_eq!(v.as_str(), None);
        assert_eq!(v.type_name(), "Bool");
    }

    #[test]
    fn test_value_int() {
        let v = Value::Int(42);
        assert!(!v.is_bool());
        assert!(v.is_int());
        assert!(!v.is_string());
        assert_eq!(v.as_bool(), None);
        assert_eq!(v.as_int(), Some(42));
        assert_eq!(v.as_str(), None);
        assert_eq!(v.type_name(), "Int");
    }

    #[test]
    fn test_value_string() {
        let v = Value::String("hello");
        assert!(!v.is_bool());
        assert!(!v.is_int());
        assert!(v.is_string());
        assert_eq!(v.as_bool(), None);
        assert_eq!(v.as_int(), None);
        assert_eq!(v.as_str(), Some("hello"));
        assert_eq!(v.type_name(), "String");
    }

    #[test]
    fn test_value_equality() {
        assert_eq!(Value::Bool(true), Value::Bool(true));
        assert_ne!(Value::Bool(true), Value::Bool(false));
        assert_ne!(Value::Bool(true), Value::Int(1));
        assert_eq!(Value::Int(0), Value::Int(0));
        assert_eq!(Value::String("a"), Value::String("a"));
        assert_ne!(Value::String("a"), Value::String("b"));
    }
}
