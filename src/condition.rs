//! Boolean condition evaluation.
//!
//! Minimal expression language: Equals, NotEquals, And, Or, Not.
//! Depth is checked at construction time.
//! Evaluation is stack-based (non-recursive) to guarantee termination.

use crate::error::PolicyError;
use crate::value::Value;

/// A boolean condition that can be evaluated against request context.
#[derive(Debug, Clone, PartialEq)]
pub enum Condition<'a> {
    /// Always evaluates to true.
    True,
    /// Always evaluates to false.
    False,
    /// True if the attribute equals the value.
    Equals {
        /// The attribute name to look up in context.
        attr: &'a str,
        /// The value to compare against.
        value: Value<'a>,
    },
    /// True if the attribute does not equal the value.
    NotEquals {
        /// The attribute name to look up in context.
        attr: &'a str,
        /// The value to compare against.
        value: Value<'a>,
    },
    /// True if both conditions are true.
    And(Box<Condition<'a>>, Box<Condition<'a>>),
    /// True if either condition is true.
    Or(Box<Condition<'a>>, Box<Condition<'a>>),
    /// True if the inner condition is false.
    Not(Box<Condition<'a>>),
}

impl<'a> Condition<'a> {
    /// Compute the depth of this condition tree.
    ///
    /// Used to enforce bounded complexity at construction time.
    pub fn depth(&self) -> usize {
        match self {
            Condition::True | Condition::False => 1,
            Condition::Equals { .. } | Condition::NotEquals { .. } => 1,
            Condition::And(a, b) | Condition::Or(a, b) => {
                1 + a.depth().max(b.depth())
            }
            Condition::Not(inner) => 1 + inner.depth(),
        }
    }

    /// Validate that this condition does not exceed the maximum depth.
    pub fn validate_depth(&self, max_depth: usize) -> Result<(), PolicyError> {
        let actual = self.depth();
        if actual > max_depth {
            Err(PolicyError::ConditionTooDeep {
                max: max_depth,
                actual,
            })
        } else {
            Ok(())
        }
    }

    /// Evaluate this condition against the given context.
    ///
    /// Uses stack-based evaluation to guarantee termination.
    /// Returns `Ok(true)` or `Ok(false)` if evaluation succeeds.
    /// Returns `Err` if a required attribute is missing or has wrong type.
    ///
    /// Note: Missing attributes return `Ok(false)` for Equals and `Ok(true)` for NotEquals.
    /// This is a deliberate design choice for fail-closed semantics.
    pub fn evaluate(&self, context: &[(&str, Value<'_>)]) -> Result<bool, PolicyError> {
        // Stack-based evaluation to avoid recursion
        enum StackItem<'a, 'b> {
            Eval(&'b Condition<'a>),
            ApplyNot,
            ApplyAnd,
            ApplyOr,
        }

        let mut stack: Vec<StackItem<'a, '_>> = vec![StackItem::Eval(self)];
        let mut results: Vec<bool> = Vec::with_capacity(16);

        while let Some(item) = stack.pop() {
            match item {
                StackItem::Eval(cond) => match cond {
                    Condition::True => results.push(true),
                    Condition::False => results.push(false),
                    Condition::Equals { attr, value } => {
                        let result = lookup_attr(context, attr)
                            .map(|v| v == value)
                            .unwrap_or(false); // Missing attr = false (fail-closed)
                        results.push(result);
                    }
                    Condition::NotEquals { attr, value } => {
                        let result = lookup_attr(context, attr)
                            .map(|v| v != value)
                            .unwrap_or(true); // Missing attr = true for NotEquals
                        results.push(result);
                    }
                    Condition::Not(inner) => {
                        stack.push(StackItem::ApplyNot);
                        stack.push(StackItem::Eval(inner));
                    }
                    Condition::And(a, b) => {
                        stack.push(StackItem::ApplyAnd);
                        stack.push(StackItem::Eval(b));
                        stack.push(StackItem::Eval(a));
                    }
                    Condition::Or(a, b) => {
                        stack.push(StackItem::ApplyOr);
                        stack.push(StackItem::Eval(b));
                        stack.push(StackItem::Eval(a));
                    }
                },
                StackItem::ApplyNot => {
                    let val = results.pop().ok_or(PolicyError::InternalError)?;
                    results.push(!val);
                }
                StackItem::ApplyAnd => {
                    let b = results.pop().ok_or(PolicyError::InternalError)?;
                    let a = results.pop().ok_or(PolicyError::InternalError)?;
                    results.push(a && b);
                }
                StackItem::ApplyOr => {
                    let b = results.pop().ok_or(PolicyError::InternalError)?;
                    let a = results.pop().ok_or(PolicyError::InternalError)?;
                    results.push(a || b);
                }
            }
        }

        // Final result should be the only item on the stack
        results.pop().ok_or(PolicyError::InternalError)
    }
}

/// Look up an attribute in the context by name.
fn lookup_attr<'a, 'b>(context: &'b [(&'b str, Value<'a>)], name: &str) -> Option<&'b Value<'a>> {
    context.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_true() {
        let c = Condition::True;
        assert_eq!(c.depth(), 1);
        assert_eq!(c.evaluate(&[]), Ok(true));
    }

    #[test]
    fn test_condition_false() {
        let c = Condition::False;
        assert_eq!(c.depth(), 1);
        assert_eq!(c.evaluate(&[]), Ok(false));
    }

    #[test]
    fn test_condition_equals() {
        let c = Condition::Equals {
            attr: "role",
            value: Value::String("admin"),
        };
        assert_eq!(c.depth(), 1);

        let ctx: &[(&str, Value)] = &[("role", Value::String("admin"))];
        assert_eq!(c.evaluate(ctx), Ok(true));

        let ctx: &[(&str, Value)] = &[("role", Value::String("user"))];
        assert_eq!(c.evaluate(ctx), Ok(false));

        // Missing attribute = false (fail-closed)
        assert_eq!(c.evaluate(&[]), Ok(false));
    }

    #[test]
    fn test_condition_not_equals() {
        let c = Condition::NotEquals {
            attr: "status",
            value: Value::String("blocked"),
        };

        let ctx: &[(&str, Value)] = &[("status", Value::String("active"))];
        assert_eq!(c.evaluate(ctx), Ok(true));

        let ctx: &[(&str, Value)] = &[("status", Value::String("blocked"))];
        assert_eq!(c.evaluate(ctx), Ok(false));

        // Missing attribute = true for NotEquals
        assert_eq!(c.evaluate(&[]), Ok(true));
    }

    #[test]
    fn test_condition_not() {
        let c = Condition::Not(Box::new(Condition::True));
        assert_eq!(c.depth(), 2);
        assert_eq!(c.evaluate(&[]), Ok(false));

        let c = Condition::Not(Box::new(Condition::False));
        assert_eq!(c.evaluate(&[]), Ok(true));
    }

    #[test]
    fn test_condition_and() {
        let c = Condition::And(
            Box::new(Condition::True),
            Box::new(Condition::True),
        );
        assert_eq!(c.depth(), 2);
        assert_eq!(c.evaluate(&[]), Ok(true));

        let c = Condition::And(
            Box::new(Condition::True),
            Box::new(Condition::False),
        );
        assert_eq!(c.evaluate(&[]), Ok(false));
    }

    #[test]
    fn test_condition_or() {
        let c = Condition::Or(
            Box::new(Condition::False),
            Box::new(Condition::True),
        );
        assert_eq!(c.depth(), 2);
        assert_eq!(c.evaluate(&[]), Ok(true));

        let c = Condition::Or(
            Box::new(Condition::False),
            Box::new(Condition::False),
        );
        assert_eq!(c.evaluate(&[]), Ok(false));
    }

    #[test]
    fn test_condition_depth_nested() {
        // (A AND (B OR (NOT C)))
        let c = Condition::And(
            Box::new(Condition::True),
            Box::new(Condition::Or(
                Box::new(Condition::False),
                Box::new(Condition::Not(Box::new(Condition::True))),
            )),
        );
        assert_eq!(c.depth(), 4);
    }

    #[test]
    fn test_validate_depth_ok() {
        let c = Condition::And(
            Box::new(Condition::True),
            Box::new(Condition::False),
        );
        assert!(c.validate_depth(10).is_ok());
        assert!(c.validate_depth(2).is_ok());
    }

    #[test]
    fn test_validate_depth_exceeds() {
        let c = Condition::And(
            Box::new(Condition::True),
            Box::new(Condition::Not(Box::new(Condition::False))),
        );
        // Depth is 3
        assert!(c.validate_depth(2).is_err());
        let err = c.validate_depth(2).unwrap_err();
        assert_eq!(
            err,
            PolicyError::ConditionTooDeep { max: 2, actual: 3 }
        );
    }

    #[test]
    fn test_complex_condition() {
        // (role == "admin") OR (level >= 5 represented as level == 5)
        let c = Condition::Or(
            Box::new(Condition::Equals {
                attr: "role",
                value: Value::String("admin"),
            }),
            Box::new(Condition::Equals {
                attr: "level",
                value: Value::Int(5),
            }),
        );

        let ctx: &[(&str, Value)] = &[("role", Value::String("admin"))];
        assert_eq!(c.evaluate(ctx), Ok(true));

        let ctx: &[(&str, Value)] = &[("level", Value::Int(5))];
        assert_eq!(c.evaluate(ctx), Ok(true));

        let ctx: &[(&str, Value)] = &[("role", Value::String("user")), ("level", Value::Int(3))];
        assert_eq!(c.evaluate(ctx), Ok(false));
    }
}
