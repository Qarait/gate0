//! Evaluation statistics for observable bound usage.
//!
//! This module provides the `EvaluationStats` struct which tracks
//! how close an evaluation got to its configured limits.

/// Observable bound usage during policy evaluation.
///
/// These statistics show how much of the configured capacity was used
/// during a single `evaluate_with_stats()` call. Useful for monitoring,
/// debugging, and capacity planning.
///
/// All fields use small integer types to minimize overhead. The struct
/// is `Copy` to allow cheap cloning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvaluationStats {
    /// Number of rules checked before reaching a decision.
    /// 
    /// For deny-overrides semantics, this may be less than the total
    /// rule count if an early deny is found.
    pub rules_checked: u16,

    /// Maximum stack depth reached during condition evaluation.
    /// 
    /// Compare against `ABSOLUTE_MAX_CONDITION_DEPTH` to see how
    /// close you got to the limit.
    pub max_depth_reached: u8,

    /// Total number of condition nodes evaluated.
    /// 
    /// Includes all And, Or, Not, Equals, NotEquals nodes visited.
    pub condition_evals: u16,
}

impl EvaluationStats {
    /// Create a new stats tracker initialized to zero.
    #[inline]
    pub const fn new() -> Self {
        EvaluationStats {
            rules_checked: 0,
            max_depth_reached: 0,
            condition_evals: 0,
        }
    }

    /// Increment the rules checked counter.
    #[inline]
    pub fn inc_rules(&mut self) {
        self.rules_checked = self.rules_checked.saturating_add(1);
    }

    /// Update the max depth if current depth is higher.
    #[inline]
    pub fn update_depth(&mut self, depth: u8) {
        if depth > self.max_depth_reached {
            self.max_depth_reached = depth;
        }
    }

    /// Increment the condition evaluation counter.
    #[inline]
    pub fn inc_condition_evals(&mut self) {
        self.condition_evals = self.condition_evals.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_default() {
        let stats = EvaluationStats::default();
        assert_eq!(stats.rules_checked, 0);
        assert_eq!(stats.max_depth_reached, 0);
        assert_eq!(stats.condition_evals, 0);
    }

    #[test]
    fn test_stats_increment() {
        let mut stats = EvaluationStats::new();
        
        stats.inc_rules();
        stats.inc_rules();
        assert_eq!(stats.rules_checked, 2);

        stats.update_depth(5);
        stats.update_depth(3); // should not change
        stats.update_depth(7);
        assert_eq!(stats.max_depth_reached, 7);

        stats.inc_condition_evals();
        assert_eq!(stats.condition_evals, 1);
    }
}
