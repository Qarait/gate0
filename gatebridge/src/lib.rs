//! GateBridge - YAML policy translator and shadow evaluator for Gate0
//!
//! Translates Ephemera-style YAML policies to Gate0's internal representation
//! and provides shadow evaluation for validation.

mod ast;
mod explain;
mod loader;
pub mod reference_eval;
mod shadow;
mod translate;
pub mod fuzz;

pub use ast::*;
pub use explain::{explain, format_explain, ExplainResult};
pub use loader::{load_policy_file, parse_policy};
pub use reference_eval::evaluate as reference_evaluate;
pub use shadow::{shadow_evaluate, ShadowResult};
pub use translate::to_gate0;

