//! The verbs. Each `run` returns the payload its `--json` form emits, so the
//! human renderer and the machine one describe exactly the same pass.

pub mod add;
pub mod add_token;
pub mod history;
pub mod import;
pub mod list;
pub mod refresh;
pub mod rotate;
pub mod switch;
