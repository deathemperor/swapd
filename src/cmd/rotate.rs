//! `swapd rotate` — pick the next account by a strategy, then switch to it.

use crate::cmd::switch::{view, SwitchOutput};
use crate::core::collect::{collect, CollectOpts};
use crate::core::switch::{self, Strategy, SwitchResult};
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::Result;
use crate::output;

/// The strategy `--strategy` defaults to: the rotation order `list` already
/// advertises as `nextCandidate`, so a plain `rotate` lands where the contract
/// said it would.
pub const DEFAULT_STRATEGY: Strategy = Strategy::NextAvailable;

pub fn run(ctx: &Ctx, provider: &dyn Driver, strategy: Strategy) -> Result<SwitchOutput> {
    // A collection pass first: ranking on a stale table would rotate onto an
    // account that is already spent. The pass respects the stored poll plans,
    // so a rotate costs at most the fetches those plans already wanted.
    let cursor = collect(ctx, provider, &CollectOpts::default())?;
    let preferred: Vec<String> = Vec::new();
    let ranked = switch::rank(ctx, &cursor, strategy, &preferred);

    let Some(target) = ranked.first().copied() else {
        return Ok(SwitchOutput {
            schema_version: output::SCHEMA_VERSION,
            switched: false,
            reason: Some("no-candidate".to_string()),
            from: None,
            to: None,
            warnings: Vec::new(),
        });
    };
    let result: SwitchResult = switch::perform(ctx, provider, target, "rotate")?;
    Ok(view(result))
}
