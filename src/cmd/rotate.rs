//! `swapd rotate` — pick the next account by a strategy, then switch to it.

use crate::cmd::switch::{view, SwitchOutput};
use crate::core::collect::{collect, CollectOpts};
use crate::core::switch::{self, Strategy};
use crate::ctx::Ctx;
use crate::driver::Driver;
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

/// Which strategy a plain `rotate` uses is `settings.json`'s
/// `<provider>.strategy` (cswap's `autoswitch.strategy`, default `best`),
/// resolved in `main`; a knob the user can set and `rotate` ignores would be a
/// silent no-op.
///
/// `next-available` is the rotation order `list` advertises as `nextCandidate`,
/// and — since the two share the collector's health rule
/// (`collect::within_threshold`) — it lands where the contract said it would.
/// `consume-first` is gated on the same threshold (brief step 5's "soonest 7d
/// reset among healthy", cswap `autoswitch.py:2109-2113`), with cswap's
/// `all_above` escape: when every candidate is above the threshold the gate is
/// dropped rather than the answer withheld. `best` is ungated — it is asked for
/// by name and already ranks by the most headroom, so only an exhausted window
/// is out for it.
pub fn run(ctx: &Ctx, provider: &dyn Driver, strategy: Strategy) -> Result<SwitchOutput> {
    // A collection pass first: ranking on a stale table would rotate onto an
    // account that is already spent. The pass respects the stored poll plans,
    // so a rotate costs at most the fetches those plans already wanted.
    let cursor = collect(ctx, provider, &CollectOpts::default())?;
    // `settings.json`'s pinned accounts (`<provider>.preferred`): they win
    // among the candidates a strategy's own gates already admit, never past
    // them (cswap's `preferred`, settings.py:88).
    let ranked = switch::rank(ctx, &cursor, strategy, &ctx.settings.preferred)?;

    // The whole ranking, not just its head: a candidate whose credential turns
    // out to be dead is exactly the case rotation exists for, and giving up on
    // it would leave the user on a spent account with a healthy one ranked
    // right behind it (cswap's loop does the same). Only a failure that says
    // nothing about the candidate's credential aborts.
    let mut warnings: Vec<String> = Vec::new();
    for target in ranked {
        match switch::perform(ctx, provider, target, "rotate", switch::Freshen::ON_DEMAND) {
            Ok(result) if result.switched => {
                let mut out = view(result);
                warnings.append(&mut out.warnings);
                out.warnings = warnings;
                return Ok(out);
            }
            // The live login moved between the collection pass and here (a
            // concurrent switch, Claude Code's own `/login`): this candidate is
            // already the answer to somebody, so try the next one rather than
            // report a rotation that did not happen.
            Ok(result) => warnings.push(format!(
                "slot {target} was not rotated to ({}); trying the next candidate",
                result.reason.as_deref().unwrap_or("no reason given")
            )),
            Err(e) if skippable(&e) => warnings.push(format!(
                "slot {target} could not be rotated to ({}); trying the next candidate",
                e.message
            )),
            Err(e) => return Err(e),
        }
    }

    Ok(SwitchOutput {
        schema_version: output::SCHEMA_VERSION,
        switched: false,
        reason: Some("no-candidate".to_string()),
        from: None,
        to: None,
        warnings,
    })
}

/// Whether a failed candidate is a reason to try the next one.
///
/// A dead or refused credential and an upstream that would not answer are all
/// facts about that account; anything else (a lock swapd could not take, a full
/// disk, an unactivatable slot) is a fact about the machine, and walking on
/// would repeat it once per candidate.
fn skippable(e: &SwapdError) -> bool {
    matches!(
        e.code,
        ErrorCode::TokenDead | ErrorCode::RefreshDenied | ErrorCode::Http
    )
}
