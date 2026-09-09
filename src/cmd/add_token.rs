//! `swapd add-token -` — register a raw OAuth setup token or a managed API key
//! as a slot, with no prior login on this machine.
//!
//! Port of cswap `add_account_from_token` (`switcher.py:3562`). The token is
//! read from stdin and never from argv: a secret in an argument is visible in
//! every process listing on the machine, so `-` is the only accepted form.

use std::io::Read as _;

use serde_json::{json, Value};

use crate::cmd::add::{check_alias, compose, AddOutput};
use crate::core::import::valid_email;
use crate::core::slots::{self};
use crate::ctx::Ctx;
use crate::driver::{Driver, Identity, Login};
use crate::errors::{ErrorCode, Result, SwapdError};
use crate::output;

/// The scopes cswap wraps a setup token in (`switcher.py:105`).
const SETUP_TOKEN_SCOPES: [&str; 1] = ["user:inference"];

pub struct AddTokenOpts {
    pub slot: Option<u32>,
    pub email: Option<String>,
    pub alias: Option<String>,
    pub force: bool,
}

/// What kind of credential the token is. Detected, never asked for
/// (`credentials.py:166-178`): an `sk-ant-api…` value is a managed key on
/// Claude Code's other auth axis, anything else is an OAuth setup token.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    ApiKey,
    Oauth,
}

impl Kind {
    /// The label its synthesized email is built from
    /// (`switcher.py:3581-3616`).
    fn label(self) -> &'static str {
        match self {
            Kind::ApiKey => "api-key",
            Kind::Oauth => "setup-token",
        }
    }
}

pub fn run(
    ctx: &Ctx,
    provider: &dyn Driver,
    source: &str,
    opts: &AddTokenOpts,
) -> Result<AddOutput> {
    if source != "-" {
        return Err(SwapdError::new(
            ErrorCode::InvalidInput,
            "the token is read from stdin: `swapd add-token -`",
        ));
    }
    if !provider.capabilities().add_token {
        return Err(SwapdError::new(
            ErrorCode::Unsupported,
            format!("{} cannot register a raw token", provider.id()),
        ));
    }
    let id = provider.id();

    let mut token = String::new();
    std::io::stdin().read_to_string(&mut token)?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(SwapdError::new(ErrorCode::InvalidInput, "empty token"));
    }
    // The driver owns the predicate (an engine's credentials are its own
    // business); `add-token` only turns the answer into a label.
    let kind = if provider.is_api_key(&Login {
        bytes: token.clone(),
    }) {
        Kind::ApiKey
    } else {
        Kind::Oauth
    };

    if let Some(email) = &opts.email {
        if !valid_email(email) {
            return Err(SwapdError::new(
                ErrorCode::InvalidInput,
                format!("invalid email format: {email}"),
            ));
        }
    }

    // Decided and written in one `slots.json` lock cycle: the synthesized email
    // carries the slot number, so the slot has to be chosen and taken together
    // or two concurrent registrations would answer with the same default
    // address.
    let (slot, (email, created)) = slots::claim(ctx, id, false, |existing| {
        let by_email = |email: &str| {
            existing
                .slots
                .iter()
                .find(|(_, s)| s.email.to_lowercase() == email.to_lowercase())
                .map(|(n, _)| *n)
        };
        // The slot has to be known before the email can be: the synthesized
        // label carries the slot number, which is what makes every default
        // address unique (`switcher.py:3610-3616`).
        let (slot, email) = match (opts.slot, &opts.email) {
            (Some(slot), Some(email)) => (slot, email.clone()),
            (Some(slot), None) => (slot, synthesized(kind, slot)),
            (None, Some(email)) => (
                by_email(email).unwrap_or_else(|| existing.next_free()),
                email.clone(),
            ),
            (None, None) => {
                let slot = existing.next_free();
                (slot, synthesized(kind, slot))
            }
        };
        if slot < 1 {
            return Err(SwapdError::new(
                ErrorCode::InvalidInput,
                "slot numbers start at 1",
            ));
        }

        // A forced `--email` that already names an account of the other kind is
        // refused (`_reject_cross_kind_collision`, `switcher.py:3160`): identity
        // is matched on (email, org) alone, so an API-key slot and an OAuth slot
        // sharing an address could not be told apart at switch time. swapd reads
        // the kind off the stored credential rather than a recorded field, so
        // the check needs no new state.
        if let Some(existing_slot) = by_email(&email) {
            let stored = ctx
                .secrets
                .get(&crate::secrets::slot_key(id, existing_slot))?;
            let existing_kind = match stored.map(|bytes| Login { bytes }) {
                Some(login) if provider.is_api_key(&login) => Kind::ApiKey,
                Some(_) => Kind::Oauth,
                None => kind,
            };
            if existing_kind != kind {
                return Err(SwapdError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "'{email}' already exists as a{} account (slot {existing_slot}); \
                         pass a distinct --email",
                        match existing_kind {
                            Kind::ApiKey => "n API-key",
                            Kind::Oauth => "n OAuth",
                        }
                    ),
                ));
            }
        }

        if let Some(alias) = &opts.alias {
            check_alias(existing, alias, Some(slot))?;
        }

        let prior = existing.slots.get(&slot).cloned();
        if let Some(prior) = &prior {
            if prior.email.to_lowercase() != email.to_lowercase() && !opts.force {
                return Err(SwapdError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "slot {slot} holds {}; pass --force to overwrite it",
                        prior.email
                    ),
                ));
            }
        }

        let login = compose_login(kind, &token, &email);
        // These tokens carry no org metadata of their own, so the account is
        // personal (`switcher.py:3634-3641`) unless the endpoint later says
        // otherwise — which the collector's own identity match will pick up.
        let identity = Identity {
            email: email.clone(),
            organization_uuid: String::new(),
            organization_name: String::new(),
            plan: None,
            uuid: None,
        };
        let meta = compose(&identity, prior.as_ref(), opts.alias.as_deref(), ctx.now());
        let created = prior.is_none();
        Ok((slot, meta, login, (email, created)))
    })?;

    Ok(AddOutput {
        schema_version: output::SCHEMA_VERSION,
        slot,
        email,
        created,
    })
}

/// `{label}-{slot}@token.local` (`switcher.py:3610-3616`) — these tokens have
/// no email metadata, and the slot number is what makes each default unique.
fn synthesized(kind: Kind, slot: u32) -> String {
    format!("{}-{slot}@token.local", kind.label())
}

/// The credential to store. A managed key goes in raw, on Claude Code's own
/// API-key axis; a setup token is wrapped in the credential JSON Claude Code
/// reads (`switcher.py:3625-3641`), with the synthesized `oauthAccount`
/// alongside it — swapd's `Login` is that envelope, so the account has an
/// offline identity from the moment it is registered.
fn compose_login(kind: Kind, token: &str, email: &str) -> Login {
    if kind == Kind::ApiKey {
        return Login {
            bytes: token.to_string(),
        };
    }
    let envelope = json!({
        "claudeAiOauth": {
            "accessToken": token,
            "scopes": SETUP_TOKEN_SCOPES,
        },
        "oauthAccount": {
            "emailAddress": email,
            "accountUuid": "",
            "organizationUuid": Value::Null,
            "organizationName": Value::Null,
        },
    });
    Login {
        bytes: envelope.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_keys_and_setup_tokens_get_their_own_labels() {
        assert_eq!(synthesized(Kind::ApiKey, 3), "api-key-3@token.local");
        assert_eq!(synthesized(Kind::Oauth, 1), "setup-token-1@token.local");
    }

    #[test]
    fn an_api_key_is_stored_raw_and_a_token_is_wrapped() {
        let key = compose_login(Kind::ApiKey, "sk-ant-api03-x", "api-key-1@token.local");
        assert_eq!(key.bytes, "sk-ant-api03-x");

        let oauth = compose_login(Kind::Oauth, "sk-ant-oat01-y", "setup-token-1@token.local");
        let value: Value = serde_json::from_str(&oauth.bytes).unwrap();
        assert_eq!(value["claudeAiOauth"]["accessToken"], "sk-ant-oat01-y");
        assert_eq!(value["claudeAiOauth"]["scopes"][0], "user:inference");
        assert_eq!(
            value["oauthAccount"]["emailAddress"],
            "setup-token-1@token.local"
        );
    }
}
