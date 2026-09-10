//! Who a Gemini login belongs to, without the network: the CLI's own cached
//! email (`google_accounts.json`, what `/about` shows) or the `id_token`'s
//! claims. The JWT is decoded, never verified: it was written by the CLI
//! after Google issued it, and this is a read-only peek at its subject.

use base64::Engine as _;
use serde_json::Value;

use crate::driver::gemini::live::Envelope;
use crate::driver::{Identity, Login};

/// The payload object of a JWT, or `None` when the token is not three
/// base64url segments around a JSON object.
pub fn jwt_payload(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    match serde_json::from_slice::<Value>(&bytes).ok()? {
        v @ Value::Object(_) => Some(v),
        _ => None,
    }
}

pub fn identity_offline(login: &Login) -> Option<Identity> {
    let envelope = Envelope::parse(&login.bytes).ok()?;
    let claims = envelope
        .oauth_creds
        .get("id_token")
        .and_then(Value::as_str)
        .and_then(jwt_payload);
    let claim = |name: &str| {
        claims
            .as_ref()
            .and_then(|c| c.get(name))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let email = envelope.google_account.clone().or_else(|| claim("email"))?;
    Some(Identity {
        email,
        organization_uuid: String::new(),
        organization_name: claim("hd").unwrap_or_default(),
        plan: None,
        uuid: claim("sub"),
    })
}

/// `expiry_date` is epoch milliseconds (google-auth-library computes
/// `Date.now() + expires_in * 1000` and drops `expires_in`).
pub fn expires_at(login: &Login) -> Option<f64> {
    let envelope = Envelope::parse(&login.bytes).ok()?;
    envelope
        .oauth_creds
        .get("expiry_date")
        .and_then(Value::as_f64)
        .map(|ms| ms / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A structurally valid, unsigned JWT: `header.payload.sig` with the
    /// payload base64url-encoded without padding.
    fn jwt(payload: &str) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            b64.encode(r#"{"alg":"none"}"#),
            b64.encode(payload),
            b64.encode("sig")
        )
    }

    fn login(creds: &str, account: &str) -> Login {
        Login {
            bytes: format!(r#"{{"oauth_creds":{creds},"google_account":{account}}}"#),
        }
    }

    #[test]
    fn identity_prefers_the_pointer_file_email() {
        let id_token = jwt(r#"{"email":"jwt@example.com","sub":"123"}"#);
        let login = login(
            &format!(r#"{{"id_token":"{id_token}"}}"#),
            r#""cached@example.com""#,
        );
        let identity = identity_offline(&login).unwrap();
        assert_eq!(identity.email, "cached@example.com");
        assert_eq!(identity.uuid.as_deref(), Some("123"));
        assert_eq!(identity.organization_uuid, "");
    }

    #[test]
    fn identity_falls_back_to_the_id_token_claims() {
        let id_token = jwt(r#"{"email":"jwt@example.com","sub":"123","hd":"example.com"}"#);
        let login = login(&format!(r#"{{"id_token":"{id_token}"}}"#), "null");
        let identity = identity_offline(&login).unwrap();
        assert_eq!(identity.email, "jwt@example.com");
        assert_eq!(identity.organization_name, "example.com");
        assert_eq!(identity.plan, None);
    }

    #[test]
    fn identity_is_none_without_either() {
        assert!(identity_offline(&login(r#"{"access_token":"a"}"#, "null")).is_none());
        assert!(identity_offline(&login(r#"{"id_token":"not-a-jwt"}"#, "null")).is_none());
    }

    #[test]
    fn expires_at_is_expiry_date_in_seconds() {
        let login = login(r#"{"expiry_date":1772074235302}"#, "null");
        assert_eq!(expires_at(&login), Some(1772074235.302));
        assert_eq!(expires_at(&self::login(r#"{}"#, "null")), None);
    }
}
