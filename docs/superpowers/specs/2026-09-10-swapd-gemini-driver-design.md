# swapd — Gemini CLI driver (DRAFT sub-spec, 2026-09-10)

**Status: proposal, not approved.** Written from the research in
swapd #11 and the phase-2 decision list in #13 while the user was
away. It stops at the spec-review gate: no plan, no code, until the
user has answered #13 and reviewed this file. Every fact about the
CLI below is cited to `google-gemini/gemini-cli` at tag `v0.46.0`
(the installed version) via #11; nothing here was read from the
user's real `~/.gemini` beyond key names.

## 0. Assumptions this draft makes about #13

| #13 item | assumed answer | where it bites |
|---|---|---|
| 1 igniter may cost money | **1a**: a metered call is acceptable *as the igniter*; the usage call is the igniter | §6, §7 |
| 2 swapd-owned locks | **yes**: `read_live_locked`/`write_live` take a swapd-owned mkdir lock next to the CLI's credential file | §3 |
| 3 identity without network | Gemini has `google_accounts.json`; nothing to decide | §4 |
| 4 ordering | **Gemini first** (simplest store), ahead of Codex; the spec's §11 order is amended | — |
| 9 quota window | **from `resetTime` only**, no hardcoded window; buckets map to `WindowKind::Scoped` named by `modelId` | §5 |
| 10 fixtures | captured by the user from a throwaway login on a throwaway `GEMINI_CLI_HOME`, structure only | §9 |

If any of those answers change, the section it bites is rewritten;
the rest stands.

## 1. Goal

`swapd list/add/switch/refresh/ignite/run/auto …` work for provider
`gemini` exactly as they do for `claude`: several Google accounts,
each a slot, the CLI's live login swapped between them, usage windows
per slot, auto-switch on exhaustion. Nothing in core changes shape;
the driver fills the `Driver` trait (spec §5) and the Infinitus
Engines pane gains a row.

## 2. Givens (from #11)

- Live login is a **plaintext file pair** under `<home>/.gemini/`:
  `oauth_creds.json` (mode 600, the tokens: `access_token`,
  `refresh_token`, `id_token`, `expiry_date` epoch-**ms**, `scope`,
  `token_type`) and `google_accounts.json` (mode 644,
  `{active: string|null, old: string[]}`, the CLI's own identity cache).
  `<home>` is `$GEMINI_CLI_HOME` or the OS home. Same layout on all
  three OSes; no keychain unless `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE`
  is set (then keychain service `gemini-cli-oauth`, account
  `main-account`).
- Identity: `google_accounts.json` `active` (email). The `id_token`
  carries `email`, `sub`, `hd` as standard claims. No `whoami`.
- Usage: `POST https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota`
  body `{project, userAgent?}`, bearer access token, response
  `{buckets: [{remainingAmount?, remainingFraction?, resetTime?,
  tokenType?, modelId?}]}`. The CLI throttles it to once per 30 s.
- Refresh: standard Google token endpoint
  `https://oauth2.googleapis.com/token`, form-encoded
  `refresh_token, client_id, client_secret, grant_type=refresh_token`;
  the client id and the (deliberately public, installed-app) secret
  are constants in `packages/core/src/code_assist/oauth2.ts:76-85`.
  A refresh response may **omit** `refresh_token` (PR #26924): the
  stored one is kept. Access tokens last ~1 h.
- Igniter: `gemini -p "hi" --skip-trust` under `GEMINI_CLI_HOME`.
  Exit **41** = `FatalAuthenticationError` (dead credential); other
  fatal codes 42/44/52-55/130 are not about the account. Headless
  with no credential fails fast, never prompts.
- Locks: **none** on either credential file (in-process refresh
  de-dup only). `proper-lockfile` guards only `projects.json` and
  `trustedFolders.json`, which the igniter touches as a side effect.
- Login is interactive only (browser or paste-a-code). swapd never
  drives it; `add` captures what the CLI already holds.

## 3. Live login

`read_live(env)`: read both files under `<home>/.gemini/`; the `Login`
bytes are an **envelope** (as for Claude, spec §5):

```json
{"oauth_creds": {…the file verbatim…}, "google_account": "<active email or null>"}
```

`NoLogin` when `oauth_creds.json` is missing or empty; a missing
`google_accounts.json` is not an error (envelope field null →
`identity_offline` falls back to the `id_token` claims, §4).
`Invalid` when `oauth_creds.json` is not a JSON object.
`GEMINI_FORCE_ENCRYPTED_FILE_STORAGE` set → `Unsupported` in this
cut (matches the #13 item 5 recommendation for Codex keyring).

`read_live_locked(env)`: same read under a swapd-owned mkdir lock
`<home>/.gemini/.swapd-live.lock` (stale after 60 s, the Claude
driver's `locks.rs` handshake reused verbatim). The CLI does not take
this lock — it exists so swapd's own writer (`switch`) and readers
(`list`, the collector) never see the pair half-written, and the
`Locked` degrade path in core keeps working. *Assumes #13 item 2.*

`write_live(env, login)`: under the same lock, write
`oauth_creds.json` (tmp + rename, mode 600) then `google_accounts.json`
with `active` = the envelope's email and the previous `active` pushed
onto `old[]` (dedup'd, the CLI's own rotation rule,
`userAccountManager.ts:100-117`). Preserve nothing else — the two
files are the whole login state. `mcp-oauth-tokens*.json`,
`settings.json`, `projects.json` are never touched.

`live_config_text`: `google_accounts.json` verbatim (the "config half"
for `export --full`), `None` when absent.

`can_activate`: `Ok` for any envelope with a non-empty
`oauth_creds.refresh_token`; `Invalid` otherwise. `is_api_key`: always
`false` — `GEMINI_API_KEY`/Vertex modes never appear in
`oauth_creds.json`; they live in env vars and `settings.json`
`security.auth.selectedType`, which swapd reads only to refuse
(`selectedType != "oauth-personal"` → `NoLogin` with reason
`auth-type-not-oauth`; a new `ErrorCode` string, same `NoLogin`
class).

## 4. Identity and fingerprint

`identity_offline(login)`: the envelope's `google_account` email; when
null, `email` from the `id_token` payload (base64url-decoded, **not**
verified — a local peek, the token was written by the CLI). `Identity
{ email, organization_uuid: "", organization_name: hd-claim-or-"",
plan: None, uuid: sub-claim }`. `same_account` (slots.rs:181) already
matches on email alone when the org is empty, so slots key on email.
`identity()` = `identity_offline()`; there is no network fallback
(userinfo is only called by the CLI at login time).

**Fingerprint.** `Login::fingerprint` (driver/mod.rs:23) is
Claude-shaped: it hashes `/claudeAiOauth/refreshToken` and otherwise
the whole blob. A Gemini envelope would hash the whole blob, which
changes on every access-token refresh and would make every refresh
look like a new account. Proposal: **move the pointer into the
driver** — `Driver::fingerprint(&self, login: &Login) -> String`,
Claude's impl unchanged, Gemini's hashing `/oauth_creds/refresh_token`
(same `sha256:` / `sha256-full:` prefixes). 27 call sites in 11 files
change from `login.fingerprint()` to `driver.fingerprint(&login)`;
`Login::fingerprint` is deleted so no caller can pick the wrong one.
This is the one **core** change the driver needs and it lands as its
own task before the driver.

## 5. Usage

`usage(login)`: `NeedsRefresh` when `expiry_date` (ms → s) is within
the refresh buffer, as Claude does (`oauth::is_expired`); never
refreshes. POST `retrieveUserQuota` with `{project, userAgent: "swapd/<version>"}`
(where `project` comes from is the paragraph below); 401/403
→ `NeedsRefresh`; 429 → `Throttled { retry_after }` from the
`RetryInfo.retryDelay` detail when present, else 60 s.

**`project`.** The CLI passes the Code Assist project it resolved at
login (`loadCodeAssist` → `cloudaicompanionProject`), which is not in
`oauth_creds.json`. Two options: (a) call `loadCodeAssist` once per
slot and cache the project id in the slot row (`slots.json` gains a
provider-private `extra: {project}` field); (b) send an empty
`project` and see what the server does. **(a)** is the proposal; the
research did not test (b). *Open question for the user to confirm on
a throwaway account.*

Bucket → window mapping: one `Window` per bucket, `kind: Scoped`,
`name: modelId` (or `tokenType` when `modelId` is absent), `pct = 100
× (1 − remainingFraction)` or from `remainingAmount`/limit when the
server sends amounts, `resets_at: resetTime` (RFC 3339, as-is).
`used`/`limit` only when `remainingAmount` came with a known limit;
never invented. Pace is computed by core from `resets_at` as for
Claude's windows only when the window has a start — Gemini buckets
have none, so `pace: None`. The Infinitus adapter already renders
`Scoped` windows by name (Claude's `opus` / `sonnet` scoped windows
use the same path).

Cadence: the collector's usage cadence (spec §6) applies; the CLI's
own 30 s throttle is a hint that anything faster is unwelcome.

## 6. Refresh

`refresh(login)`: POST the Google token endpoint with the constants
from #11 (`SWAPD_URL_GOOGLE_OAUTH` override, tests only). `200` →
new envelope: `access_token`, `expiry_date = now_ms + expires_in ×
1000`, `id_token` if sent, **`refresh_token` kept from the input when
the response omits it**, `google_account` carried over. `400
invalid_grant` → `TokenDead`. Other 4xx → `Http`; 429 → `Throttled`.
`expires_at` = `expiry_date / 1000`, the generation oracle for
`live_is_older`. Google refresh tokens are **not** single-use, so the
spent-generation hazard is milder than Claude's; the generational
rule still applies unchanged (a newer `expiry_date` wins).

Secrets: the envelope is the slot's secret (keychain
`gemini:<slot>` on macOS, `credentials/gemini/<slot>` elsewhere, spec
§9). `refresh-gemini-<slot>.lock` fences it as for Claude.

## 7. Igniter and run profiles

`run_profile(env, slot, login)`: profile dir
`<swapd home>/profiles/gemini/<slot>/` used **as `GEMINI_CLI_HOME`**;
the CLI then reads `<dir>/.gemini/oauth_creds.json` and
`google_accounts.json`. Seeded once per fingerprint via the
`.swapd-seeded` marker (the Claude driver's `needs_seeding` /
`commit_profile` rule, run.rs:364-444, lifted into a shared helper so
both drivers use one marker implementation). `env`:
`GEMINI_CLI_HOME=<dir>`; `unset`: `GEMINI_API_KEY`,
`GOOGLE_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`,
`GOOGLE_GENAI_USE_VERTEXAI`, `GOOGLE_CLOUD_PROJECT` — any of which
makes the CLI bypass the OAuth login the profile selects. `read_back`
reads the pair back after the child exits and returns it as a
rotation when the `expiry_date` moved. `settings.json` in the profile
is seeded with `{"security":{"auth":{"selectedType":"oauth-personal"}}}`
so the CLI never opens the auth picker; `trustedFolders.json` is not
seeded (`--skip-trust` on ignite; `run` inherits the user's cwd and
their trust answer is theirs to give).

`ignite(env, slot, login)`: *under assumption 1a* the igniter is the
**usage call** (`usage()` with a fresh-if-needed token), not a
`gemini -p` turn: it costs no model tokens, exercises the same bearer
token, and returns quota. `IgniteOutcome { exit_code: 0 | 41,
rotated }` — 41 synthesised from `TokenDead`/`NeedsRefresh`-after-
refresh so `auto`'s dead-strike logic (which keys on the exit code)
needs no Gemini branch. If the user answers 1b (no metered calls),
`ignite` becomes `gemini -p "." --skip-trust -o json` in the profile
(one prompt is the whole turn; the CLI has no max-turns flag) and
exit 41 is read straight off the child.

`forget_profile`: `remove_dir_all` of the profile dir; nothing lives
outside it (no keychain migration on this store).

`capabilities()`: `{ignite: true, add_token: false, prefer: true,
refresh: true, run: true}`. `add_token` is false because there is no
token-shaped credential a user could paste (the pair is two files);
`add` captures the live pair.

## 8. Core touchpoints (all small)

1. `Driver::fingerprint` (§4) — the one refactor, its own task.
2. `driver::registry` / `provider_ids` add `"gemini"`; `config`
   validation picks it up for free.
3. `paths.rs`: `refresh_lock_base` / `credentials_dir` / `profiles_dir`
   already take the provider; nothing new.
4. `contract`: no new fields. `activeUnreadable` reasons are reused
   (`switch-in-progress`, `cli-busy` when `.swapd-live.lock` is held).
5. `Endpoints`: two new names, `GOOGLE_OAUTH` and `CLOUDCODE`,
   with `SWAPD_URL_*` overrides.
6. Infinitus adapter (`SwapdEngine`): one more `EngineFleet` for
   provider `gemini`, gated on `capabilities` as the rule says; no
   Gemini-specific UI.

Things that must **not** happen: no reading of the user's real
`~/.gemini` in tests; the OAuth client secret never printed, logged
or exported; `export` carries the envelope as `credentials` like any
provider (it is the user's own token).

## 9. Testing

- Unit: envelope round-trip; `identity_offline` from the pointer file
  and from a synthetic `id_token`; fingerprint stability across an
  access-token-only refresh; bucket mapping (fraction, amount,
  missing `modelId`, empty buckets); refresh keeps the old
  `refresh_token` when the response omits it; `expires_at` ms → s.
- Live-store tests under `SWAPD_HOME` + a temp `GEMINI_CLI_HOME`
  seeded with **fixture** files (structure captured by the user, #13
  item 10; every value synthetic). Lock handshake: a held
  `.swapd-live.lock` → `Locked` → core degrades.
- HTTP: `SWAPD_URL_GOOGLE_OAUTH` / `SWAPD_URL_CLOUDCODE` at a local
  `tiny_http` stub (the Claude driver's pattern), never the network.
- Igniter: `SWAPD_GEMINI_CLI` pointing at a stub script that exits
  0 / 41 / 52 and optionally rewrites `oauth_creds.json` (rotation
  read-back). Windows: the stub is a `.cmd`, as for Claude.
- `tools/parity.py` gains nothing — there is no cswap Gemini to
  compare against; parity for this driver is the fixture suite.
- Gates unchanged: fmt, clippy (both targets), test on three OSes.

## 10. Open questions for the user

1. #13 items 1, 2, 4, 9, 10 (assumed above).
2. `project` for `retrieveUserQuota` (§5): confirm option (a) on a
   throwaway account, or test (b).
3. Whether to support `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE` in the
   first cut (proposal: `Unsupported`, listed in `doctor`).
4. Whether `run` should seed `trustedFolders.json` for the profile so
   a headless `run` in an untrusted cwd does not stop on the trust
   prompt (proposal: no; `--skip-trust` only on `ignite`).
