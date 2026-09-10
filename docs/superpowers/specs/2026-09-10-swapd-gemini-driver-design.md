# swapd — Gemini CLI driver (sub-spec, 2026-09-10)

**Status: approved by the user 2026-09-10 ("go").** Written
from the research in swapd #11; the phase-2 decisions in #13 were
ruled on by the user on 2026-09-10 and are folded in below. No plan,
no code, until the user has reviewed this file. Every fact about the
CLI is cited to `google-gemini/gemini-cli` at tag `v0.46.0` (the
installed version) via #11; nothing here was read from the user's
real `~/.gemini` beyond key names.

## 0. Rulings from #13 this spec rests on

| #13 item | ruling | where it lands |
|---|---|---|
| 1 igniter may cost money | yes; the usage call is the igniter | §6, §7 |
| 2 swapd-owned locks | yes: `read_live_locked`/`write_live` take a swapd-owned mkdir lock next to the CLI's credential file | §3 |
| 3 identity without network | `google_accounts.json`, `id_token` claims as fallback | §4 |
| 4 ordering | Gemini first, then Codex, Grok, Kiro; the main spec's §11 is amended in the same commit | — |
| 5 encrypted / keyring stores | refused with a clear error in the first cut; `doctor` lists it | §3, §10 |
| 9 quota window | from `resetTime` only, no hardcoded window; buckets map to `WindowKind::Scoped` named by `modelId` | §5 |
| 10 fixtures | captured by the user from a throwaway login on a throwaway `GEMINI_CLI_HOME`, structure only | §9 |

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
  swapd does NOT compile them in (a public repository must not carry
  another product's OAuth client; GitHub push protection refuses it):
  the driver reads the pair from the installed CLI's bundle — the one
  `GOCSPX-` secret and the client id declared beside it — or from
  `SWAPD_GEMINI_OAUTH_CLIENT_ID` / `SWAPD_GEMINI_OAUTH_CLIENT_SECRET`
  (`SWAPD_GEMINI_BUNDLE_DIR` points tests at a synthetic bundle).
  `doctor` notes an installed CLI whose bundle yields no client.
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
cut (#13 ruling 5; `doctor` reports it).

`read_live_locked(env)`: same read under a swapd-owned mkdir lock
`<home>/.gemini/.swapd-live.lock` (stale after 60 s, the Claude
driver's `locks.rs` handshake reused verbatim). The CLI does not take
this lock — it exists so swapd's own writer (`switch`) and readers
(`list`, the collector) never see the pair half-written, and the
`Locked` degrade path in core keeps working. (#13 ruling 2.)

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
(`selectedType != "oauth-personal"` → `NoLogin`, as does the encrypted
store under `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE`). Both are the plain
`NoLogin` class with no reason string: `list` without `--provider` fans
out over every driver and gives up on the first hard error, so anything
harsher blanks the Claude board of a user who merely runs the Gemini CLI
on an API key. `doctor` carries the reason for both — a note naming the
flag, or `"gemini is configured for <type> auth; only oauth-personal is
managed"`.

## 4. Identity and fingerprint

`identity_offline(login)`: the envelope's `google_account` email; when
null, `email` from the `id_token` payload (base64url-decoded, **not**
verified — a local peek, the token was written by the CLI). `Identity
{ email, organization_uuid: "", organization_name: hd-claim-or-"",
plan: None, uuid: sub-claim }`. `same_account` (slots.rs:181) already
matches on email alone when the org is empty, so slots key on email.
`identity()` = `identity_offline()`; there is no network fallback
(userinfo is only called by the CLI at login time).

**Fingerprint.** `Login::fingerprint` reads the refresh token through an
ordered list of envelope pointers (`/claudeAiOauth/refreshToken`, then
`/oauth_creds/refresh_token`), so a Gemini envelope keeps its fingerprint
across access-token refreshes. Both envelopes are swapd's own formats, so
core reads its own keys, never a provider's token. (Ruling 2026-09-10,
replacing the earlier proposal to move the pointer into `Driver`: same
behaviour, three lines instead of 27 call sites.)

## 5. Usage

`usage(login)`: `NeedsRefresh` when `expiry_date` (ms → s) is within
the refresh buffer, as Claude does (`oauth::is_expired`); never
refreshes. POST `retrieveUserQuota` with `{project, userAgent: "swapd/<version>"}`
(where `project` comes from is the paragraph below); 401/403
→ `NeedsRefresh`; 429 → `Throttled { retry_after }` from the
`RetryInfo.retryDelay` detail when present, else 60 s.

**`project`.** `project` comes from one `loadCodeAssist` call per
account, memoised in the driver for the process lifetime
(`project_memo`); it is never persisted, so the slot row stays
provider-neutral.

Bucket → window mapping: one `Window` per bucket, `kind: Scoped`,
`name: modelId` (or `tokenType` when `modelId` is absent), `pct = 100
× (1 − remainingFraction)` or from `remainingAmount`/limit when the
server sends amounts, `resets_at: resetTime` (RFC 3339, as-is).
`used`/`limit` only when `remainingAmount` came with a known limit;
never invented. Pace is the driver's to compute (the Claude driver
does it in `usage::windows_at` from the window's start); Gemini
buckets have no start, so the Gemini driver leaves `pace: None`. The Infinitus adapter already renders
`Scoped` windows by name (Claude's `opus` / `sonnet` scoped windows
use the same path).

**Which windows gate the account.** A Gemini reply carries no 5-hour
and no 7-day window, so `usage::relevant` gates the account on every
NAMED scoped bucket it reports — the `models` setting narrows only an
account that has account-wide windows to fall back on. Without that
rule a Gemini account's headroom is `None` forever and `auto` can
never judge it exhausted.

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

`ignite(env, slot, login)`: under #13 ruling 1 the igniter is the
**usage call** (`usage()` with a fresh-if-needed token), not a
`gemini -p` turn: it costs no model tokens, exercises the same bearer
token, and returns quota. `IgniteOutcome { exit_code: 0 | 41,
rotated }` — 41 synthesised from `TokenDead`/`NeedsRefresh`-after-
refresh so `auto`'s dead-strike logic (which keys on the exit code)
needs no Gemini branch. (Had ruling 1 gone the other way,
`ignite` would have been `gemini -p "." --skip-trust -o json` in the profile
(one prompt is the whole turn; the CLI has no max-turns flag) with
exit 41 read straight off the child — recorded so the alternative is
not re-derived.)

`forget_profile`: `remove_dir_all` of the profile dir; nothing lives
outside it (no keychain migration on this store).

`capabilities()`: `{ignite: true, add_token: false, prefer: true,
refresh: true, run: true}`. `add_token` is false because there is no
token-shaped credential a user could paste (the pair is two files);
`add` captures the live pair.

## 8. Core touchpoints (all small)

1. `Login::fingerprint` gains the Gemini envelope pointer (§4).
2. `driver::registry` / `provider_ids` add `"gemini"`; `config`
   validation picks it up for free.
3. `paths.rs`: `refresh_lock_base` / `credentials_dir` / `profiles_dir`
   already take the provider; nothing new.
4. `contract`: no new fields and no new reason string — the auth-type
   and encrypted-store refusals are plain `NoLogin`, with `doctor`
   carrying the reason (§3). `activeUnreadable` reasons are reused:
   a held `.swapd-live.lock` is swapd's own lock, so it reports
   `switch-in-progress`; `cli-busy` stays reserved for a CLI-owned
   lock (#8's definition), of which Gemini has none.
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

## 10. Rulings on the two open questions (controller, under the user's "go")

1. `project` for `retrieveUserQuota`: one `loadCodeAssist` call per
   account, its `cloudaicompanionProject` memoised in the driver
   (`project_memo`) for the process lifetime, never in the slot row;
   the request shape is read from the CLI source at `v0.46.0` during
   implementation.
2. `run` does not seed `trustedFolders.json`; `--skip-trust` only on
   `ignite`.
3. Fixtures: until the user's captured files arrive, tests use synthetic
   files built from the key names in #11; the captured files replace
   them if the structure differs.
