# swapd — multi-provider account engine (designed 2026-09-09)

User's decision (2026-09-09): "it's time to make the decision to rebuild
cswap engine ourselves, maybe using the best efficient and simplest lang
to keep it fast and lightweight. this should be a separate repo and the
app use it." Then: "expand the scope to support codex, grok, kiro and
other cli providers."

Answers that fixed the shape: macOS + Linux + Windows; the CLI stays
usable standalone beside other pollers; clean protocol (not a cswap
twin); repo and binary `swapd`; Grok targets xAI's official CLI; Rust
(user's call over Go, 2026-09-09: smaller binary, native keychain
crate, bundled SQLite for Kiro).

## 1. Goal

One binary that keeps several logins per AI coding CLI, shows each
login's usage windows, switches the CLI's live login between them
(by hand or automatically before a limit binds), and starts a login's
usage window on demand. Infinitus drives it over `--json` subprocess
calls; a terminal user drives it the same way without `--json`.

## 2. Givens

- **Rust, one static binary per OS.** No runtime, a few ms startup,
  ~3 MB. Keychain through the `keyring` crate (macOS Security
  framework, Windows Credential Manager, Linux secret-service with a
  0600-file fallback when no daemon runs). Networking `ureq` with
  rustls (no OpenSSL to ship). SQLite via `rusqlite` bundled (Kiro).
  Edition 2021, MSRV = current stable; `cargo install --path .` and
  release binaries from a GitHub Actions matrix (macos-arm64,
  macos-x86_64, linux-x86_64, linux-arm64, windows-x86_64).
- **Still one `AccountEngine` adapter in Infinitus.** The app gates on
  capabilities, never on engine identity; nothing in the app may depend
  on swapd existing (the same rule that governs cswap). The subprocess
  boundary stays: the app never reads `~/.swapd/`.
- **Secrets over stdin, never argv; shown masked.**
- **Measured behaviour ports verbatim, not re-derived** (section 8).
- **Scope = what Infinitus calls plus a standalone-usable CLI.** No TUI,
  no directory mappings, no session-resume, no cmux control, no
  away-notify channels beyond `notify --json` status.

## 3. Shape

```
swapd <verb> [args] [--provider claude|codex|kiro|gemini|grok] [--json]
```

- Human output on stderr; with `--json` exactly one JSON object on
  stdout (NDJSON for `auto --json`).
- Errors: `{"schemaVersion":1,"error":{"code":"...","message":"..."}}`
  and a non-zero exit. `code` is a stable token (`no-such-slot`,
  `provider-not-installed`, `keychain-unavailable`, `refresh-denied`,
  `token-dead`, `locked`, `unsupported`).
- `schemaVersion` is additive-stable: new fields never bump it; a shape
  change does, and the app refuses a newer version as it does today.
- `--provider` defaults to `claude`. `list` without it returns every
  provider that has at least one slot or an installed CLI.

### Layout

```
Cargo.toml            one binary crate `swapd` (workspace later if a driver grows)
src/main.rs           clap verb dispatch, --json/--provider, exit codes
src/output.rs         JSON envelope, error codes, stderr human view
src/core/             slots, aliases, settings, history, usage store,
                      poll policy, auto loop, events, export/import
src/driver/mod.rs     the Driver trait + registry
src/driver/claude.rs  src/driver/codex.rs  src/driver/kiro.rs
src/driver/gemini.rs  src/driver/grok.rs
src/secrets.rs        keyring wrapper + 0600-file fallback
src/locks.rs          cross-process locks (dir-mkdir mutex, per CLI)
tests/                integration tests: temp HOME, fake keychain, httpmock
```

Crates: `clap` (derive), `serde` + `serde_json`, `ureq` (rustls),
`keyring`, `rusqlite` (bundled), `sha2`, `time`, `thiserror`,
`fd-lock`; dev: `httpmock`, `assert_cmd`, `tempfile`.

## 4. Contract v1

### `list --json`

```json
{
  "schemaVersion": 1,
  "providers": [
    {
      "provider": "claude",
      "installed": true,
      "activeSlot": 2,
      "nextCandidate": 1,
      "nextRecovery": {"slot": 8, "at": "2026-09-09T03:29:59Z"},
      "accounts": [
        {
          "slot": 1,
          "email": "you@example.com",
          "organizationName": "…", "organizationUuid": "…",
          "plan": "Max 20x",
          "alias": "death2", "icon": "🩸",
          "active": false, "disabled": false, "preferred": false,
          "usageStatus": "ok",
          "fetchedAt": "2026-09-09T01:11:03Z", "ageSeconds": 7.6,
          "windows": [
            {"kind": "5h",  "pct": 0,  "resetsAt": "2026-09-09T05:59:59Z"},
            {"kind": "7d",  "pct": 19, "resetsAt": "2026-09-15T10:59:59Z",
             "pace": {"expectedPct": 20.3, "ahead": true,
                      "exhaustsAt": null, "lastsToReset": true}},
            {"kind": "scoped", "name": "Fable", "pct": 29,
             "resetsAt": "2026-09-15T10:59:59Z"}
          ],
          "lastGood": {"fetchedAt": "…", "ageSeconds": 0, "windows": []}
        }
      ]
    }
  ]
}
```

- `windows[].kind` ∈ `5h | 7d | daily | monthly | scoped | spend`.
  `pct` is always present (0–100, above 100 for overage); `spend`
  adds `used/limit/currency`. `resetsAt` may be absent (spend, or an
  unknown reset).
- `usageStatus` ∈ `ok | stale | relogin-required | token-expired |
  no-credentials | api-key | unsupported`. `stale` means `windows` is
  the last good fetch, `ageSeconds` says how old.
- `lastGood` appears only when the live fetch failed and an older good
  fetch exists.
- Countdown/clock strings are NOT in the contract (the app formats).

### Verbs

| verb | effect | notes |
|---|---|---|
| `list` | read | above |
| `refresh [--slot n]` | write (usage store) | forces one fetch for slot n past the serve floor; without `--slot`, every stale slot. Returns `list`. |
| `switch <slot\|email\|alias>` | write | activates that login under the CLI's locks; returns `{switched, from, to}` |
| `rotate [--strategy consume-first\|best\|next-available]` | write | the auto loop's choice, once |
| `reorder <slot>…` | write | rotation order, every slot exactly once |
| `hold <slot>` / `unhold <slot>` | write | out of / back into rotation |
| `alias <slot> <name\|--unset>` | write | |
| `icon <slot> <emoji\|--unset>` | write | |
| `prefer <slot> on\|off` | write | the auto loop lands on preferred slots first |
| `add [--slot n]` | write | captures the CLI's current live login into a slot |
| `add-token -` | write | raw token / API key from stdin |
| `remove <slot> --yes` | write | |
| `export <path\|->` [--slot n] [--full] | read | swapd envelope (section 9) |
| `import <path> [--force]` | write | swapd envelope, or cswap's `export` envelope |
| `ignite <slot>` | human | the driver's cheapest request under that slot's login, then `refresh --slot`; returns `list` |
| `run <slot> -- <args>` | human | the CLI as that slot, this process only |
| `auto --json` | daemon | NDJSON events (section 6) |
| `config list\|get\|set\|unset` | | `settings.json` keys below |
| `history [--limit n]` | read | switches, oldest last |
| `notify` | read | which push channels are set (masked) |
| `version` | | `swapd 0.1.0` |
| `doctor` | read | installed CLIs, keychain reachability, lock dirs, store health |

Every write verb is refused with `locked` while `auto` holds the
provider's engine mutex for a switch in flight (the app's supervisor
already understands a refusal event).

### `settings.json` keys (per provider, `<provider>.` prefix; `claude.`
matches cswap's `autoswitch.*` semantics one to one)

`enabled, threshold, intervalSeconds, cooldownSeconds, hysteresisPct,
strategy, preferred, model, unhealthyTicks`.

## 5. Driver interface

```rust
pub trait Driver: Send + Sync {
    fn id(&self) -> &'static str;                       // "claude"
    fn installed(&self) -> Option<PathBuf>;             // the CLI on this machine
    /// The CLI's live login for the current environment.
    fn read_live(&self, env: &Env) -> Result<Login, DriverError>;
    /// Replace it, under the CLI's own locks; preserve state the login
    /// does not own (Claude: MCP OAuth tokens, non-account config).
    fn write_live(&self, env: &Env, login: &Login) -> Result<(), DriverError>;
    fn identity(&self, login: &Login) -> Result<Identity, DriverError>; // email, org, plan
    fn refresh(&self, login: &Login) -> Result<Login, DriverError>;     // TokenDead on invalid_grant
    fn usage(&self, login: &Login) -> Result<Usage, DriverError>;       // windows[]; Throttled{retry_after}
    fn ignite(&self, login: &Login) -> Result<(), DriverError>;         // one minimal request
    fn run_env(&self, login: &Login) -> Result<RunProfile, DriverError>; // per-process profile; Drop cleans up
    fn capabilities(&self) -> Caps;                                     // ignite, add_token, prefer, refresh…
}
```

`DriverError` is an enum (`NotInstalled`, `NoLogin`, `TokenDead`,
`Throttled { retry_after: Option<Duration> }`, `Locked`, `Io`, `Http`,
`Unsupported`) mapped one-to-one onto the JSON error codes.

`Login` is opaque bytes plus a fingerprint (refresh-token hash when one
exists, else content hash) — the core never parses provider tokens.

### Driver facts to verify per provider (each becomes its own sub-spec)

| provider | live login store | identity | usage | refresh | igniter | locks |
|---|---|---|---|---|---|---|
| claude | keychain `Claude Code-credentials[-<sha8 of CLAUDE_CONFIG_DIR>]`, `~/.claude.json` `oauthAccount` | bytes + `GET api.anthropic.com/api/oauth/profile` | `GET api.anthropic.com/api/oauth/usage` (beta `oauth-2025-04-20`) | `POST platform.claude.com/v1/oauth/token`, client id `9d1c250a-…` | `claude -p . --max-turns 1` under `CLAUDE_CONFIG_DIR` | `<config-home>/.oauth_refresh.lock`, `~/.claude.lock`, `~/.claude.json.lock` (mkdir mutex, stale 60 s) |
| codex | `~/.codex/auth.json` or keychain when `cli_auth_credentials_store = "keychain"` (0.153 has no auth.json on this Mac — verify) | id_token claims | rate-limit headers / status endpoint — research | refresh endpoint — research | `codex exec -m … "."` | research |
| kiro | `~/Library/Application Support/kiro-cli/data.sqlite3` (+ `.refresh.lock`); Builder ID / Identity Center / social | `kiro-cli whoami` | monthly credits — research | SSO OIDC refresh — research | `kiro-cli chat --no-interactive "."` | `.refresh.lock` |
| gemini | `~/.gemini/oauth_creds.json` (+ `google_accounts.json` active/old) | id_token / userinfo | daily request quota — research | Google OAuth refresh | `gemini -p .` | research |
| grok (xAI official CLI) | research | research | research | research | research | research |

The Claude column is read from cswap (`credentials.py:110-122`,
`session.py:232-243`, `oauth.py:18-19,249,366`, `claude_locks.py`).
Every "research" cell is filled by inspecting the real files on this
Mac (key names only, never values) and the CLI's own source before
that driver's sub-spec is written.

## 6. Polling, switching, the daemon

- **Usage store** (`~/.swapd/usage.json`, one row per provider+slot):
  last good fetch, fetchedAt, error, backoff, claim lease, poll plan.
  Concurrent collectors (auto, list, Infinitus, a terminal) reserve
  slots atomically under a file lock; a claimed slot is skipped for
  `CLAIM_TTL_S`.
- **Serve floor 180 s**: a row younger than that is served without a
  fetch. `refresh --slot n` is the only bypass.
- **Cadence** per slot, adapted from movement: 180 s floor, active
  ceiling 300 s, idle candidate 300→600 s, exhausted 600 s, urgent
  60 s near the threshold with movement; ±10 % jitter.
- **429 is a throttle, not quota**: keep last good until the window's
  advertised reset; edge backoff 300 s; post-429 floor 360 s for an
  hour; AIMD ×1.5 up to 1800 s while 429s recur.
- **Dead token**: `invalid_grant` on refresh → `relogin-required`,
  quarantined from rotation until re-added or imported over.
- **Switch**: refresh the target first; take the CLI's locks; back up
  the live login into its slot (only if its fingerprint matches the
  slot, else preserve it as an unclaimed entry); write the target;
  preserve non-account state; release; append history; emit `switch`.
- **Auto loop** per enabled provider: every `intervalSeconds`, fetch
  what is due, decide (threshold, hysteresis, cooldown, preferred,
  strategy), switch or `no-switch{reason}`. Events (NDJSON, one per
  line): `poll, switch, no-switch, account-quarantined,
  account-unquarantined, all-exhausted, engine-refused, error`, each
  with `schemaVersion, event, ts, provider`. Under `SWAPD_SUPERVISED=1`
  the daemon exits on stdin EOF.

## 7. Infinitus adapter

- `Sources/InfinitusCore/Engines/Swapd/`: `SwapdCLI` (subprocess,
  same continuation pattern as `CswapCLI`), `SwapdEngine`
  (`AccountEngine`, one `EngineFleet` per provider from one `list`),
  `SwapdSupervisor` (reuses `SupervisorBackoff` and `EventFeed` with
  `provider` on each event).
- Capabilities: today's set plus `refreshAccount`; `ignite` maps to
  `swapd ignite`. `AppModel.ignite` calls it and publishes the
  returned list — the "nothing happens" (#338) closes for good.
- Neutral `Account` gains `windows` (the existing `usage.fiveHour /
  sevenDay / scoped` are derived from it for the phone's decoder until
  the phone learns `windows`).
- The Engines pane lists swapd beside cswap; both may be on during the
  transition; the app never assumes either exists. Binary lookup:
  `INFINITUS_SWAPD_CLI` (e2e stub) → `/opt/homebrew/bin/swapd`,
  `/usr/local/bin/swapd`, `~/.local/bin/swapd`.
- `tools/e2e.sh` gains a `swapd` stub answering `list --json`,
  `refresh`, `ignite`, `auto --json`.

## 8. Ported verbatim from cswap (source of truth, file:line)

| behaviour | cswap |
|---|---|
| serve floor, cadences, 429 constants, AIMD | `poll_policy.py:75-140` |
| claim leases, stale-on-error, 429 trust bound | `usage_store.py:54-120, 309-350` |
| Claude Code lock handshake (two locks, order, stale 60 s, retry) | `claude_locks.py:1-60` |
| keychain service naming, fallback order, sticky file fallback | `credentials.py:69-140`, `session.py:232-243` |
| OAuth endpoints, client id, beta header, expiry buffer | `oauth.py:16-19, 140-161, 249, 366-370` |
| usage payload → windows (incl. `weekly_scoped`) | `oauth.py:478-498` |
| switch: preserve MCP OAuth state, back up only matching fingerprint | `switcher.py:6270-6810` |
| export envelope (import compatibility) | `transfer.py:164-330` |

## 9. Storage

```
~/.swapd/                      (Linux: $XDG_DATA_HOME/swapd, Windows: %APPDATA%\swapd)
  slots.json                   provider → slots (email, org, alias, icon, disabled, added, fingerprint)
  usage.json                   the usage store
  settings.json
  history.jsonl
  auto-state.json              cooldowns, quarantine
  credentials/<provider>/<slot>   0600 files (non-macOS)
  profiles/<provider>/<slot>/  per-slot run profiles
  swapd.log
```

macOS credentials: keychain service `swapd`, account
`<provider>:<slot>`. Export envelope: `{"format":"swapd/1",
"exportedAt", "providers":[{provider, activeSlot, accounts:[{slot,
email, org…, alias, icon, credentials, config?}]}]}`; import also
accepts cswap's `{"version":…, "accounts":[…]}` as provider `claude`.

## 10. Testing

- Rust: unit tests beside each module; `httpmock` fixtures per driver
  (usage, refresh, profile) recorded once with values scrubbed, never
  live tokens; a `Secrets` trait with an in-memory fake and a temp
  `HOME` for every store test; `assert_cmd` end-to-end runs of the
  binary; a lock-contention test with two processes.
- Golden parity: `swapd list --json --provider claude` mapped back to
  cswap's shape must equal `cswap list --json` on this Mac's seven
  accounts (a one-off script during the transition, not CI).
- Infinitus: `SwapdEngine` fixture tests; e2e with the stub; the perf
  gate unchanged.

## 11. Phases

1. **Core + Claude driver + `list/refresh/switch/add/import/ignite/auto`**,
   Infinitus adapter behind the Engines pane, cswap still on. Exit
   criterion: a week of parity on this Mac, the ignite fix live.
2. **Rest of the verbs** (reorder, hold, alias, icon, prefer, remove,
   export, history, notify, doctor) and cutover: cswap off by default.
3. **Codex driver** (sub-spec first). 4. **Kiro**. 5. **Gemini**.
6. **Grok** (xAI official CLI). Each driver ships with its fixtures
   and its Engines-pane row; the phone shows it through `windows`.

## 12. Out of scope

TUI, directory mappings, session resume, cmux, Slack/Telegram sending
(status only), encryption of exports, a resident daemon beyond `auto`.
