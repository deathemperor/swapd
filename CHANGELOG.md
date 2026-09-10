# Changelog

## 0.1.0 — unreleased

- Windows: a lock taken over as stale is no longer removed when its previous holder exits (#15).
- auto: one tick reads the live login and each slot's secret once, not once per pass (#1)
- add --slot n moves an account that already has a slot instead of duplicating it (#3)
- auto: a quarantine follows its credential when `add --slot` moves the account, instead of being dropped (#14)
- list --json says why the active slot is missing (`activeUnreadable`: switch-in-progress, keychain-unavailable, cli-busy) and auto reports `no-switch{switch-in-progress}` instead of no-active-account (#8)
- list waits 1 s for a switch to land before degrading, not 5 s (#8)
- `list`/`refresh`: the JSON contract, `--json` on every verb, `schemaVersion` 1.
- `add`/`add-token`/`import`/`export`: capture, register and move accounts between machines.
- `switch`/`rotate`/`history`: activate an account, let a strategy pick one, read the switch log.
- `config`: read and set the per-provider policy knobs.
- `auto`: the switching daemon, streaming NDJSON events.
- `ignite`/`run`: start a usage window, or run the CLI as one account without touching the live login.
- Secrets backends: macOS keychain via `security`, a file store, an in-memory store for tests.
- Platforms: macOS, Linux, Windows.
- `doctor` reports the live store, secrets backend, engine/auto lock state (with the daemon pid), profile dirs and the CLI version (#7).
- unclaimed: a stashed login that matched no slot is recorded in a manifest, listed by `swapd unclaimed`, dropped with `--purge`, and carried by `export` (#2).
- Gemini CLI accounts: `--provider gemini` for list, add, switch, refresh, ignite, run and auto, over the CLI's oauth-personal login.
