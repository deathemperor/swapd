# Changelog

## 0.1.0 — unreleased

- `list`/`refresh`: the JSON contract, `--json` on every verb, `schemaVersion` 1.
- `add`/`add-token`/`import`/`export`: capture, register and move accounts between machines.
- `switch`/`rotate`/`history`: activate an account, let a strategy pick one, read the switch log.
- `config`: read and set the per-provider policy knobs.
- `auto`: the switching daemon, streaming NDJSON events.
- `ignite`/`run`: start a usage window, or run the CLI as one account without touching the live login.
- Secrets backends: macOS keychain via `security`, a file store, an in-memory store for tests.
- Platforms: macOS, Linux, Windows.
- `doctor` reports the live store, secrets backend, engine/auto lock state (with the daemon pid), profile dirs and the CLI version (#7).
