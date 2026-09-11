# swapd

[![CI](https://github.com/deathemperor/swapd/actions/workflows/ci.yml/badge.svg)](https://github.com/deathemperor/swapd/actions/workflows/ci.yml)

swapd is a multi-provider account switcher for AI coding CLIs (Claude Code
and Gemini CLI today; Codex, Kiro and Grok are planned). It tracks a fleet of
logins per provider, polls each one's usage, and switches the CLI's live
login when a policy says to — by hand (`switch`, `rotate`) or unattended
(`auto`). Every verb speaks `--json`, so swapd is as usable as a library
called from another program (it is the engine behind
[Infinitus](https://infinitus.run)) as it is from a terminal.

## Install

Download a release archive for your platform from the
[releases page](https://github.com/deathemperor/swapd/releases), or build
from source:

```sh
cargo install --git https://github.com/deathemperor/swapd swapd
```

## Verbs

| verb | effect |
|---|---|
| `version` | print the swapd version |
| `doctor` | check the local environment: stores, locks, profiles, CLI version |
| `list` | list every account, its usage and the rotation |
| `refresh [--slot n]` | fetch usage now, then list |
| `add [--slot n] [--alias name] [--force]` | capture the CLI's current live login into a slot, moving it there if it already owns a different one |
| `add-token - [--slot n] [--email addr] [--alias name] [--force]` | register a raw OAuth setup token or API key read from stdin |
| `import <path\|-> [--force]` | import accounts from an export file |
| `export <path\|-> [--slot n] [--full]` | write an export envelope to a file |
| `switch <ident>` | make an account the live login, by slot number, alias or email |
| `rotate [--strategy s]` | switch to the next account a strategy picks |
| `auto` | run the switching daemon: poll usage, switch when policy says to |
| `ignite <ident>` | start an account's usage window: one short run in its own profile |
| `run <ident> -- <args>` | run the provider's CLI as one account, without touching the live login |
| `alias <ident> [name\|--unset]` | set or clear a slot's short name |
| `icon <ident> [icon\|--unset]` | set or clear a slot's icon |
| `prefer <ident> on\|off` | pin or unpin an account the rotation lands on first |
| `hold <ident>` / `unhold <ident>` | take an account out of / back into the rotation |
| `reorder <idents>…` | set the rotation order: every slot, exactly once |
| `remove <ident> --yes` | forget an account: its login, run profile and slot |
| `config list\|get\|set\|unset` | read or change the `settings.json` knobs |
| `history [--limit n]` | the switch log, newest last |
| `unclaimed [--purge id]` | list, or drop, logins a switch stashed because they matched no slot |
| `notify` | which push channels are configured, masked |

`ident` is a slot number, alias or email. Every verb accepts `--json` for
machine-readable output; `--provider <name>` picks a provider other than the
default (`claude`).

`export --full` embeds the active account's whole `~/.claude.json` — which
includes its project paths and prompt history — beside the credentials, so
treat a `--full` export as the same kind of secret as the login itself. A plain
`export` carries the logins and the slot rows only.

## The JSON contract

Every verb's `--json` output starts with `"schemaVersion": 1`, so a caller
can detect a breaking change before it breaks. The full contract — `list`'s
shape, every verb's effect, `auto`'s NDJSON event stream — is
`docs/superpowers/specs/2026-09-09-swapd-design.md` (section 4).

## Environment variables

| variable | effect |
|---|---|
| `SWAPD_HOME` | the data directory, overriding the platform default |
| `SWAPD_SECRETS` | `file` \| `memory` — overrides the secrets backend (macOS default is the login keychain) |
| `SWAPD_LIVE_STORE` | `file` \| `keychain` — overrides where the Claude CLI's live login is written |
| `SWAPD_URL_ANTHROPIC_API` | overrides the Anthropic API base URL |
| `SWAPD_URL_PLATFORM` | overrides the platform (console) base URL |
| `SWAPD_CLAUDE_CLI` | the `claude` binary to run, overriding PATH lookup |
| `SWAPD_SUPERVISED` | set to `1` by a supervisor holding `auto`'s stdin open; the daemon exits when it sees EOF |

## Storage

```
~/.swapd/                      (Linux: $XDG_DATA_HOME/swapd, Windows: %APPDATA%\swapd)
  slots.json                   provider -> slots (email, org, alias, icon, disabled,
                               order, and each slot's credential fingerprint)
  usage.json                   the usage store
  settings.json                per-provider policy knobs
  notify.json                  the configured push channels (`notify`)
  history.jsonl                the switch log, append-only
  auto-state.json              cooldowns, quarantine
  credentials/<provider>_<slot>   0600 files (non-macOS; macOS default is the login keychain)
  profiles/<provider>/<slot>/  per-slot run profiles (`ignite`, `run`)
  engine.lock                  the live login's fence: every read of it
                               (list, add, export, run) and every write
  refresh-<provider>-<slot>.lock  held for one slot's token refresh
  auto.lock                    the `auto` daemon's mutex, one per data dir
```

## Security

Secrets travel over stdin, never argv (`add-token -`) — argv is visible to
every process on the machine. On macOS, logins are stored in the login
keychain via `/usr/bin/security` by default; everywhere else, and when
`SWAPD_SECRETS=file` overrides it, they are files under `credentials/`
readable only by the owner. swapd never reads another tool's state beyond
the provider's own login files (Claude Code's `.credentials.json`,
`.claude.json`); it does not read or write any other CLI's configuration.

## Migrate from cswap

1. Export your accounts by hand, from cswap: `cswap export ~/swapd-import.json`.
2. Import them into swapd: `swapd import ~/swapd-import.json`.
3. Check the two engines agree before trusting swapd:
   `python3 tools/parity.py` — it re-runs the import, then diffs
   `swapd list --json --provider claude` against `cswap list --json`
   (usage percentages, reset times, active slot, alias) and exits 1 on
   any mismatch. To keep the credentials off disk, pipe the export
   straight through: `cswap export - | python3 tools/parity.py --import -`.
4. While cswap is still the tool switching accounts, keep swapd in
   shadow: `export SWAPD_SHADOW=1` (parity.py sets it on its own swapd
   calls). A Claude refresh token is single-use, so a refresh swapd made
   would kill cswap's copy of that account; in shadow, `list` and
   `refresh` never refresh and never write Claude Code's live login, and
   `switch`, `auto`, `ignite`, `run` and `rotate` are refused. An account
   whose access token has expired reads `token-expired` on the swapd
   side until the next export carries cswap's rotation, so re-export
   before every parity run.
5. Point Infinitus at the swapd engine, in its Engines pane. Once cswap is
   off, run one last `cswap export - | swapd import -` (cswap's final
   rotations), then unset `SWAPD_SHADOW`.

swapd never reads cswap's state directly. The only two touchpoints
between the two tools are the export file you produce by hand and, only
inside `tools/parity.py`, a `cswap list --json` subprocess call for the
diff — swapd itself never runs or shells out to cswap.
