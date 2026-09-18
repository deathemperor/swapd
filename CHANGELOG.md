# Changelog

## Unreleased

- `swapd auto-ignite <ident> on|off` keeps an account's 5h window running: on every tick the daemon ignites the first flagged account whose 5h window has gone cold (no 5h reset ahead on an account that reports a 7d window), skipping the active account, held, quarantined and API-key accounts, accounts it could not measure this tick, and accounts whose 7d or scoped window is 95% spent; each slot is then left alone for 20 minutes, since the endpoint shows the new window minutes after the run. The flag travels on `list --json` as `autoIgnite`, and the run is reported on a new `ignited` event (`ok`, `detail`), never as the tick's error. `import` does not carry the flag: it is a policy of the machine running the daemon.

## 0.2.2 — 2026-09-18

- Weekly account gauges report ahead/behind pace starting one minute after reset instead of staying blank for the first day.

## 0.2.1 — 2026-09-17

- Automatic account switching recovers after a temporary macOS Keychain failure instead of reporting no candidates until the daemon restarts. Keychain retries back off for one minute, and credentials saved during the outage remain usable.

## 0.2.0 — 2026-09-15

- `swapd limit-hit <ident> [--resets-at <rfc3339>]` records a refusal the consumer saw before the usage endpoint could: the mark overrides the stored 5-hour window at the one decision point `auto`, `list`'s `nextCandidate` and `rotate` read, is believed while the reported reset is ahead or until a later measurement lands, and a supervised daemon (`SWAPD_SUPERVISED=1`) re-evaluates on any stdin line instead of discarding it, so the switch happens now rather than a poll later (#38).
- `swapd --json --provider <p> add-oauth` signs an account in through the browser: swapd is the OAuth client, prints the sign-in URL once its loopback listener is up, catches the redirect itself (the PKCE verifier never leaves the process) and prints the `add` envelope once the account is stored (#39).
- A credential carrying no refresh token reports `relogin-required` instead of `token-expired`: nothing can renew it, so naming a retry that can never land left the status stuck on "retrying" forever (#30).
- `refresh --slot n` now fetches through the failure backoff, which was a cadence rule for automatic passes and silently dropped an explicit ask; the reply's `skipped` names the two gates a force still does not override (a live claim, a dead-token quarantine) rather than returning the unchanged list as if the fetch had happened (#31).
- The plan label is re-derived each pass from the credential the collector already holds, instead of being frozen at `add` time: an account whose tier changed went on advertising the one it was captured on, and an account added while another was live never got a label at all, because the envelope's `oauthAccount` describes only the live account. The re-stamp is offline (no fetch, no extra secret read), skips a credential naming a different account, and a credential advertising no plan leaves the stored label alone (#35).
- ignite: the forced re-fetch after the run is repeated on a short backoff (3, 7, 15, 30 s) while the usage endpoint still reads the account as cold, and the reply's `ignited.windowSeen` says whether the 5h window ever showed a reset ahead; the human line adds "window not visible yet" when it did not.
- `list` (text): an account with no 5h/7d window — the Gemini shape, one scoped bucket per model — names its binding bucket (`gemini-2.5-pro 75%`) where the two columns go, instead of reading `- / -` about an account swapd had just measured (#18).
- tests: `supervised_exits_on_stdin_eof` gives the EOF exit 10 s instead of 2 s and reports the time it took when it runs long. The 2 s was asserting the runner's scheduling, not the daemon's behaviour — it failed once on a loaded macos-14 runner and the rerun of the same sha passed everywhere; a watcher that never fires still fails the test (#19).
- ignite: a rotation the run made survives a failure that produced no exit status. The Gemini igniter refreshes and retries the quota call, and a retry that failed for its own reasons (a 500, a timeout) used to drop the refreshed credential — losing the new refresh token when the reply carried one (#18).

## 0.1.0 — 2026-09-11

- list --json carries `lastKnownActiveSlot` beside `activeUnreadable` so a reader keeps the active slot through a switch (#28)
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
