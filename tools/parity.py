#!/usr/bin/env python3
"""Parity check between swapd and cswap for the `claude` provider.

Runs `swapd import <path>` (an export the user produced by hand with
`cswap export <path>`), then diffs `swapd list --json --provider claude`
against `cswap list --json`: same accounts, same usage numbers, same
active slot. Exits 1 on any mismatch, 0 when everything matches.

Never reads `~/.claude-swap-backup/*` or any other cswap state; the only
cswap touchpoints are the `cswap list --json` subprocess and the export
file the user already produced (read only by `swapd import`, never by
this script).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# swapd's kebab-case usageStatus -> cswap's snake_case usageStatus
# (json_output.py:155-167). `stale` and `ok` both count as cswap's `ok`:
# swapd's `stale` means "serving the last good fetch", which is what
# cswap's `ok` also does when it isn't past STALE_OK_S. cswap emits a few
# statuses swapd's contract has no equivalent for (`keychain_unavailable`,
# `foreign_credential`, `unavailable`) — those are left unmapped so a
# swapd/cswap disagreement there surfaces as a real mismatch, not noise.
USAGE_STATUS_MAP = {
    "ok": "ok",
    "stale": "ok",
    "relogin-required": "relogin_required",
    "token-expired": "token_expired",
    "no-credentials": "no_credentials",
    "api-key": "api_key",
    "unsupported": "unsupported",
}


def normalize_ts(raw: str | None) -> str | None:
    """Parse an RFC 3339 timestamp and reprint it as UTC, seconds precision,
    `Z` suffix — cswap's own `isoformat(timespec="seconds").replace("+00:00",
    "Z")` convention (json_output.py:83)."""
    if not raw:
        return raw
    s = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalize_window_resets_at(window: dict | None) -> dict | None:
    if not window or not window.get("resetsAt"):
        return window
    out = dict(window)
    out["resetsAt"] = normalize_ts(out["resetsAt"])
    return out


def map_swapd_account(account: dict) -> dict:
    """Map one `swapd list --json` account (contract.rs `AccountView`) to
    cswap's `account_row` shape (json_output.py:213), the subset this script
    compares."""
    usage: dict = {"fiveHour": None, "sevenDay": None, "spend": None, "scoped": []}
    for window in account.get("windows") or []:
        kind = window.get("kind")
        mapped = _normalize_window_resets_at(window)
        if kind == "5h":
            usage["fiveHour"] = {"pct": mapped.get("pct"), "resetsAt": mapped.get("resetsAt")}
        elif kind == "7d":
            usage["sevenDay"] = {"pct": mapped.get("pct"), "resetsAt": mapped.get("resetsAt")}
        elif kind == "spend":
            usage["spend"] = {
                "pct": mapped.get("pct"),
                "resetsAt": mapped.get("resetsAt"),
                "used": mapped.get("used"),
                "limit": mapped.get("limit"),
                "currency": mapped.get("currency"),
            }
        elif kind == "scoped":
            usage["scoped"].append(
                {"name": mapped.get("name"), "pct": mapped.get("pct"), "resetsAt": mapped.get("resetsAt")}
            )
        # `daily`/`monthly` windows have no cswap equivalent (claude never
        # emits them); nothing to compare them against.
    status = account.get("usageStatus")
    return {
        "number": account.get("slot"),
        "email": account.get("email") or "",
        "alias": account.get("alias") or "",
        "active": bool(account.get("active")),
        "usageStatus": USAGE_STATUS_MAP.get(status, status),
        "usage": usage,
    }


def map_cswap_account(account: dict) -> dict:
    """Normalize one `cswap list --json` account row to the same shape
    `map_swapd_account` produces, so the two sides diff field-for-field."""
    usage_in = account.get("usage") or {}
    scoped = [_normalize_window_resets_at(w) for w in usage_in.get("scoped") or []]
    usage = {
        "fiveHour": _normalize_window_resets_at(usage_in.get("fiveHour")),
        "sevenDay": _normalize_window_resets_at(usage_in.get("sevenDay")),
        "spend": _normalize_window_resets_at(usage_in.get("spend")),
        "scoped": scoped,
    }
    return {
        "number": account.get("number"),
        "email": account.get("email") or "",
        "alias": account.get("alias") or "",
        "active": bool(account.get("active")),
        "usageStatus": account.get("usageStatus"),
        "usage": usage,
    }


def _diff_scalar(field: str, cswap_val, swapd_val, rows: list) -> None:
    verdict = "OK" if cswap_val == swapd_val else "MISMATCH"
    rows.append((field, cswap_val, swapd_val, verdict))


def _diff_pct(field: str, cswap_val, swapd_val, rows: list) -> None:
    if cswap_val is None or swapd_val is None:
        verdict = "OK" if cswap_val == swapd_val else "MISMATCH"
    else:
        verdict = "OK" if abs(cswap_val - swapd_val) <= 1 else "MISMATCH"
    rows.append((field, cswap_val, swapd_val, verdict))


def _diff_window(prefix: str, cswap_win: dict | None, swapd_win: dict | None, rows: list) -> None:
    if cswap_win is None and swapd_win is None:
        return
    _diff_pct(f"{prefix}.pct", (cswap_win or {}).get("pct"), (swapd_win or {}).get("pct"), rows)
    _diff_resets_at(
        f"{prefix}.resetsAt", (cswap_win or {}).get("resetsAt"), (swapd_win or {}).get("resetsAt"), rows
    )


def _diff_resets_at(field: str, cswap_val, swapd_val, rows: list) -> None:
    """`resetsAt` within one second is a match. The endpoint reports the
    weekly reset with a sub-second fraction that lands either side of the hour
    boundary from one fetch to the next (`…14:59:59.876` then `…15:00:00.045`),
    so two engines that fetched at different moments disagree by a second at
    seconds precision — swapd copies the value verbatim, per spec."""
    if cswap_val is None or swapd_val is None:
        verdict = "OK" if cswap_val == swapd_val else "MISMATCH"
    else:
        delta = abs(_epoch(cswap_val) - _epoch(swapd_val))
        verdict = "OK" if delta <= 1.0 else "MISMATCH"
    rows.append((field, cswap_val, swapd_val, verdict))


def _epoch(normalized: str) -> float:
    return datetime.fromisoformat(normalized.replace("Z", "+00:00")).timestamp()


def diff_account(cswap_row: dict, swapd_row: dict) -> list[tuple[str, object, object, str]]:
    """`(field, cswap_value, swapd_value, verdict)` rows for one account,
    already mapped to the shared shape."""
    rows: list[tuple[str, object, object, str]] = []
    _diff_scalar("active", cswap_row["active"], swapd_row["active"], rows)
    _diff_scalar("alias", cswap_row["alias"], swapd_row["alias"], rows)
    _diff_scalar("usageStatus", cswap_row["usageStatus"], swapd_row["usageStatus"], rows)
    _diff_window("fiveHour", cswap_row["usage"]["fiveHour"], swapd_row["usage"]["fiveHour"], rows)
    _diff_window("sevenDay", cswap_row["usage"]["sevenDay"], swapd_row["usage"]["sevenDay"], rows)
    _diff_window("spend", cswap_row["usage"]["spend"], swapd_row["usage"]["spend"], rows)
    cswap_scoped = {w.get("name"): w for w in cswap_row["usage"]["scoped"]}
    swapd_scoped = {w.get("name"): w for w in swapd_row["usage"]["scoped"]}
    for name in sorted(set(cswap_scoped) | set(swapd_scoped), key=lambda n: (n is None, n)):
        _diff_window(f"scoped[{name}]", cswap_scoped.get(name), swapd_scoped.get(name), rows)
    return rows


def build_diff(cswap_payload: dict, swapd_payload: dict) -> dict[str, list[tuple[str, object, object, str]]]:
    """Join cswap's flat account list against swapd's `providers[provider ==
    'claude'].accounts`, by email, case-insensitive. Returns `{email: rows}`;
    an account present on only one side is one `"present"` mismatch row."""
    cswap_accounts = {
        a.get("email", "").lower(): map_cswap_account(a) for a in cswap_payload.get("accounts", [])
    }
    claude = next(
        (p for p in swapd_payload.get("providers", []) if p.get("provider") == "claude"),
        {"accounts": []},
    )
    swapd_accounts = {
        a.get("email", "").lower(): map_swapd_account(a) for a in claude.get("accounts", [])
    }

    diff: dict[str, list[tuple[str, object, object, str]]] = {}
    for email in sorted(set(cswap_accounts) | set(swapd_accounts)):
        cswap_row = cswap_accounts.get(email)
        swapd_row = swapd_accounts.get(email)
        if cswap_row is None or swapd_row is None:
            diff[email] = [
                ("present", "yes" if cswap_row else "no", "yes" if swapd_row else "no", "MISMATCH")
            ]
            continue
        diff[email] = diff_account(cswap_row, swapd_row)
    return diff


# Parity is by definition the cswap-still-on flow: cswap owns the logins and
# their single-use refresh grants, so every swapd subprocess here runs in
# shadow (`SWAPD_SHADOW=1`: no refresh, no live-login write). An account whose
# access token has expired reads `token-expired` on the swapd side until the
# next export carries cswap's rotation — re-export before every run.
_SWAPD_ENV = {**os.environ, "SWAPD_SHADOW": "1"}


def _run_json(cmd: list[str]) -> dict:
    proc = subprocess.run(cmd, capture_output=True, text=True, env=_SWAPD_ENV)
    if proc.returncode != 0:
        # Never relay stderr here: cswap's `list --json` never touches the
        # import file, but keeping the two failure paths identical means one
        # rule to remember.
        sys.stderr.write(f"{' '.join(cmd)} failed (exit {proc.returncode}); run it by hand for the reason\n")
        sys.exit(2)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"{' '.join(cmd)} did not print JSON: {e}\n")
        sys.exit(2)


def _run_import(path: str) -> None:
    # `-` relays this process's stdin, so `cswap export - | parity.py --import -`
    # never puts a credentials file on disk.
    stdin = sys.stdin.read() if path == "-" else None
    proc = subprocess.run(
        ["swapd", "import", path], input=stdin, capture_output=True, text=True, env=_SWAPD_ENV
    )
    if proc.returncode != 0:
        # swapd import's error text can interpolate emails from the export
        # file (e.g. a duplicate-slot refusal) — never printed here.
        sys.stderr.write(f"swapd import {path} failed (exit {proc.returncode}); run it by hand for the reason\n")
        sys.exit(2)


def _print_table(diff: dict[str, list[tuple[str, object, object, str]]]) -> int:
    print(f"{'email':<32} {'field':<18} {'cswap':<24} {'swapd':<24} verdict")
    total = 0
    mismatches = 0
    for email, rows in diff.items():
        for field, cswap_val, swapd_val, verdict in rows:
            total += 1
            if verdict != "OK":
                mismatches += 1
            print(f"{email:<32} {field:<18} {str(cswap_val):<24} {str(swapd_val):<24} {verdict}")
    print(f"\n{total - mismatches}/{total} fields match across {len(diff)} account(s)")
    return mismatches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--import",
        dest="import_path",
        default=str(Path.home() / "swapd-import.json"),
        help="export file to import before diffing (default ~/swapd-import.json; `-` reads stdin)",
    )
    parser.add_argument("--no-import", action="store_true", help="skip the swapd import step")
    parser.add_argument("--json", action="store_true", help="print the diff as JSON instead of a table")
    args = parser.parse_args(argv)

    if not args.no_import:
        _run_import(args.import_path)

    swapd_payload = _run_json(["swapd", "list", "--json", "--provider", "claude"])
    cswap_payload = _run_json(["cswap", "list", "--json"])

    diff = build_diff(cswap_payload, swapd_payload)

    if args.json:
        payload = {
            email: [{"field": f, "cswap": c, "swapd": s, "verdict": v} for f, c, s, v in rows]
            for email, rows in diff.items()
        }
        print(json.dumps(payload, indent=2))
        mismatches = sum(1 for rows in diff.values() for row in rows if row[3] != "OK")
    else:
        mismatches = _print_table(diff)

    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
