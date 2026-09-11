"""Tests for tools/parity.py's mapping and diff functions — no subprocess,
no real `swapd`/`cswap` binary. Run with `python3 -m unittest tests/parity_test.py`."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "parity", Path(__file__).resolve().parents[1] / "tools" / "parity.py"
)
parity = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(parity)


def swapd_account(**overrides) -> dict:
    base = {
        "slot": 1,
        "email": "You@Example.com",
        "alias": "death2",
        "active": True,
        "usageStatus": "ok",
        "windows": [
            {"kind": "5h", "pct": 10, "resetsAt": "2026-09-09T05:59:59Z"},
            {
                "kind": "7d",
                "pct": 19,
                "resetsAt": "2026-09-15T10:59:59Z",
                "pace": {"expectedPct": 20.3, "ahead": True, "lastsToReset": True},
            },
            {"kind": "scoped", "name": "Fable", "pct": 29, "resetsAt": "2026-09-15T10:59:59Z"},
        ],
    }
    base.update(overrides)
    return base


def cswap_account(**overrides) -> dict:
    base = {
        "number": 1,
        "email": "you@example.com",
        "alias": "death2",
        "active": True,
        "usageStatus": "ok",
        "usage": {
            "fiveHour": {"pct": 10, "resetsAt": "2026-09-09T05:59:59Z"},
            "sevenDay": {"pct": 19, "resetsAt": "2026-09-15T10:59:59Z", "expectedPct": 20.3},
            "scoped": [{"name": "Fable", "pct": 29, "resetsAt": "2026-09-15T10:59:59Z"}],
        },
    }
    base.update(overrides)
    return base


class NormalizeTsTest(unittest.TestCase):
    def test_z_and_offset_are_equal(self):
        self.assertEqual(
            parity.normalize_ts("2026-09-09T05:59:59Z"),
            parity.normalize_ts("2026-09-09T05:59:59+00:00"),
        )

    def test_non_utc_offset_normalizes_to_z(self):
        self.assertEqual(
            parity.normalize_ts("2026-09-09T10:59:59+05:00"),
            "2026-09-09T05:59:59Z",
        )

    def test_none_passthrough(self):
        self.assertIsNone(parity.normalize_ts(None))


class MapAccountTest(unittest.TestCase):
    def test_swapd_maps_windows_to_cswap_shape(self):
        mapped = parity.map_swapd_account(swapd_account())
        self.assertEqual(mapped["usage"]["fiveHour"], {"pct": 10, "resetsAt": "2026-09-09T05:59:59Z"})
        self.assertEqual(mapped["usage"]["sevenDay"]["pct"], 19)
        self.assertEqual(mapped["usage"]["scoped"], [{"name": "Fable", "pct": 29, "resetsAt": "2026-09-15T10:59:59Z"}])
        self.assertEqual(mapped["number"], 1)
        self.assertEqual(mapped["usageStatus"], "ok")

    def test_usage_status_kebab_to_snake(self):
        for swapd_status, cswap_status in [
            ("relogin-required", "relogin_required"),
            ("token-expired", "token_expired"),
            ("no-credentials", "no_credentials"),
            ("api-key", "api_key"),
        ]:
            mapped = parity.map_swapd_account(swapd_account(usageStatus=swapd_status))
            self.assertEqual(mapped["usageStatus"], cswap_status)

    def test_stale_maps_to_ok(self):
        mapped = parity.map_swapd_account(swapd_account(usageStatus="stale"))
        self.assertEqual(mapped["usageStatus"], "ok")

    def test_alias_absent_becomes_empty_string(self):
        account = swapd_account()
        del account["alias"]
        mapped = parity.map_swapd_account(account)
        self.assertEqual(mapped["alias"], "")


class DiffAccountTest(unittest.TestCase):
    def test_identical_accounts_all_ok(self):
        rows = parity.diff_account(parity.map_cswap_account(cswap_account()), parity.map_swapd_account(swapd_account()))
        self.assertTrue(rows)
        self.assertTrue(all(v == "OK" for _, _, _, v in rows))

    def test_pct_off_by_one_is_ok(self):
        swapd = swapd_account()
        swapd["windows"][0]["pct"] = 11
        rows = parity.diff_account(parity.map_cswap_account(cswap_account()), parity.map_swapd_account(swapd))
        row = next(r for r in rows if r[0] == "fiveHour.pct")
        self.assertEqual(row[3], "OK")

    def test_pct_off_by_two_mismatches(self):
        swapd = swapd_account()
        swapd["windows"][0]["pct"] = 12
        rows = parity.diff_account(parity.map_cswap_account(cswap_account()), parity.map_swapd_account(swapd))
        row = next(r for r in rows if r[0] == "fiveHour.pct")
        self.assertEqual(row[3], "MISMATCH")

    def test_resets_at_one_second_apart_is_ok(self):
        # The endpoint's weekly reset straddles the hour boundary between fetches.
        cswap = cswap_account()
        cswap["usage"]["sevenDay"]["resetsAt"] = "2026-09-15T11:00:00Z"
        rows = parity.diff_account(parity.map_cswap_account(cswap), parity.map_swapd_account(swapd_account()))
        row = next(r for r in rows if r[0] == "sevenDay.resetsAt")
        self.assertEqual(row[3], "OK")

    def test_resets_at_two_seconds_apart_mismatches(self):
        cswap = cswap_account()
        cswap["usage"]["sevenDay"]["resetsAt"] = "2026-09-15T11:00:01Z"
        rows = parity.diff_account(parity.map_cswap_account(cswap), parity.map_swapd_account(swapd_account()))
        row = next(r for r in rows if r[0] == "sevenDay.resetsAt")
        self.assertEqual(row[3], "MISMATCH")

    def test_resets_at_offset_vs_z_matches(self):
        cswap = cswap_account()
        cswap["usage"]["fiveHour"]["resetsAt"] = "2026-09-09T05:59:59+00:00"
        rows = parity.diff_account(parity.map_cswap_account(cswap), parity.map_swapd_account(swapd_account()))
        row = next(r for r in rows if r[0] == "fiveHour.resetsAt")
        self.assertEqual(row[3], "OK")

    def test_alias_mismatch(self):
        swapd = swapd_account(alias="different")
        rows = parity.diff_account(parity.map_cswap_account(cswap_account()), parity.map_swapd_account(swapd))
        row = next(r for r in rows if r[0] == "alias")
        self.assertEqual(row[3], "MISMATCH")

    def test_a_mismatch_carries_swapd_fetch_note(self):
        swapd = swapd_account(alias="different", usageStatus="stale", lastError="http-429",
                              backoffUntil="2026-09-09T06:00:00+00:00")
        rows = parity.diff_account(parity.map_cswap_account(cswap_account()), parity.map_swapd_account(swapd))
        note = rows[-1]
        self.assertEqual(note[0], "swapd.fetch")
        self.assertEqual(note[3], "NOTE")
        self.assertIn("stale", note[2])
        self.assertIn("lastError http-429", note[2])
        self.assertIn("backoff until 2026-09-09T06:00:00Z", note[2])

    def test_a_stale_row_compares_its_last_good_windows(self):
        swapd = swapd_account(usageStatus="stale")
        swapd["lastGood"] = {"fetchedAt": "2026-09-09T01:00:00Z", "ageSeconds": 480.0, "windows": swapd.pop("windows")}
        swapd["windows"] = []
        rows = parity.diff_account(parity.map_cswap_account(cswap_account()), parity.map_swapd_account(swapd))
        self.assertTrue(all(r[3] == "OK" for r in rows), rows)

    def test_a_clean_account_carries_no_note(self):
        rows = parity.diff_account(parity.map_cswap_account(cswap_account()), parity.map_swapd_account(swapd_account()))
        self.assertFalse(any(r[3] == "NOTE" for r in rows))

    def test_note_rows_do_not_count_as_fields(self):
        import contextlib, io
        diff = {"you@example.com": [("alias", "a", "b", "MISMATCH"), ("swapd.fetch", "", "stale", "NOTE")]}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mismatches = parity._print_table(diff)
        self.assertEqual(mismatches, 1)
        self.assertIn("0/1 fields match", out.getvalue())


class BuildDiffTest(unittest.TestCase):
    def _payloads(self, cswap_accounts, swapd_accounts):
        cswap_payload = {"schemaVersion": 1, "activeAccountNumber": 1, "accounts": cswap_accounts}
        swapd_payload = {
            "schemaVersion": 1,
            "providers": [{"provider": "claude", "installed": True, "accounts": swapd_accounts}],
        }
        return cswap_payload, swapd_payload

    def test_email_join_is_case_insensitive(self):
        cswap_payload, swapd_payload = self._payloads([cswap_account()], [swapd_account()])
        diff = parity.build_diff(cswap_payload, swapd_payload)
        self.assertIn("you@example.com", diff)
        self.assertTrue(all(v == "OK" for _, _, _, v in diff["you@example.com"]))

    def test_account_only_on_one_side_is_a_mismatch(self):
        cswap_payload, swapd_payload = self._payloads([cswap_account()], [])
        diff = parity.build_diff(cswap_payload, swapd_payload)
        rows = diff["you@example.com"]
        self.assertEqual(rows, [("present", "yes", "no", "MISMATCH")])


if __name__ == "__main__":
    unittest.main()
