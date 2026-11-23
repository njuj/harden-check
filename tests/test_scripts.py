"""The fix/undo scripts and the command line."""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hardencheck import checks as C, fixes
from hardencheck.cli import main
from tests.snap import hardened


def weak():
    """A PC with something to fix in nearly every check, including names that need quoting."""
    s = hardened()
    s["reg"].update({C.R["llmnr"]: None, C.R["lmcompat"]: 2, C.R["wdigest"]: 1, C.R["hide_ext"]: 1, C.R["sblog"]: None,
                     C.R["cmdline"]: None, C.R["wsh"]: None, C.R["runasppl"]: None, C.R["rdp_deny"]: 0,
                     C.R["smartscreen"]: "Off", C.R["startopts"]: " TESTSIGNING"})
    s["ps"]["mppref"].update(pua=0, asr=[], cfa=0, excl_path=["C:\\"])
    s["ps"]["smbc"].update(signing=False, guest=True)
    s["ps"]["services"][0].update(status="Running", start="Automatic")
    s["ps"]["wlan"].append({"name": "Joe's \"Free\" WiFi", "auth": "open", "mode": "auto"})
    s["ps"]["adapters"][0]["netbios"] = 0
    s["ps"]["users"][0]["enabled"] = True
    return s


def cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Scripts(unittest.TestCase):
    def test_safe_level_leaves_caution_fixes_out(self):
        results = C.evaluate(weak())
        safe, caution = fixes.chosen(results, "safe"), fixes.chosen(results, "caution")
        self.assertTrue(all(c.fix.risk == "safe" for c in safe))
        self.assertGreater(len(caution), len(safe))
        apply, _ = fixes.scripts(results, "safe")
        self.assertNotIn("bcdedit", apply)
        self.assertNotIn("Disable-LocalUser", apply)

    def test_shape(self):
        apply, undo = fixes.scripts(C.evaluate(weak()), "caution")
        for text in (apply, undo):
            self.assertTrue(text.startswith("# harden-check"))
            self.assertIn("#Requires -RunAsAdministrator", text)
        steps = [l for l in apply.splitlines() if l.startswith("Step ")]
        undos = [l for l in undo.splitlines() if l.startswith("Step ")]
        self.assertEqual(len(steps), len(fixes.chosen(C.evaluate(weak()), "caution")))
        self.assertEqual(undos, list(reversed(steps)))                   # undo runs in reverse order
        self.assertIn("Restart Windows", apply)

    def test_written_files(self):
        d = Path(tempfile.mkdtemp())
        try:
            a, u, n = fixes.write(C.evaluate(weak()), d / "harden.ps1", "caution")
            self.assertEqual(u.name, "harden-undo.ps1")
            raw = a.read_bytes()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
        finally:
            shutil.rmtree(d)

    @unittest.skipUnless(sys.platform == "win32", "needs Windows PowerShell")
    def test_powershell_parses_both_scripts(self):
        d = Path(tempfile.mkdtemp())
        try:
            a, u, _ = fixes.write(C.evaluate(weak()), d / "harden.ps1", "caution")
            code = ("foreach ($f in $args) { $e = $null; [Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, "
                    "[ref]$e) | Out-Null; foreach ($x in $e) { \"$f`:$($x.Extent.StartLineNumber): $($x.Message)\" } }")
            p = subprocess.run(["powershell", "-NoProfile", "-Command", code, str(a), str(u)], capture_output=True, text=True)
            self.assertEqual(p.stdout.strip(), "")
        finally:
            shutil.rmtree(d)


class Cli(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir)

    def save(self, snap):
        p = self.dir / "snap.json"
        p.write_text(json.dumps(snap), encoding="utf-8")
        return str(p)

    def test_clean_pc(self):
        code, out, _ = cli("--snapshot", self.save(hardened()), "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("Grade A+", out)
        self.assertIn("Windows 11 Pro 24H2 (26100.2314)", out)

    def test_weak_pc(self):
        code, out, _ = cli("--snapshot", self.save(weak()), "--no-color", "--fix", str(self.dir / "h.ps1"))
        self.assertEqual(code, 1)
        self.assertIn("HIGH     WDigest plain-text passwords", out)
        self.assertIn("Grade F", out)                     # WDigest + NTLMv1 + test signing ...
        self.assertTrue((self.dir / "h.ps1").exists() and (self.dir / "h-undo.ps1").exists())

    def test_json(self):
        code, out, _ = cli("--snapshot", self.save(weak()), "--json")
        data = json.loads(out)
        out.encode("ascii")
        self.assertEqual(data["grade"], "F")
        wd = next(c for c in data["checks"] if c["id"] == "wdigest")
        self.assertEqual(wd["fix"]["risk"], "safe")

    def test_errors(self):
        self.assertEqual(cli("--snapshot", str(self.dir / "missing.json"))[0], 2)
        bad = self.dir / "bad.json"
        bad.write_text("{", encoding="utf-8")
        self.assertEqual(cli("--snapshot", str(bad))[0], 2)


@unittest.skipUnless(sys.platform == "win32", "reads a live Windows PC")
class Live(unittest.TestCase):
    def test_this_pc(self):
        from hardencheck import gather
        snap = gather.snapshot()
        self.assertGreater(snap["build"], 10000)
        self.assertIn("fw", snap["ps"])
        results = C.evaluate(snap)
        self.assertEqual([c.detail for c in results if "crashed" in c.detail], [])
        self.assertNotEqual(results[0].status, "unknown")          # the firewall is readable without admin
        json.dumps(snap)


@unittest.skipUnless(os.environ.get("HARDEN_CHECK_ROUNDTRIP") == "1",
                     "changes system settings: only on a throwaway CI machine (HARDEN_CHECK_ROUNDTRIP=1)")
class RoundTrip(unittest.TestCase):
    """Apply every safe fix on a real Windows, check each one took, undo, check everything is back."""

    def run_ps1(self, path):
        p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        print(p.stdout)
        self.assertNotIn("  fail  ", p.stdout, p.stdout + p.stderr)

    def test_apply_then_undo(self):
        from hardencheck import gather
        d = Path(tempfile.mkdtemp())
        before = gather.snapshot()
        self.assertTrue(before["elevated"])
        results = C.evaluate(before)
        todo = {c.id for c in fixes.chosen(results, "safe") if not c.fix.reboot}
        print("safe fixes on this runner:", sorted(todo))
        a, u, _ = fixes.write(results, d / "harden.ps1", "safe")
        self.run_ps1(a)
        after = {c.id: c for c in C.evaluate(gather.snapshot())}
        self.assertEqual({i: after[i].detail for i in todo if after[i].status == "fail"}, {})
        self.run_ps1(u)
        restored = gather.snapshot()
        changed = {k: (v, restored["reg"].get(k)) for k, v in before["reg"].items() if restored["reg"].get(k) != v}
        self.assertEqual(changed, {})
        for snap in (before, restored):                                     # Add/Remove-MpPreference reorder the list
            if isinstance(snap["ps"].get("mppref"), dict):
                snap["ps"]["mppref"]["asr"] = sorted(snap["ps"]["mppref"]["asr"], key=lambda r: r["id"])
        for section in ("mppref", "services", "fw", "smbs", "smbc", "wlan"):
            self.assertEqual(restored["ps"].get(section), before["ps"].get(section), section)
