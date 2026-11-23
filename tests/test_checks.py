"""Each check on a hardened snapshot with one setting broken: right verdict, right severity, right fix."""

import datetime as dt
import unittest

from hardencheck import checks as C, fixes
from tests.snap import SID, hardened

BY_ID = {}


def run(snap):
    return {c.id: c for c in C.evaluate(snap)}


class Baseline(unittest.TestCase):
    def test_hardened_pc_gets_a_plus(self):
        results = C.evaluate(hardened())
        self.assertEqual([c.id for c in results if c.status not in ("pass", "info")], [])
        self.assertEqual(C.grade(results), "A+")
        self.assertEqual(fixes.chosen(results, "caution"), [])

    def test_ids_are_unique(self):
        ids = [c.id for c in C.evaluate(hardened())]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 50)


def _set(path, value):
    def f(s):
        s["reg"][path] = value
    return f


def _ps(section, **kw):
    def f(s):
        s["ps"][section].update(kw)
    return f


# (what breaks, check id, severity, fix risk or None for "by hand")
CASES = [
    (_set(C.R["llmnr"], None), "llmnr", "medium", "safe"),
    (_set(C.R["lmcompat"], 1), "ntlm", "high", "safe"),
    (_set(C.R["lmcompat"], None), "ntlm", "low", "safe"),
    (_set(C.R["nolmhash"], 0), "lm-hash", "medium", "safe"),
    (_set(C.R["restrictsam"], 0), "anonymous", "medium", "safe"),
    (_set(C.R["restrictanon"], 0), "anonymous", "low", "safe"),
    (_set(C.R["rdp_deny"], 0), "rdp", "low", "caution"),
    (lambda s: (s["reg"].update({C.R["rdp_deny"]: 0, C.R["rdp_nla"]: 0})), "rdp", "high", "safe"),
    (_set(C.R["remote_assist"], 1), "remote-assistance", "low", "safe"),
    (_set(C.R["smb1_client"], 2), "smb1", "high", "safe"),
    (_ps("smbs", smb1=True), "smb1", "high", "safe"),
    (_ps("smbc", signing=False), "smb-signing", "medium", "caution"),
    (_ps("smbc", guest=True), "smb-guest", "medium", "caution"),
    (lambda s: s["ps"]["adapters"][0].update(netbios=0), "netbios", "low", "caution"),
    (lambda s: s["ps"]["fw"][2].update(enabled="False"), "firewall", "critical", "safe"),
    (lambda s: s["ps"]["fw"][1].update(inbound="Allow"), "firewall", "critical", "safe"),
    (lambda s: s["ps"]["services"][0].update(start="Manual"), "remote-registry", "low", "safe"),
    (lambda s: s["ps"]["services"][1].update(status="Running", start="Automatic"), "winrm", "medium", "caution"),
    (lambda s: s["ps"]["wlan"].append({"name": "Airport Free WiFi", "auth": "open", "mode": "auto"}), "wifi-open", "medium", "safe"),
    (lambda s: s["ps"]["shares"].append({"name": "Games", "path": r"D:\Games", "type": 0}), "shares", "low", None),
    (lambda s: s["reg"].update({C.R["proxy_on"]: 1, C.R["proxy_server"]: "127.0.0.1:8888"}), "proxy", "medium", None),
    (_set(C.R["proxy_pac"], "http://wpad.example/proxy.pac"), "proxy", "medium", None),
    (lambda s: s["ps"]["av"][0].update(state=393472), "antivirus", "critical", None),
    (_ps("mp", realtime=False), "defender", "critical", "safe"),
    (_ps("mp", tamper=False), "tamper", "high", None),
    (lambda s: (s["ps"]["mp"].update(realtime=False), s["reg"].update({C.R["def_policy_rt"]: 1})), "defender", "critical", None),
    (_ps("mp", sig_age=9), "signatures", "medium", "safe"),
    (_ps("mppref", maps=0), "cloud", "medium", "safe"),
    (_ps("mppref", pua=0), "pua", "medium", "safe"),
    (_ps("mppref", netprot=2), "network-protection", "low", "safe"),
    (_ps("mppref", excl_path=["C:\\"]), "exclusions", "high", "caution"),
    (_ps("mppref", excl_path=[r"C:\Users\me\AppData\Roaming\svc"]), "exclusions", "high", "caution"),
    (_ps("mppref", excl_ext=[".exe"]), "exclusions", "high", "caution"),
    (_ps("mppref", asr=[]), "asr", "medium", "safe"),
    (_set(C.R["smartscreen"], "Off"), "smartscreen", "medium", "safe"),
    (_set(C.R["smartscreen_policy"], 0), "smartscreen", "medium", "safe"),
    (_set(C.R["uac_lua"], 0), "uac", "critical", "safe"),
    (_set(C.R["uac_admin"], 0), "uac", "high", "safe"),
    (_set(C.R["uac_desktop"], 0), "uac", "low", "safe"),
    (lambda s: s["ps"]["users"][1].update(enabled=True), "accounts", "medium", "caution"),
    (_set(C.R["runasppl"], 0), "lsa-protection", "medium", "caution"),
    (_ps("dg", running=[1]), "memory-integrity", "medium", None),
    (_set(C.R["blocklist"], 0), "driver-blocklist", "medium", "safe"),
    (_set(C.R["startopts"], " TESTSIGNING  NOEXECUTE=OPTIN"), "boot-options", "high", "caution"),
    (_set(C.R["startopts"], " NOEXECUTE=ALWAYSOFF"), "boot-options", "high", "caution"),
    (_set(C.R["secureboot"], 0), "secure-boot", "medium", None),
    (lambda s: s["ps"].update(bitlocker=2), "bitlocker", "medium", None),
    (_set(C.R["wdigest"], 1), "wdigest", "high", "safe"),
    (_set(C.R["autorun_lm"], 145), "autorun", "low", "safe"),
    (_set(C.R["hide_ext"], 1), "extensions", "medium", "safe"),
    (lambda s: s["ps"]["features"].update(MicrosoftWindowsPowerShellV2Root="Enabled"), "powershell-v2", "medium", "safe"),
    (_set(C.R["sblog"], None), "ps-logging", "low", "safe"),
    (_set(C.R["cmdline"], 0), "cmdline-audit", "low", "safe"),
    (_set(C.R["noautoupdate"], 1), "updates", "high", "safe"),
    (lambda s: s["ps"].update(updates={"last_update": "2020-01-01T00:00:00", "last_hotfix": None}), "updates", "high", None),
    (lambda s: s.update(hosts="127.0.0.1 update.microsoft.com\n"), "hosts", "high", None),
    (lambda s: s.update(hosts="45.33.32.156 login.mybank.example\n"), "hosts", "medium", None),
]


class Breaks(unittest.TestCase):
    def test_each_broken_setting_is_caught(self):
        for i, (breaks, cid, severity, risk) in enumerate(CASES):
            with self.subTest(i=i, check=cid):
                s = hardened()
                breaks(s)
                results = C.evaluate(s)
                c = next(x for x in results if x.id == cid)
                self.assertEqual((c.status, c.severity), ("fail", severity), c.detail)
                self.assertEqual(c.fix.risk if c.fix else None, risk)
                if risk is None:
                    self.assertTrue(c.manual, "a failure without a command must say what to do by hand")
                others = [x.id for x in results if x.status == "fail" and x.id != cid]
                self.assertEqual(others, [], "one broken setting should fail one check")


class FirewallRulesAndListeners(unittest.TestCase):
    APP = r"C:\Users\me\AppData\Roaming\WindowsUpdate\svchost.exe"

    def snap(self, status):
        s = hardened()
        s["ps"]["fwrules"].append({"id": "{RAT'S}", "rule": f"v2.10|Action=Allow|Active=TRUE|Dir=In|App={self.APP}|Name=svchost.exe|"})
        s["ps"]["sigs"] = {self.APP: {"status": status, "signer": None}}
        return s

    def test_unsigned_program_in_appdata_with_an_allow_rule(self):
        c = run(self.snap("NotSigned"))["firewall-rules"]
        self.assertEqual((c.status, c.severity), ("fail", "high"))
        self.assertIn("svchost.exe", c.detail)
        self.assertEqual(c.fix.apply, "Disable-NetFirewallRule -Name '{RAT''S}'")
        self.assertEqual(c.fix.undo, "Enable-NetFirewallRule -Name '{RAT''S}'")

    def test_signed_and_leftover_rules(self):
        self.assertEqual(run(self.snap("Valid"))["firewall-rules"].status, "pass")
        c = run(self.snap("Missing"))["firewall-rules"]
        self.assertEqual((c.status, c.severity, c.fix.risk), ("fail", "low", "safe"))

    def test_program_folders_are_not_flagged(self):
        self.assertEqual(run(hardened())["firewall-rules"].detail, "none")

    def test_unsigned_listener_in_user_folder(self):
        s = hardened()
        s["ps"]["listen"].append({"addr": "::", "port": 7777, "pid": 66, "name": "client", "path": self.APP})
        c = run(s)["listening"]
        self.assertEqual((c.status, c.severity), ("fail", "high"))
        self.assertIn("client (port 7777)", c.detail)
        s["ps"]["sigs"] = {self.APP: {"status": "Valid", "signer": "Someone"}}
        self.assertEqual(run(s)["listening"].status, "info")

    def test_localhost_listeners_are_ignored(self):
        self.assertNotIn(5000, [p for p, _ in run(hardened())["listening"].items])


class Hosts(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(C.parse_hosts("# c\n127.0.0.1 a b  # x\n\n0.0.0.0 ads.example\n"),
                         [("127.0.0.1", "a"), ("127.0.0.1", "b"), ("0.0.0.0", "ads.example")])

    def test_blocklists_and_dev_names_are_only_info(self):
        s = hardened()
        s["hosts"] = "0.0.0.0 ads.tracker.example\n127.0.0.1 myapp.test\n192.168.1.20 nas\n"
        self.assertEqual(run(s)["hosts"].status, "info")


class Unknown(unittest.TestCase):
    def test_sections_that_need_admin_are_unknown_not_pass(self):
        s = hardened()
        s["elevated"] = False
        s["ps"]["mppref"].update(excl_path=["N/A: Must be an administrator to view exclusions"])
        s["ps"]["features"] = {"error": "needs administrator"}
        s["build"] = 19045
        s["reg"][C.R["psv2"]] = None
        r = run(s)
        self.assertEqual(r["exclusions"].status, "unknown")
        self.assertEqual(r["powershell-v2"].status, "unknown")

    def test_failed_section(self):
        s = hardened()
        s["ps"]["fw"] = {"error": "Access denied"}
        self.assertEqual(run(s)["firewall"].status, "unknown")

    def test_a_check_that_crashes_is_unknown(self):
        s = hardened()
        s["ps"]["fw"] = "garbage"
        c = run(s)["firewall"]
        self.assertEqual(c.status, "unknown")
        self.assertIn("crashed", c.detail)

    def test_other_antivirus_primary(self):
        s = hardened()
        s["ps"]["mp"]["mode"] = "Passive Mode"
        s["ps"]["av"].append({"name": "Other AV", "state": 266240})
        r = run(s)
        self.assertEqual([r[i].status for i in ("defender", "asr", "pua", "cloud")], ["info"] * 4)


class FixValues(unittest.TestCase):
    def test_undo_restores_the_value_seen(self):
        s = hardened()
        s["reg"][C.R["lmcompat"]] = 3
        f = run(s)["ntlm"].fix
        self.assertIn("-Name 'LmCompatibilityLevel' -Value 5 -Type DWord", f.apply)
        self.assertIn("-Name 'LmCompatibilityLevel' -Value 3 -Type DWord", f.undo)

    def test_undo_removes_a_value_that_was_not_there(self):
        f = run(_broken(C.R["llmnr"], None))["llmnr"].fix
        self.assertTrue(f.undo.startswith("Remove-ItemProperty"))
        self.assertIn("Test-Path", f.apply)                 # never New-Item -Force on an existing key: it wipes its values

    def test_user_settings_go_to_the_scanned_users_hive(self):
        f = run(_broken(C.R["hide_ext"], 1))["extensions"].fix
        self.assertIn(f"Registry::HKEY_USERS\\{SID}\\SOFTWARE", f.apply)

    def test_string_values(self):
        f = run(_broken(C.R["smartscreen"], "Off"))["smartscreen"].fix
        self.assertIn("-Value 'Warn' -Type String", f.apply)
        self.assertIn("-Value 'Off' -Type String", f.undo)

    def test_asr_undo_puts_back_audit_mode(self):
        s = hardened()
        s["ps"]["mppref"]["asr"] = [{"id": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "action": 2}]
        f = run(s)["asr"].fix
        self.assertIn("-AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 "
                      "-AttackSurfaceReductionRules_Actions AuditMode", f.undo)
        self.assertIn("Remove-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9", f.undo)

    def test_service_undo(self):
        s = hardened()
        s["ps"]["services"][0].update(status="Running", start="Automatic")
        f = run(s)["remote-registry"].fix
        self.assertEqual(f.undo, "Set-Service -Name 'RemoteRegistry' -StartupType Automatic; Start-Service -Name 'RemoteRegistry'")

    def test_wifi_names_are_quoted(self):
        s = hardened()
        s["ps"]["wlan"].append({"name": 'Cafe "Free"', "auth": "open", "mode": "auto"})
        self.assertIn('name="Cafe Free" connectionmode=manual', run(s)["wifi-open"].fix.apply)


def _broken(path, value):
    s = hardened()
    s["reg"][path] = value
    return s


class Grade(unittest.TestCase):
    def test_critical_is_f(self):
        self.assertEqual(C.grade(C.evaluate(_broken(C.R["uac_lua"], 0))), "F")

    def test_score(self):
        r = C.evaluate(_broken(C.R["wdigest"], 1))
        self.assertEqual((C.score(r), C.grade(r)), (88, "B"))

    def test_updates_age(self):
        s = hardened()
        s["ps"]["updates"] = {"last_update": "2026-01-01T10:00:00", "last_hotfix": None}
        c = C.updates(s, now=dt.datetime(2026, 2, 15))
        self.assertEqual((c.status, c.severity), ("fail", "medium"))


if __name__ == "__main__":
    unittest.main()
