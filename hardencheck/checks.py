"""Every check: what it reads from the snapshot, why it matters, and the reversible fix.

A check never changes anything. Its Fix carries two PowerShell snippets: `apply`, and `undo`, which puts back
the exact value the scan saw. "safe" fixes don't change how a normal home or office PC works; "caution"
fixes can break something specific (named in the note) and are only written with --level caution.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low")
PENALTY = {"critical": 25, "high": 12, "medium": 6, "low": 2}
DENIED = "<denied>"


@dataclass
class Fix:
    risk: str                    # "safe" | "caution"
    apply: str                   # PowerShell, run elevated
    undo: str                    # PowerShell that restores what the scan saw
    note: str = ""               # caution: what it can break
    reboot: bool = False


@dataclass
class Check:
    id: str
    area: str                    # "network" | "device"
    title: str
    status: str = "pass"         # pass | fail | info | unknown
    severity: str = "low"
    detail: str = ""
    why: str = ""
    fix: Fix | None = None
    manual: str = ""             # what to do when no command can do it safely
    items: list = field(default_factory=list)


# ---------------------------------------------------------------------------------------------- registry
LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
R = {
    "llmnr": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast",
    "lmcompat": LSA + r"\LmCompatibilityLevel",
    "nolmhash": LSA + r"\NoLMHash",
    "restrictanon": LSA + r"\RestrictAnonymous",
    "restrictsam": LSA + r"\RestrictAnonymousSAM",
    "everyoneanon": LSA + r"\EveryoneIncludesAnonymous",
    "runasppl": LSA + r"\RunAsPPL",
    "wdigest": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
    "rdp_deny": r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections",
    "rdp_nla": r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication",
    "remote_assist": r"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance\fAllowToGetHelp",
    "smb1_client": r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start",
    "uac_lua": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
    "uac_admin": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin",
    "uac_desktop": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop",
    "cmdline": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled",
    "smartscreen": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled",
    "smartscreen_policy": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen",
    "blocklist": r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable",
    "secureboot": r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled",
    "startopts": r"HKLM\SYSTEM\CurrentControlSet\Control\SystemStartOptions",
    "autorun_lm": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun",
    "autorun_cu": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun",
    "hide_ext": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt",
    "psv2": r"HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine\PowerShellVersion",
    "sblog": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging",
    "wsh": r"HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled",
    "noautoupdate": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate",
    "proxy_on": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable",
    "proxy_server": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer",
    "proxy_pac": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL",
    "def_policy_rt": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring",
    "def_policy_off": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
    "edition": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EditionID",
    "product": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName",
    "display": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DisplayVersion",
    "build": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber",
    "ubr": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR",
}
NETBT = r"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{}\NetbiosOptions"
REG_PATHS = list(R.values())


def q(s) -> str:
    """A PowerShell single-quoted literal."""
    return "'" + str(s).replace("'", "''") + "'"


def ps_key(key: str, sid: str | None) -> str:
    root, _, rest = key.partition("\\")
    if root == "HKCU":                     # the elevated script may run as another account: write the scanned user's hive
        return f"Registry::HKEY_USERS\\{sid}\\{rest}" if sid else f"HKCU:\\{rest}"
    return f"{root}:\\{rest}"


def _set(key: str, name: str, value) -> str:
    kind = "DWord" if isinstance(value, int) else "String"
    val = value if isinstance(value, int) else q(value)
    return (f"$k = {q(key)}; if (-not (Test-Path -LiteralPath $k)) {{ New-Item -Path $k -Force | Out-Null }}; "
            f"Set-ItemProperty -LiteralPath $k -Name {q(name)} -Value {val} -Type {kind}")


def reg_fix(snap, path: str, value, risk="safe", note="", reboot=False, current=...) -> Fix:
    key, _, name = path.rpartition("\\")
    k = ps_key(key, snap.get("user_sid"))
    current = snap["reg"].get(path) if current is ... else current
    if current is None:
        undo = f"Remove-ItemProperty -LiteralPath {q(k)} -Name {q(name)} -ErrorAction SilentlyContinue"
    elif current == DENIED:
        undo = f"# {name}: the scan could not read the old value; set it back by hand if needed"
    else:
        undo = _set(k, name, current)
    return Fix(risk, _set(k, name, value), undo, note, reboot)


def mp_fix(param: str, value: int, current, risk="safe", note="") -> Fix:
    undo = f"Set-MpPreference -{param} {current}" if isinstance(current, int) else f"# {param} was not readable"
    # Set-MpPreference reports success even when a policy overrides it: check it took
    apply = (f"Set-MpPreference -{param} {value}; if ([int](Get-MpPreference).{param} -ne {value}) "
             f"{{ throw 'not applied: a policy or another antivirus controls this setting' }}")
    return Fix(risk, apply, undo, note)


def service_fix(svc: dict, risk="safe", note="") -> Fix:
    name = q(svc["name"])
    undo = f"Set-Service -Name {name} -StartupType {svc['start'] if svc['start'] in ('Automatic', 'Manual', 'Disabled') else 'Manual'}"
    if svc["status"] == "Running":
        undo += f"; Start-Service -Name {name}"
    return Fix(risk, f"Stop-Service -Name {name} -Force -ErrorAction SilentlyContinue; "
                     f"Set-Service -Name {name} -StartupType Disabled", undo, note)


def reg(snap, key):
    return snap["reg"].get(R[key])


def ps(snap, section):
    """The PowerShell section, or None when it failed (no access, cmdlet missing)."""
    v = snap["ps"].get(section)
    return None if isinstance(v, dict) and "error" in v else v


def user_writable(path: str | None) -> bool:
    p = (path or "").lower().replace("/", "\\")
    return any(s in p for s in ("\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\"))


# ----------------------------------------------------------------------------------------------- network
def firewall(snap):
    c = Check("firewall", "network", "Windows Firewall", severity="critical",
              why="the firewall is what stops other machines on the network from reaching services on this PC")
    profiles = ps(snap, "fw")
    if profiles is None:
        c.status = "unknown"
        return c
    off = [p["name"] for p in profiles if p["enabled"] == "False"]
    allow = [p["name"] for p in profiles if p["inbound"] == "Allow"]
    if off or allow:
        c.status = "fail"
        c.detail = "; ".join(filter(None, [off and f"off for: {', '.join(off)}",
                                           allow and f"allows all inbound connections on: {', '.join(allow)}"]))
        names = ", ".join(q(n) for n in sorted(set(off + allow)))
        prev = {p["name"]: p for p in profiles}
        undo = "; ".join(f"Set-NetFirewallProfile -Profile {q(n)} -Enabled {prev[n]['enabled']} "
                         f"-DefaultInboundAction {prev[n]['inbound']}" for n in sorted(set(off + allow)))
        c.fix = Fix("safe", f"Set-NetFirewallProfile -Profile {names} -Enabled True -DefaultInboundAction Block", undo)
    else:
        c.detail = "on for all profiles, inbound blocked unless a rule allows it"
    return c


def _rule_fields(raw: str) -> dict:
    out = {}
    for part in raw.split("|"):
        k, sep, v = part.partition("=")
        if sep:
            out.setdefault(k, v)
    return out


def firewall_rules(snap):
    c = Check("firewall-rules", "network", "Inbound firewall rules for programs in user folders", severity="high",
              why="njRAT and other RATs add a firewall rule for themselves so the attacker can connect in; real "
                  "apps live in Program Files and are signed")
    rules, sigs = ps(snap, "fwrules"), ps(snap, "sigs") or {}
    if rules is None:
        c.status = "unknown"
        return c
    import os
    bad, signed, gone = [], [], []
    for r in rules:
        f = _rule_fields(r["rule"])
        app = os.path.expandvars(f.get("App", ""))
        if not user_writable(app):
            continue
        sig = next((v for k, v in sigs.items() if k.lower() == app.lower()), None)
        entry = {"id": r["id"], "app": app, "signer": sig and sig.get("signer"), "status": sig and sig.get("status")}
        (gone if sig and sig["status"] == "Missing" else signed if sig and sig["status"] == "Valid" else bad).append(entry)
    c.items = bad + signed + gone
    if bad:
        c.status = "fail"
        c.detail = f"{len(bad)} rule(s) let unsigned programs in user folders accept connections: " + \
                   ", ".join(sorted({os.path.basename(e['app']) for e in bad}))
        c.fix = Fix("caution", "; ".join(f"Disable-NetFirewallRule -Name {q(e['id'])}" for e in bad),
                    "; ".join(f"Enable-NetFirewallRule -Name {q(e['id'])}" for e in bad),
                    "disables (not deletes) the rules; a game or tool you trust may then fail to host or connect in")
    elif gone:
        c.status, c.severity = "fail", "low"
        c.detail = f"{len(gone)} rule(s) point at programs that no longer exist (leftovers)"
        c.fix = Fix("safe", "; ".join(f"Disable-NetFirewallRule -Name {q(e['id'])}" for e in gone),
                    "; ".join(f"Enable-NetFirewallRule -Name {q(e['id'])}" for e in gone))
    else:
        c.detail = f"{len(signed)} rule(s) for signed programs in user folders" if signed else "none"
    return c


def listening(snap):
    c = Check("listening", "network", "Programs accepting connections from the network", severity="high",
              why="a program listening on all network interfaces can be reached by any machine that gets past the "
                  "firewall; an unsigned one in a user folder is how backdoors wait for their operator")
    rows, sigs = ps(snap, "listen"), ps(snap, "sigs") or {}
    if rows is None:
        c.status = "unknown"
        return c
    public = [r for r in rows if r["addr"] in ("0.0.0.0", "::")]
    bad = [r for r in public if user_writable(r.get("path")) and (sigs.get(r["path"]) or {}).get("status") != "Valid"]
    c.items = sorted({(r["port"], r.get("name") or f"pid {r['pid']}") for r in public})
    if bad:
        c.status = "fail"
        c.detail = "unsigned program(s) in user folders listening on every interface: " + \
                   ", ".join(sorted({f"{r['name']} (port {r['port']})" for r in bad}))
        c.manual = "look each one up; if you don't know it, scan it (kira-scan, unmask) and remove it"
    else:
        c.status = "info"
        c.detail = f"{len(c.items)} port(s) open on all interfaces: " + \
                   ", ".join(f"{p} {n}" for p, n in c.items[:12]) + (" …" if len(c.items) > 12 else "")
    return c


def smb1(snap):
    c = Check("smb1", "network", "SMBv1 (the protocol WannaCry spread through)", severity="high",
              why="SMBv1 has no modern protection and is what EternalBlue/WannaCry used; nothing current needs it")
    server, feat = ps(snap, "smbs"), ps(snap, "features") or {}
    client = snap["reg"].get(R["smb1_client"])
    on = []
    if server and server.get("smb1"):
        on.append("server")
    if isinstance(client, int) and client != 4:
        on.append("client")
    if feat.get("SMB1Protocol") == "Enabled" and not on:
        on.append("feature installed")
    if server is None and client == DENIED:
        c.status = "unknown"
    elif on:
        c.status, c.detail = "fail", "on: " + ", ".join(on)
        c.fix = Fix("safe", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; "
                            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null",
                    "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart | Out-Null; "
                    "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force", reboot=True,
                    note="a NAS or printer from before ~2012 that only speaks SMBv1 stops working; replace it")
    else:
        c.detail = "off"
    return c


def smb_signing(snap):
    c = Check("smb-signing", "network", "SMB signing", severity="medium",
              why="without signing, someone on the same network can relay or tamper with file-sharing traffic")
    s, cl = ps(snap, "smbs"), ps(snap, "smbc")
    if s is None or cl is None:
        c.status = "unknown"
        return c
    off = [n for n, v in (("server", s.get("signing")), ("client", cl.get("signing"))) if v is False]
    if off:
        c.status, c.detail = "fail", "not required on: " + ", ".join(off)
        apply = [f"Set-Smb{n.title()}Configuration -RequireSecuritySignature $true -Force" for n in off]
        undo = [f"Set-Smb{n.title()}Configuration -RequireSecuritySignature $false -Force" for n in off]
        c.fix = Fix("caution", "; ".join(apply), "; ".join(undo),
                    "an old NAS or printer without signing support stops working (Windows 11 24H2 requires it by default)")
    else:
        c.detail = "required"
    return c


def smb_guest(snap):
    c = Check("smb-guest", "network", "Guest access to network shares", severity="medium",
              why="guest logons skip authentication, so a fake share on the network can feed this PC files")
    cl = ps(snap, "smbc")
    if cl is None:
        c.status = "unknown"
    elif cl.get("guest"):
        c.status, c.detail = "fail", "insecure guest logons allowed"
        c.fix = Fix("caution", "Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force",
                    "Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force",
                    "a NAS share you open without a password stops opening; give it a user and password instead")
    else:
        c.detail = "blocked"
    return c


def llmnr(snap):
    c = Check("llmnr", "network", "LLMNR name lookups", severity="medium",
              why="when DNS can't find a name, Windows asks the whole local network; any machine can answer and "
                  "collect your password hash (Responder)")
    v = reg(snap, "llmnr")
    if v == 0:
        c.detail = "off by policy"
    else:
        c.status, c.detail = "fail", "on (the Windows default)"
        c.fix = reg_fix(snap, R["llmnr"], 0)
    return c


def netbios(snap):
    c = Check("netbios", "network", "NetBIOS over TCP/IP", severity="low",
              why="the older cousin of LLMNR: broadcast name lookups that tools like Responder answer")
    adapters = ps(snap, "adapters")
    if adapters is None:
        c.status = "unknown"
        return c
    on = [a for a in adapters if a.get("netbios") != 2 and a.get("id")]
    if on:
        c.status, c.detail = "fail", "on for: " + ", ".join(a["name"] for a in on)
        fixes = [reg_fix(snap, NETBT.format(a["id"]), 2, current=a["netbios"] if a["netbios"] in (0, 1) else None)
                 for a in on]
        c.fix = Fix("caution", "; ".join(f.apply for f in fixes), "; ".join(f.undo for f in fixes),
                    "very old devices found by NetBIOS name only (some NAS, old printers) need their IP instead")
    else:
        c.detail = "off on every adapter"
    return c


def ntlm(snap):
    c = Check("ntlm", "network", "NTLM version", severity="high",
              why="LM and NTLMv1 hashes crack in minutes; Windows should only send and accept NTLMv2")
    v = reg(snap, "lmcompat")
    level = v if isinstance(v, int) else 3      # unset: Windows sends NTLMv2 only (level 3)
    if level < 3:
        c.status, c.detail = "fail", f"level {level}: this PC still sends LM/NTLMv1"
    elif level < 5:
        c.status, c.severity, c.detail = "fail", "low", f"level {level}: sends NTLMv2 only, still accepts NTLMv1"
    else:
        c.detail = "level 5: NTLMv2 only, both ways"
    if c.status == "fail":
        c.fix = reg_fix(snap, R["lmcompat"], 5)
    return c


def lm_hash(snap):
    c = Check("lm-hash", "network", "LM password hashes", severity="medium",
              why="the LM hash of a password is trivial to crack; Windows should never store it")
    v = reg(snap, "nolmhash")
    if v == 1:
        c.detail = "not stored"
    else:
        c.status, c.detail = "fail", "may be stored on the next password change"
        c.fix = reg_fix(snap, R["nolmhash"], 1)
    return c


def anonymous(snap):
    c = Check("anonymous", "network", "Anonymous access to accounts and shares", severity="medium",
              why="anonymous sessions let anyone on the network list user names and shares to attack")
    sam, anon, every = reg(snap, "restrictsam"), reg(snap, "restrictanon"), reg(snap, "everyoneanon")
    bad = []
    if sam == 0:
        bad.append(("restrictsam", 1, "account list open"))
    if every == 1:
        bad.append(("everyoneanon", 0, "anonymous users get Everyone's rights"))
    if not isinstance(anon, int) or anon == 0:
        bad.append(("restrictanon", 1, "share list open to anonymous sessions"))
    if bad:
        c.status, c.detail = "fail", "; ".join(b[2] for b in bad)
        if all(b[0] == "restrictanon" for b in bad):
            c.severity = "low"
        fixes = [reg_fix(snap, R[k], v) for k, v, _ in bad]
        c.fix = Fix("safe", "; ".join(f.apply for f in fixes), "; ".join(f.undo for f in fixes))
    else:
        c.detail = "restricted"
    return c


def rdp(snap):
    c = Check("rdp", "network", "Remote Desktop", severity="high",
              why="RDP is the most brute-forced door on Windows; without Network Level Authentication anyone can "
                  "reach the login screen and its bugs (BlueKeep)")
    deny, nla = reg(snap, "rdp_deny"), reg(snap, "rdp_nla")
    if deny != 0:
        c.detail = "off"
        return c
    if nla == 0:
        c.status, c.detail = "fail", "on, without Network Level Authentication"
        c.fix = reg_fix(snap, R["rdp_nla"], 1)
    else:
        c.status, c.severity, c.detail = "fail", "low", "on (with Network Level Authentication)"
        c.fix = reg_fix(snap, R["rdp_deny"], 1, risk="caution", note="you can no longer connect to this PC with Remote Desktop")
    return c


def remote_assistance(snap):
    c = Check("remote-assistance", "network", "Remote Assistance invitations", severity="low",
              why="lets someone you invite take over the screen; scammers talk people into it")
    if reg(snap, "remote_assist") == 1:
        c.status, c.detail = "fail", "allowed"
        c.fix = reg_fix(snap, R["remote_assist"], 0)
    else:
        c.detail = "off"
    return c


def _service(snap, name):
    svcs = ps(snap, "services")
    return None if svcs is None else next((s for s in svcs if s["name"].lower() == name.lower()), {})


def remote_registry(snap):
    c = Check("remote-registry", "network", "Remote Registry service", severity="low",
              why="lets other machines read and change this PC's registry over the network")
    s = _service(snap, "RemoteRegistry")
    if s is None:
        c.status = "unknown"
    elif s and s["start"] != "Disabled":
        c.status, c.detail = "fail", f"{s['start'].lower()}, {s['status'].lower()}"
        c.fix = service_fix(s)
    else:
        c.detail = "disabled"
    return c


def winrm(snap):
    c = Check("winrm", "network", "PowerShell remoting (WinRM)", severity="medium",
              why="a running WinRM service accepts remote PowerShell sessions, a favourite for moving between machines")
    s = _service(snap, "WinRM")
    if s is None:
        c.status = "unknown"
    elif s and s["status"] == "Running":
        c.status, c.detail = "fail", "running"
        c.fix = service_fix(s, "caution", "remote management tools (Intune, scripts, Ansible) can no longer reach this PC")
    else:
        c.detail = "not running"
    return c


def wifi(snap):
    c = Check("wifi-open", "network", "Saved open Wi-Fi networks that auto-connect", severity="medium",
              why="anyone can create a hotspot with the same name; the PC joins it by itself and the attacker sees "
                  "the traffic (evil twin)")
    profiles = ps(snap, "wlan")
    if profiles is None:
        c.status = "unknown"
        return c
    bad = [p for p in profiles if p["auth"].lower() == "open" and p["mode"].lower() == "auto"]
    c.items = [p["name"] for p in bad]
    if bad:
        c.status, c.detail = "fail", ", ".join(c.items)
        c.fix = Fix("safe", "; ".join(f"netsh wlan set profileparameter name={_cmd_arg(p['name'])} connectionmode=manual | Out-Null"
                                      for p in bad),
                    "; ".join(f"netsh wlan set profileparameter name={_cmd_arg(p['name'])} connectionmode=auto | Out-Null"
                              for p in bad))
    else:
        c.detail = f"{len(profiles)} saved network(s), none open with auto-connect" if profiles else "no saved Wi-Fi"
    return c


def _cmd_arg(s: str) -> str:
    return '"' + s.replace('"', '') + '"'


SECURITY_SITES = re.compile(
    r"(?:^|\.)(?:microsoft\.com|windowsupdate\.com|windows\.com|live\.com|msftncsi\.com|msftconnecttest\.com|"
    r"virustotal\.com|malwarebytes\.com|kaspersky\.com|eset\.com|avast\.com|avg\.com|bitdefender\.com|norton\.com|"
    r"mcafee\.com|sophos\.com|trendmicro\.com|hybrid-analysis\.com|google\.com|github\.com|discord\.com|"
    r"steampowered\.com|steamcommunity\.com|paypal\.com|apple\.com)$", re.I)


def parse_hosts(text: str) -> list[tuple[str, str]]:
    out = []
    for line in (text or "").splitlines():
        parts = line.split("#", 1)[0].split()
        out += [(parts[0], name.lower()) for name in parts[1:]] if len(parts) > 1 else []
    return out


def hosts(snap):
    c = Check("hosts", "network", "hosts file", severity="high",
              why="malware edits the hosts file to block antivirus updates or send you to a fake login page")
    text = snap.get("hosts")
    if text is None:
        c.status = "unknown"
        return c
    entries = [(ip, n) for ip, n in parse_hosts(text) if n not in ("localhost", "localhost.localdomain")]
    security = [(ip, n) for ip, n in entries if SECURITY_SITES.search(n)]
    redirected = []
    for ip, n in entries:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_global and (ip, n) not in security:
            redirected.append((ip, n))
    c.items = security + redirected
    if security:
        c.status = "fail"
        c.detail = "security, update or login sites overridden: " + ", ".join(f"{n} -> {ip}" for ip, n in security[:6])
    elif redirected:
        c.status, c.severity = "fail", "medium"
        c.detail = "names sent to internet addresses: " + ", ".join(f"{n} -> {ip}" for ip, n in redirected[:6])
    else:
        c.status = "info" if entries else "pass"
        c.detail = f"{len(entries)} local/blocking entr(ies)" if entries else "no entries"
    if c.status == "fail":
        c.manual = r"open notepad as administrator, edit C:\Windows\System32\drivers\etc\hosts and delete lines you didn't add"
    return c


def proxy(snap):
    c = Check("proxy", "network", "Web proxy", severity="medium",
              why="a proxy sees all web traffic; stealers and adware set one so they can read and change it")
    on, server, pac = reg(snap, "proxy_on"), reg(snap, "proxy_server"), reg(snap, "proxy_pac")
    if on == 1 or pac:
        c.status = "fail"
        c.detail = "; ".join(filter(None, [on == 1 and f"proxy {server}", pac and f"auto-config script {pac}"]))
        c.manual = "if you (or your company) didn't set it: Settings > Network & internet > Proxy, turn it off"
    else:
        c.detail = "none"
    return c


def dns(snap):
    c = Check("dns", "network", "DNS servers", status="info",
              why="whoever answers DNS decides which server every name goes to; DNS changers point it at their own")
    adapters = ps(snap, "adapters")
    if adapters is None:
        c.status = "unknown"
        return c
    servers = sorted({d for a in adapters for d in a.get("dns") or []})
    c.items = servers
    c.detail = ", ".join(servers) + "  (check you or your router set these)" if servers else "none set"
    return c


def network_profile(snap):
    c = Check("network-profile", "network", "Network type", status="info",
              why="Private lets other devices find this PC; use Public on any network you don't control")
    conn = ps(snap, "conn")
    if conn is None:
        c.status = "unknown"
    else:
        c.detail = ", ".join(f"{x['alias']}: {x['category']}" for x in conn) or "not connected"
    return c


def shares(snap):
    c = Check("shares", "network", "Shared folders", severity="low",
              why="every shared folder is reachable by other machines on the network")
    rows = ps(snap, "shares")
    if rows is None:
        c.status = "unknown"
        return c
    mine = [s for s in rows if not s["name"].endswith("$")]
    c.items = [f"{s['name']} ({s['path']})" for s in mine]
    if mine:
        c.status, c.detail = "fail", ", ".join(c.items)
        c.manual = "stop sharing folders you no longer need: right-click > Properties > Sharing"
    else:
        c.detail = "only Windows' own admin shares"
    return c


# ------------------------------------------------------------------------------------------------ device
def _defender_primary(snap) -> bool | None:
    mp = ps(snap, "mp")
    if not mp or mp.get("mode") is None:
        return None
    return mp["mode"].lower() == "normal"          # "Passive Mode", "EDR Block Mode": another antivirus is primary


def antivirus(snap):
    c = Check("antivirus", "device", "Antivirus", severity="critical",
              why="without an active antivirus nothing blocks known malware when it lands")
    products = ps(snap, "av")
    if products is None:
        c.status = "unknown"
        return c
    active = [p["name"] for p in products if (p["state"] >> 8) & 0x10]   # productState middle byte: 0x10 = scanning on
    c.items = [p["name"] for p in products]
    if active:
        c.detail = "active: " + ", ".join(active)
    elif products:
        c.status, c.detail = "fail", "installed but not active: " + ", ".join(c.items)
        c.manual = "open Windows Security > Virus & threat protection and turn protection on"
    else:
        c.status, c.detail = "fail", "none registered"
    return c


def defender(snap):
    c = Check("defender", "device", "Microsoft Defender real-time protection", severity="critical",
              why="real-time protection is what scans files as they arrive; malware's first step is turning it off")
    mp = ps(snap, "mp")
    primary = _defender_primary(snap)
    if not mp or primary is None:
        c.status = "unknown"
    elif not primary:
        c.status, c.detail = "info", f"another antivirus is primary (Defender mode: {mp['mode']})"
    elif mp.get("realtime") is False:
        c.status, c.detail = "fail", "off"
        if 1 in (reg(snap, "def_policy_rt"), reg(snap, "def_policy_off")):
            c.detail += " by Group Policy"
            c.manual = (r"a policy turns it off (HKLM\SOFTWARE\Policies\Microsoft\Windows Defender); if you or your "
                        "company didn't set it, malware did: remove the policy, then scan with Defender offline")
        else:
            c.fix = Fix("safe", "Set-MpPreference -DisableRealtimeMonitoring $false; Start-Sleep -Seconds 3; "
                                "if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) "
                                "{ throw 'still off: a policy or another antivirus controls it' }",
                        "Set-MpPreference -DisableRealtimeMonitoring $true")
    else:
        c.detail = "on"
    return c


def tamper(snap):
    c = Check("tamper", "device", "Defender Tamper Protection", severity="high",
              why="stops malware (and scripts) from switching Defender off or adding exclusions")
    mp = ps(snap, "mp")
    if not mp or mp.get("tamper") is None or _defender_primary(snap) is None:
        c.status = "unknown"
    elif _defender_primary(snap) is False:
        c.status = "info"
    elif mp["tamper"]:
        c.detail = "on"
    else:
        c.status, c.detail = "fail", "off"
        c.manual = "Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On " \
                   "(windowsdefender://threatsettings); no command can turn it on, by design"
    return c


def _pref(snap):
    return ps(snap, "mppref") if _defender_primary(snap) else None


def cloud(snap):
    c = Check("cloud", "device", "Defender cloud protection", severity="medium",
              why="cloud protection blocks brand-new malware in seconds instead of waiting for the next signature update")
    p = _pref(snap)
    if p is None:
        c.status = "info" if _defender_primary(snap) is False else "unknown"
    elif p.get("maps") == 0:
        c.status, c.detail = "fail", "off"
        c.fix = mp_fix("MAPSReporting", 2, p["maps"])
    else:
        c.detail = "on"
    return c


def pua(snap):
    c = Check("pua", "device", "Blocking of potentially unwanted apps", severity="medium",
              why="blocks bundled adware, crypto miners and the 'free FPS booster' class of download")
    p = _pref(snap)
    if p is None:
        c.status = "info" if _defender_primary(snap) is False else "unknown"
    elif p.get("pua") != 1:
        c.status, c.detail = "fail", {0: "off", 2: "audit only"}.get(p.get("pua"), "off")
        c.fix = mp_fix("PUAProtection", 1, p.get("pua"))
    else:
        c.detail = "on"
    return c


def network_protection(snap):
    c = Check("network-protection", "device", "Defender network protection", severity="low",
              why="blocks connections to known malicious and phishing hosts from every app, not only the browser")
    p = _pref(snap)
    if p is None:
        c.status = "info" if _defender_primary(snap) is False else "unknown"
    elif p.get("netprot") != 1:
        c.status, c.detail = "fail", {2: "audit only"}.get(p.get("netprot"), "off")
        c.fix = mp_fix("EnableNetworkProtection", 1, p.get("netprot"))
    else:
        c.detail = "on"
    return c


def signatures(snap):
    c = Check("signatures", "device", "Defender signature age", severity="medium",
              why="old signatures miss this week's malware")
    mp = ps(snap, "mp")
    if not mp or mp.get("sig_age") is None or not _defender_primary(snap):
        c.status = "info" if _defender_primary(snap) is False else "unknown"
    elif mp["sig_age"] > 3:
        c.status, c.detail = "fail", f"{mp['sig_age']} days old"
        c.fix = Fix("safe", "Update-MpSignature", "# signature updates are not undone")
    else:
        c.detail = f"{mp['sig_age']} day(s) old"
    return c


def _excl_readable(values) -> bool:
    return not any(str(v).startswith("N/A") for v in values)


def exclusions(snap):
    c = Check("exclusions", "device", "Defender exclusions", severity="high",
              why="malware adds its own folder or a whole drive as an exclusion so Defender never scans it")
    p = _pref(snap)
    if p is None:
        c.status = "info" if _defender_primary(snap) is False else "unknown"
        return c
    paths, procs, exts = p.get("excl_path") or [], p.get("excl_process") or [], p.get("excl_ext") or []
    if not _excl_readable(paths + procs + exts):
        c.status, c.detail = "unknown", "only administrators can read exclusions"
        return c
    def risky_path(x):
        x = x.rstrip("\\").lower()
        return bool(re.fullmatch(r"[a-z]:", x)) or user_writable(x + "\\")
    bad = [("ExclusionPath", x) for x in paths if risky_path(x)] + \
          [("ExclusionProcess", x) for x in procs if user_writable(x)] + \
          [("ExclusionExtension", x) for x in exts if x.lower().lstrip(".*") in ("exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "scr")]
    c.items = paths + procs + exts
    if bad:
        c.status, c.detail = "fail", "risky: " + ", ".join(v for _, v in bad)
        c.fix = Fix("caution", "; ".join(f"Remove-MpPreference -{k} {q(v)}" for k, v in bad),
                    "; ".join(f"Add-MpPreference -{k} {q(v)}" for k, v in bad),
                    "if you added one on purpose (a dev or malware-analysis folder), Defender scans it again")
    else:
        c.status = "info" if c.items else "pass"
        c.detail = ", ".join(c.items) if c.items else "none"
    return c


# Microsoft's ASR rule reference (learn.microsoft.com, attack-surface-reduction-rules-reference)
ASR_SAFE = {
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "Block abuse of exploited vulnerable signed drivers",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from LSASS",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block persistence through WMI event subscription",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email and webmail",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block Office apps from creating child processes",
    "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office apps from creating executable content",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office apps from injecting into other processes",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office communication apps from creating child processes",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "Block JavaScript/VBScript launching downloaded executables",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Block Adobe Reader from creating child processes",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted, unsigned processes that run from USB",
}
ASR_CAUTION = {
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": ("Block execution of potentially obfuscated scripts", "can block minified install scripts"),
    "c1db55ab-c21a-4637-bb3f-a12568109d35": ("Use advanced protection against ransomware", "can block new, unknown programs"),
    "01443614-cd74-433a-b99e-2ecdc07bfc25": ("Block executables unless prevalent, old or trusted", "blocks programs you build or download fresh"),
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": ("Block process creation from PsExec and WMI", "breaks remote management (SCCM, scripts)"),
    "33ddedf1-c6e0-47cb-833e-de6133960387": ("Block rebooting into Safe Mode", "blocks bcdedit/msconfig Safe Mode for you too"),
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": ("Block copied or impersonated system tools", "newer rule; can block renamed tools"),
}
ASR_STATE = {0: "off", 1: "block", 2: "audit", 6: "warn"}
ASR_ACTION = {0: "Disabled", 1: "Enabled", 2: "AuditMode", 6: "Warn"}


def _asr_fix(rules, current: dict, risk, note="") -> Fix:
    apply = "; ".join(f"Add-MpPreference -AttackSurfaceReductionRules_Ids {g} -AttackSurfaceReductionRules_Actions Enabled"
                      for g in rules)
    undo = "; ".join(f"Remove-MpPreference -AttackSurfaceReductionRules_Ids {g}" if g not in current else
                     f"Add-MpPreference -AttackSurfaceReductionRules_Ids {g} -AttackSurfaceReductionRules_Actions "
                     f"{ASR_ACTION.get(current[g], 'Disabled')}"
                     for g in rules)
    return Fix(risk, apply, undo, note)


def asr(snap):
    c = Check("asr", "device", "Attack surface reduction rules", severity="medium",
              why="these Defender rules stop the moves real attacks make: Office spawning PowerShell, scripts "
                  "launching downloads, dumping LSASS, loading vulnerable drivers, WMI persistence")
    p = _pref(snap)
    if p is None:
        c.status = "info" if _defender_primary(snap) is False else "unknown"
        return c
    current = {r["id"]: r["action"] for r in p.get("asr") or []}
    missing = [g for g in ASR_SAFE if current.get(g) != 1]
    c.items = [f"{ASR_SAFE[g]}: {ASR_STATE.get(current.get(g), 'not set')}" for g in missing]
    if missing:
        c.status = "fail"
        c.detail = f"{len(ASR_SAFE) - len(missing)} of {len(ASR_SAFE)} recommended rules block"
        if len(missing) <= 3 and not {"56a863a9-875e-4185-98a7-b882c64b5ce5", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"} & set(missing):
            c.severity = "low"
        c.fix = _asr_fix(missing, current, "safe")
    else:
        c.detail = f"all {len(ASR_SAFE)} recommended rules block"
    return c


def asr_strict(snap):
    c = Check("asr-strict", "device", "Stricter attack surface reduction rules", status="info",
              why="extra rules that stop more, at the price of sometimes blocking legitimate programs")
    p = _pref(snap)
    if p is None:
        c.status = "info" if _defender_primary(snap) is False else "unknown"
        return c
    current = {r["id"]: r["action"] for r in p.get("asr") or []}
    missing = [g for g in ASR_CAUTION if current.get(g) not in (1, 6)]
    c.items = [f"{ASR_CAUTION[g][0]} ({ASR_CAUTION[g][1]})" for g in missing]
    c.detail = f"{len(ASR_CAUTION) - len(missing)} of {len(ASR_CAUTION)} on"
    if missing:
        c.fix = _asr_fix(missing, current, "caution", "; ".join(f"{ASR_CAUTION[g][0].lower()}: {ASR_CAUTION[g][1]}"
                                                                  for g in missing))
    return c


def controlled_folders(snap):
    c = Check("controlled-folders", "device", "Controlled folder access (ransomware protection)", status="info",
              why="only trusted apps may change Documents, Pictures, Desktop: ransomware can't encrypt them")
    p = _pref(snap)
    if p is None:
        c.status = "info" if _defender_primary(snap) is False else "unknown"
    elif p.get("cfa") == 1:
        c.status, c.detail = "pass", "on"
    else:
        c.detail = "off"
        c.fix = mp_fix("EnableControlledFolderAccess", 1, p.get("cfa"), "caution",
                       "unknown programs can no longer save into Documents/Desktop until you allow them")
    return c


def smartscreen(snap):
    c = Check("smartscreen", "device", "SmartScreen for apps and files", severity="medium",
              why="SmartScreen warns before running a downloaded program nobody else runs, which is what fake "
                  "cheats and cracks are")
    v, policy = reg(snap, "smartscreen"), reg(snap, "smartscreen_policy")
    if policy == 0 or str(v).lower() == "off":
        c.status, c.detail = "fail", "off" + (" by policy" if policy == 0 else "")
        fixes = [reg_fix(snap, R["smartscreen"], "Warn")] + ([reg_fix(snap, R["smartscreen_policy"], 1)] if policy == 0 else [])
        c.fix = Fix("safe", "; ".join(f.apply for f in fixes), "; ".join(f.undo for f in fixes))
    else:
        c.detail = "on"
    return c


def uac(snap):
    c = Check("uac", "device", "User Account Control", severity="critical",
              why="UAC is the prompt between a program and administrator rights; malware loves a PC where it never asks")
    lua, admin, desktop = reg(snap, "uac_lua"), reg(snap, "uac_admin"), reg(snap, "uac_desktop")
    if lua == 0:
        c.status, c.detail = "fail", "off: every program runs with full rights"
        c.fix = reg_fix(snap, R["uac_lua"], 1, reboot=True)
    elif admin == 0:
        c.status, c.severity, c.detail = "fail", "high", "elevates without asking"
        c.fix = reg_fix(snap, R["uac_admin"], 5)
    elif desktop == 0:
        c.status, c.severity, c.detail = "fail", "low", "prompt not on the secure desktop (other programs can click it)"
        c.fix = reg_fix(snap, R["uac_desktop"], 1)
    else:
        c.detail = "on, asks on the secure desktop"
    return c


def accounts(snap):
    c = Check("accounts", "device", "Built-in Administrator and Guest accounts", severity="medium",
              why="the built-in Administrator is never locked out and is the first name brute-force tools try")
    users = ps(snap, "users")
    if users is None:
        c.status = "unknown"
        return c
    on = [u for u in users if u["enabled"]]
    if on:
        c.status, c.detail = "fail", "enabled: " + ", ".join(u["name"] for u in on)
        apply = "; ".join(f"Get-LocalUser | Where-Object {{ $_.SID.Value -like '*-{u['rid']}' }} | Disable-LocalUser" for u in on)
        undo = "; ".join(f"Get-LocalUser | Where-Object {{ $_.SID.Value -like '*-{u['rid']}' }} | Enable-LocalUser" for u in on)
        c.fix = Fix("caution", apply, undo, "if you sign in with the built-in Administrator itself, create another admin account first")
    else:
        c.detail = "both disabled"
    return c


def daily_admin(snap):
    c = Check("daily-admin", "device", "Daily account has administrator rights", status="info",
              why="malware you run with an admin account can take the whole PC after one UAC click")
    member = snap["ps"].get("admin_member")
    if isinstance(member, dict):
        c.status = "unknown"
    elif member:
        c.detail = "yes: a standard account for daily use (and an admin one for installs) is safer"
    else:
        c.status, c.detail = "pass", "no, standard user"
    return c


def lsa_protection(snap):
    c = Check("lsa-protection", "device", "LSA protection (LSASS as protected process)", severity="medium",
              why="stops password-dumping tools like Mimikatz from reading LSASS memory")
    v = reg(snap, "runasppl")
    if v in (1, 2):
        c.detail = "on"
    else:
        c.status, c.detail = "fail", "off"
        c.fix = reg_fix(snap, R["runasppl"], 2, "caution",
                        "old smart-card, VPN or password plug-ins that load into LSASS stop loading", reboot=True)
    return c


def _dg(snap):
    return ps(snap, "dg")


def memory_integrity(snap):
    c = Check("memory-integrity", "device", "Memory integrity (HVCI)", severity="medium",
              why="the hypervisor checks every kernel driver, so a malicious or vulnerable one can't run kernel code")
    d = _dg(snap)
    if d is None:
        c.status = "unknown"
    elif 2 in (d.get("running") or []):
        c.detail = "on"
    else:
        c.status, c.detail = "fail", "off"
        c.manual = "Windows Security > Device security > Core isolation > Memory integrity: On " \
                   "(windowsdefender://coreisolation). It checks your drivers first; a command would not."
    return c


def credential_guard(snap):
    c = Check("credential-guard", "device", "Credential Guard", status="info",
              why="keeps password hashes inside the hypervisor, out of reach of even admin-level malware")
    d, edition = _dg(snap), str(reg(snap, "edition") or "")
    if d is None:
        c.status = "unknown"
    elif 1 in (d.get("running") or []):
        c.status, c.detail = "pass", "on"
    elif not re.search(r"enterprise|education", edition, re.I):
        c.detail = f"needs Windows Enterprise or Education (this is {edition or 'unknown edition'})"
    else:
        c.status, c.severity, c.detail = "fail", "low", "off"
        c.manual = "turn on with Group Policy: Device Guard > Turn On Virtualization Based Security > Credential Guard"
    return c


def driver_blocklist(snap):
    c = Check("driver-blocklist", "device", "Vulnerable driver blocklist", severity="medium",
              why="blocks the signed-but-vulnerable drivers ransomware loads to kill antivirus (BYOVD)")
    if reg(snap, "blocklist") == 0:
        c.status, c.detail = "fail", "turned off"
        c.fix = reg_fix(snap, R["blocklist"], 1, reboot=True)
    else:
        c.detail = "on"
    return c


def boot_options(snap):
    c = Check("boot-options", "device", "Driver signing and DEP at boot", severity="high",
              why="test-signing mode lets any unsigned driver (rootkits, cheat drivers) load; DEP off re-enables "
                  "old exploit tricks")
    opts = str(reg(snap, "startopts") or "").upper()
    bad = [n for n, flag in (("test signing", "TESTSIGNING"), ("integrity checks off", "DISABLE_INTEGRITY_CHECKS"),
                             ("DEP always off", "NOEXECUTE=ALWAYSOFF")) if flag in opts]
    if bad:
        c.status, c.detail = "fail", ", ".join(bad)
        apply, undo = [], []
        if "TESTSIGNING" in opts:
            apply.append("bcdedit /set testsigning off | Out-Null"); undo.append("bcdedit /set testsigning on | Out-Null")
        if "DISABLE_INTEGRITY_CHECKS" in opts:
            apply.append("bcdedit /set nointegritychecks off | Out-Null"); undo.append("bcdedit /set nointegritychecks on | Out-Null")
        if "NOEXECUTE=ALWAYSOFF" in opts:
            apply.append("bcdedit /set nx OptIn | Out-Null"); undo.append("bcdedit /set nx AlwaysOff | Out-Null")
        c.fix = Fix("caution", "; ".join(apply), "; ".join(undo), "a test-signed driver you installed on purpose stops loading",
                    reboot=True)
    else:
        c.detail = "normal"
    return c


def secure_boot(snap):
    c = Check("secure-boot", "device", "Secure Boot", severity="medium",
              why="checks the boot loader's signature, so bootkits can't start before Windows")
    v = reg(snap, "secureboot")
    if v == 1:
        c.detail = "on"
    elif v == DENIED:
        c.status = "unknown"
    else:
        c.status, c.detail = "fail", "off or not supported"
        c.manual = "turn it on in the UEFI/BIOS setup (Boot > Secure Boot); needs UEFI mode, not legacy/CSM"
    return c


def bitlocker(snap):
    c = Check("bitlocker", "device", "Drive encryption (BitLocker)", severity="medium",
              why="without encryption anyone with the PC or its disk reads every file and saved browser session")
    v = snap["ps"].get("bitlocker")
    if isinstance(v, dict) or v is None:
        c.status = "unknown"
    elif v in (1, 6):
        c.detail = "on"
    elif v in (3, 5):
        c.status, c.severity, c.detail = "fail", "low", "encrypting or suspended"
    elif v == 0:
        c.status, c.detail = "info", "not available on this drive/edition"
    else:
        c.status, c.detail = "fail", "off"
        c.manual = "Settings > Privacy & security > Device encryption (or Control Panel > BitLocker). " \
                   "Save the recovery key somewhere off this PC first."
    return c


def wdigest(snap):
    c = Check("wdigest", "device", "WDigest plain-text passwords", severity="high",
              why="with WDigest on, Windows keeps your password in memory as plain text; malware turns it on and waits")
    if reg(snap, "wdigest") == 1:
        c.status, c.detail = "fail", "on: passwords are kept in plain text in memory"
        c.fix = reg_fix(snap, R["wdigest"], 0)
    else:
        c.detail = "off"
    return c


def autorun(snap):
    c = Check("autorun", "device", "AutoRun for USB drives and discs", severity="low",
              why="AutoRun runs a program as soon as a drive is plugged in, the oldest USB worm trick")
    lm, cu = reg(snap, "autorun_lm"), reg(snap, "autorun_cu")
    if 255 in (lm, cu):
        c.detail = "off for all drives"
    else:
        c.status, c.detail = "fail", "not turned off for all drive types"
        c.fix = reg_fix(snap, R["autorun_lm"], 255)
    return c


def extensions(snap):
    c = Check("extensions", "device", "File extensions shown", severity="medium",
              why="with extensions hidden, 'invoice.pdf.exe' shows as 'invoice.pdf': the oldest malware disguise")
    if reg(snap, "hide_ext") == 0:
        c.detail = "shown"
    else:
        c.status, c.detail = "fail", "hidden (the Windows default)"
        c.fix = reg_fix(snap, R["hide_ext"], 0)
    return c


def powershell_v2(snap):
    c = Check("powershell-v2", "device", "PowerShell 2.0 engine", severity="medium",
              why="'powershell -version 2' skips script logging and AMSI scanning, so attackers ask for it")
    feat, build = (ps(snap, "features") or {}).get("MicrosoftWindowsPowerShellV2Root"), snap.get("build") or 0
    if feat == "Enabled" or (feat is None and reg(snap, "psv2") == "2.0" and build < 26100):
        c.status, c.detail = "fail", "installed"
        c.fix = Fix("safe", "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null",
                    "Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -All -NoRestart | Out-Null")
    elif feat in ("Disabled", "Absent", "DisabledWithPayloadRemoved") or build >= 26100:
        c.detail = "removed" if build >= 26100 and feat is None else "not installed"
    else:
        c.status = "unknown"
    return c


def ps_logging(snap):
    c = Check("ps-logging", "device", "PowerShell script block logging", severity="low",
              why="records every PowerShell script that runs, de-obfuscated; the first thing an investigator wants")
    if reg(snap, "sblog") == 1:
        c.detail = "on"
    else:
        c.status, c.detail = "fail", "off"
        c.fix = reg_fix(snap, R["sblog"], 1, note="scripts that contain passwords in plain text get logged too")
    return c


def cmdline_audit(snap):
    c = Check("cmdline-audit", "device", "Process command lines in the Security log", severity="low",
              why="event 4688 with the command line shows what ran and how; evtx-hunter and Sigma rules need it")
    if reg(snap, "cmdline") == 1:
        c.detail = "on"
    else:
        c.status, c.detail = "fail", "off"
        f = reg_fix(snap, R["cmdline"], 1)
        c.fix = Fix("safe", f.apply + '; auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null',
                    f.undo + "  # process-creation auditing stays on: it only adds log entries")
    return c


def script_host(snap):
    c = Check("script-host", "device", "Windows Script Host (.vbs/.js files)", status="info",
              why="double-clicking a .js or .vbs file runs it; most email and download droppers are exactly that")
    if reg(snap, "wsh") == 0:
        c.status, c.detail = "pass", "off"
    else:
        c.detail = "on (the Windows default)"
        c.fix = reg_fix(snap, R["wsh"], 0, "caution", "some installers and company logon scripts use .vbs and stop working")
    return c


def updates(snap, now=None):
    c = Check("updates", "device", "Windows updates", severity="high",
              why="most real-world attacks use bugs that already have a patch")
    if reg(snap, "noautoupdate") == 1:
        c.status, c.detail = "fail", "automatic updates turned off by policy"
        c.fix = reg_fix(snap, R["noautoupdate"], 0)
        return c
    u = ps(snap, "updates")
    dates = [dt.datetime.fromisoformat(d[:19]) for d in (u or {}).values() if isinstance(d, str)]
    if not dates:
        c.status = "unknown"
        return c
    days = ((now or dt.datetime.now()) - max(dates)).days
    if days > 60:
        c.status, c.detail = "fail", f"last update installed {days} days ago"
    elif days > 35:
        c.status, c.severity, c.detail = "fail", "medium", f"last update installed {days} days ago"
    else:
        c.detail = f"last update installed {days} day(s) ago"
    if c.status == "fail":
        c.manual = "Settings > Windows Update > Check for updates (ms-settings:windowsupdate)"
    return c


CHECKS = [firewall, firewall_rules, listening, smb1, smb_signing, smb_guest, llmnr, netbios, ntlm, lm_hash, anonymous,
          rdp, remote_assistance, remote_registry, winrm, wifi, hosts, proxy, dns, network_profile, shares,
          antivirus, defender, tamper, cloud, pua, network_protection, signatures, exclusions, asr, asr_strict,
          controlled_folders, smartscreen, uac, accounts, daily_admin, lsa_protection, memory_integrity,
          credential_guard, driver_blocklist, boot_options, secure_boot, bitlocker, wdigest, autorun, extensions,
          powershell_v2, ps_logging, cmdline_audit, script_host, updates]


def evaluate(snap) -> list[Check]:
    out = []
    for fn in CHECKS:
        try:
            out.append(fn(snap))
        except Exception as e:                  # a surprising snapshot must never look like a pass
            out.append(Check(fn.__name__.replace("_", "-"), "device", fn.__name__, "unknown",
                             detail=f"check crashed: {type(e).__name__}: {e}"))
    return out


def score(checks) -> int:
    return max(0, 100 - sum(PENALTY[c.severity] for c in checks if c.status == "fail"))


def grade(checks) -> str:
    fails = [c for c in checks if c.status == "fail"]
    if any(c.severity == "critical" for c in fails):
        return "F"
    s = score(checks)
    if s == 100:
        return "A+"
    for limit, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if s >= limit:
            return letter
    return "F"
