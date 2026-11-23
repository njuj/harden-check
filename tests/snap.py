"""A snapshot of a fully hardened PC; tests break one setting at a time."""

import copy
import datetime as dt

from hardencheck.checks import ASR_CAUTION, ASR_SAFE, R

SID = "S-1-5-21-1000000000-2000000000-3000000000-1001"


def hardened() -> dict:
    reg = {path: None for path in R.values()}
    reg.update({
        R["llmnr"]: 0, R["lmcompat"]: 5, R["nolmhash"]: 1, R["restrictanon"]: 1, R["restrictsam"]: 1,
        R["everyoneanon"]: 0, R["runasppl"]: 2, R["rdp_deny"]: 1, R["rdp_nla"]: 1, R["remote_assist"]: 0,
        R["uac_lua"]: 1, R["uac_admin"]: 5, R["uac_desktop"]: 1, R["cmdline"]: 1, R["smartscreen"]: "Warn",
        R["secureboot"]: 1, R["startopts"]: " NOEXECUTE=OPTIN  NOVGA", R["autorun_lm"]: 255, R["hide_ext"]: 0,
        R["sblog"]: 1, R["wsh"]: 0, R["edition"]: "Professional", R["product"]: "Windows 10 Pro",
        R["display"]: "24H2", R["build"]: "26100", R["ubr"]: 2314,
    })
    recent = (dt.datetime.now() - dt.timedelta(days=5)).isoformat()
    return copy.deepcopy({
        "version": 1, "taken": recent, "elevated": True, "user_sid": SID, "build": 26100, "reg": reg, "hosts": "",
        "ps": {
            "admin_member": False,
            "av": [{"name": "Windows Defender", "state": 397568}],
            "mp": {"mode": "Normal", "realtime": True, "tamper": True, "sig_age": 0, "service": True},
            "mppref": {"pua": 1, "maps": 2, "cfa": 1, "netprot": 1, "realtime_off": False,
                       "asr": [{"id": g, "action": 1} for g in list(ASR_SAFE) + list(ASR_CAUTION)],
                       "excl_path": [], "excl_process": [], "excl_ext": []},
            "fw": [{"name": n, "enabled": "True", "inbound": "NotConfigured"} for n in ("Domain", "Private", "Public")],
            "conn": [{"alias": "Wi-Fi", "category": "Public"}],
            "listen": [{"addr": "0.0.0.0", "port": 135, "pid": 1000, "name": "svchost", "path": None},
                       {"addr": "127.0.0.1", "port": 5000, "pid": 4000, "name": "devserver",
                        "path": r"C:\Users\me\AppData\Local\dev\devserver.exe"}],
            "smbs": {"smb1": False, "signing": True},
            "smbc": {"signing": True, "guest": False},
            "bitlocker": 1,
            "dg": {"running": [1, 2], "vbs": 2},
            "adapters": [{"name": "Intel Wi-Fi", "id": "{11111111-2222-3333-4444-555555555555}", "netbios": 2,
                          "dns": ["192.168.1.1"]}],
            "users": [{"name": "Administrator", "rid": 500, "enabled": False}, {"name": "Guest", "rid": 501, "enabled": False}],
            "shares": [{"name": "ADMIN$", "path": r"C:\Windows", "type": 2147483648}, {"name": "IPC$", "path": "", "type": 2147483651}],
            "updates": {"last_update": recent, "last_hotfix": recent},
            "services": [{"name": "RemoteRegistry", "status": "Stopped", "start": "Disabled"},
                         {"name": "WinRM", "status": "Stopped", "start": "Manual"},
                         {"name": "TermService", "status": "Stopped", "start": "Manual"}],
            "wlan": [{"name": "Home", "auth": "WPA2PSK", "mode": "auto"}],
            "fwrules": [{"id": "{AAAA}", "rule": r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|"
                                                 r"App=C:\Program Files\Steam\steam.exe|Name=Steam|"}],
            "sigs": {},
            "features": {"MicrosoftWindowsPowerShellV2Root": "Absent", "SMB1Protocol": "Disabled"},
        },
    })
