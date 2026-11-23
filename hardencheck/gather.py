"""Read this PC's security settings into a plain-JSON snapshot. Read-only: nothing here changes the system."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import subprocess
import sys

from .checks import REG_PATHS

DENIED = "<denied>"

# One PowerShell run collects everything the registry alone can't tell. Each section fails on its own:
# a section that needs administrator comes back as {"error": ...} and its checks say "unknown".
PS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$o = [ordered]@{}
function S([string]$k, [scriptblock]$b) { try { $o[$k] = & $b } catch { $o[$k] = @{ error = "$($_.Exception.Message)" } } }
function L([string]$k, [scriptblock]$b) { try { $o[$k] = @(& $b) } catch { $o[$k] = @{ error = "$($_.Exception.Message)" } } }
function N($v) { if ($null -eq $v) { $null } else { [int]$v } }
function T($v) { if ($null -eq $v) { $null } else { "$v" } }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$o.elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$o.user_sid = $id.User.Value
S admin_member { [bool]((whoami /groups) -match 'S-1-5-32-544') }

L av { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | ForEach-Object { @{ name = $_.displayName; state = [int]$_.productState } } }
S mp { $s = Get-MpComputerStatus; @{ mode = T $s.AMRunningMode; realtime = $s.RealTimeProtectionEnabled; tamper = $s.IsTamperProtected; sig_age = N $s.AntivirusSignatureAge; service = $s.AMServiceEnabled } }
S mppref {
    $p = Get-MpPreference
    $ids = @($p.AttackSurfaceReductionRules_Ids | Where-Object { $_ }); $acts = @($p.AttackSurfaceReductionRules_Actions)
    @{ pua = N $p.PUAProtection; maps = N $p.MAPSReporting; cfa = N $p.EnableControlledFolderAccess; netprot = N $p.EnableNetworkProtection
       realtime_off = $p.DisableRealtimeMonitoring
       asr = @(for ($i = 0; $i -lt $ids.Count; $i++) { @{ id = "$($ids[$i])".ToLower(); action = N $acts[$i] } })
       excl_path = @($p.ExclusionPath | Where-Object { $_ }); excl_process = @($p.ExclusionProcess | Where-Object { $_ })
       excl_ext = @($p.ExclusionExtension | Where-Object { $_ }) }
}
L fw { Get-NetFirewallProfile | ForEach-Object { @{ name = "$($_.Name)"; enabled = "$($_.Enabled)"; inbound = "$($_.DefaultInboundAction)" } } }
L conn { Get-NetConnectionProfile | ForEach-Object { @{ alias = $_.InterfaceAlias; category = "$($_.NetworkCategory)" } } }
L listen {
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = @($_.ProcessName, $_.Path) }
    Get-NetTCPConnection -State Listen | ForEach-Object {
        $pp = $procs[[int]$_.OwningProcess]; if (-not $pp) { $pp = @($null, $null) }
        @{ addr = $_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; name = $pp[0]; path = $pp[1] } }
}
S smbs { $c = Get-SmbServerConfiguration; @{ smb1 = $c.EnableSMB1Protocol; signing = $c.RequireSecuritySignature } }
S smbc { $c = Get-SmbClientConfiguration; @{ signing = $c.RequireSecuritySignature; guest = $c.EnableInsecureGuestLogons } }
S bitlocker { N (New-Object -ComObject Shell.Application).NameSpace("$env:SystemDrive\").Self.ExtendedProperty('System.Volume.BitLockerProtection') }
S dg { $d = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
       @{ running = @($d.SecurityServicesRunning | ForEach-Object { [int]$_ }); vbs = N $d.VirtualizationBasedSecurityStatus } }
L adapters { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
    @{ name = $_.Description; id = $_.SettingID; netbios = N $_.TcpipNetbiosOptions; dns = @($_.DNSServerSearchOrder | Where-Object { $_ }) } } }
L users { Get-LocalUser | ForEach-Object { $rid = [int]($_.SID.Value -split '-')[-1]
    if ($rid -eq 500 -or $rid -eq 501) { @{ name = $_.Name; rid = $rid; enabled = $_.Enabled } } } }
L shares { Get-CimInstance Win32_Share | ForEach-Object { @{ name = $_.Name; path = $_.Path; type = [long]$_.Type } } }
S updates {
    $h = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $n = $h.GetTotalHistoryCount(); $last = $null
    if ($n -gt 0) { foreach ($e in $h.QueryHistory(0, [Math]::Min($n, 300))) {
        if ($e.ResultCode -eq 2 -and $e.Title -match 'KB\d' -and $e.Title -notmatch 'KB2267602|KB890830|KB4052623|KB915597|Defender') {
            if (-not $last -or $e.Date -gt $last) { $last = $e.Date } } } }
    $hf = (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
    @{ last_update = if ($last) { $last.ToString('o') } else { $null }; last_hotfix = if ($hf) { $hf.ToString('o') } else { $null } }
}
L services { Get-Service RemoteRegistry, WinRM, TermService, sshd -ErrorAction SilentlyContinue | ForEach-Object {
    @{ name = $_.Name; status = "$($_.Status)"; start = "$($_.StartType)" } } }
L wlan {
    $d = Join-Path $env:TEMP ('harden-check-' + [guid]::NewGuid()); New-Item -ItemType Directory $d | Out-Null
    try { netsh wlan export profile folder="$d" | Out-Null
          Get-ChildItem -LiteralPath $d -Filter *.xml | ForEach-Object { [xml]$x = Get-Content -Raw -LiteralPath $_.FullName
              @{ name = "$($x.WLANProfile.name)"; auth = "$($x.WLANProfile.MSM.security.authEncryption.authentication)"; mode = "$($x.WLANProfile.connectionMode)" } } }
    finally { Remove-Item -Recurse -Force -LiteralPath $d }
}
L fwrules {
    $item = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    foreach ($n in $item.GetValueNames()) { $v = [string]$item.GetValue($n)
        if ($v -match '\|Action=Allow\|' -and $v -match '\|Active=TRUE\|' -and $v -match '\|Dir=In\|' -and $v -match '\|App=') { @{ id = $n; rule = $v } } }
}
S sigs {
    $paths = @(); foreach ($r in @($o.fwrules)) { if ($r.rule -match '\|App=([^|]+)') { $paths += [Environment]::ExpandEnvironmentVariables($Matches[1]) } }
    foreach ($l in @($o.listen)) { if ($l.path) { $paths += $l.path } }
    $m = @{}
    foreach ($p in ($paths | Where-Object { $_ -match '\\Users\\|\\AppData\\|\\Temp\\|\\Downloads\\|\\ProgramData\\' } | Sort-Object -Unique)) {
        if (Test-Path -LiteralPath $p -PathType Leaf) { $s = Get-AuthenticodeSignature -LiteralPath $p
            $m[$p] = @{ status = "$($s.Status)"; signer = if ($s.SignerCertificate) { $s.SignerCertificate.GetNameInfo('SimpleName', $false) } else { $null } } }
        else { $m[$p] = @{ status = 'Missing'; signer = $null } } }
    $m
}
if ($o.elevated) {
    S features { $f = @{}; foreach ($n in 'MicrosoftWindowsPowerShellV2Root', 'SMB1Protocol') {
        $x = Get-WindowsOptionalFeature -Online -FeatureName $n; $f[$n] = if ($x) { "$($x.State)" } else { 'Absent' } }; $f }
} else { $o.features = @{ error = 'needs administrator' } }
$o | ConvertTo-Json -Depth 6 -Compress
"""


def _hive(path: str):
    import winreg
    root, _, rest = path.partition("\\")
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[root], rest


def read_registry(paths) -> dict:
    import winreg
    out = {}
    for path in paths:
        hive, rest = _hive(path)
        key, _, name = rest.rpartition("\\")
        try:
            with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                value, kind = winreg.QueryValueEx(k, name)
            out[path] = value.hex() if isinstance(value, bytes) else value
        except FileNotFoundError:
            out[path] = None
        except PermissionError:
            out[path] = DENIED
        except OSError:
            out[path] = None
    return out


def run_powershell(script: str, timeout: int = 180) -> dict:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\WindowsPowerShell\v1.0\powershell.exe")
    p = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                       capture_output=True, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    text = p.stdout.decode("utf-8", "replace").lstrip("\ufeff").strip()
    line = text.splitlines()[-1] if text else ""
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        err = p.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"PowerShell returned no data ({err[:300] or line[:300] or 'empty output'})") from None


def read_hosts() -> str | None:
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
    try:
        with open(path, "rb") as f:
            return f.read(1 << 20).decode("utf-8", "replace")
    except OSError:
        return None


def snapshot() -> dict:
    if sys.platform != "win32":
        raise RuntimeError("harden-check reads a live Windows PC; elsewhere use --snapshot FILE")
    ps = run_powershell(PS)
    reg = read_registry(REG_PATHS)
    build = reg.get(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber")
    return {
        "version": 1,
        "taken": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "elevated": bool(ps.pop("elevated", False)),
        "user_sid": ps.pop("user_sid", None),
        "build": int(build) if str(build).isdigit() else 0,
        "reg": reg,
        "ps": ps,
        "hosts": read_hosts(),
    }
