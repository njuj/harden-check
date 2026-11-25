# harden-check

[![Part of Cryptid Security](https://img.shields.io/badge/part_of-Cryptid%20Security-00ff9c?style=flat-square&labelColor=0d1117)](https://github.com/cryptid-security)

**Grade a Windows PC's network and device security in one read-only scan, then write the fixes as a PowerShell
script with an exact undo.** 51 checks: the firewall and the programs it lets in, SMB, LLMNR/NetBIOS poisoning,
NTLM, Remote Desktop, open Wi-Fi, the hosts file and proxy malware edits, Defender (and the exclusions malware adds),
attack surface reduction rules, UAC, LSA protection, memory integrity, the vulnerable driver blocklist, boot
options, BitLocker, WDigest, PowerShell logging and more. Each finding says why it matters in one line. Zero
dependencies.

[![ci](https://github.com/njuj/harden-check/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/harden-check/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-00ff9c?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-00ff9c?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-00ff9c?labelColor=0b0f17)

```text
$ python -m hardencheck
 harden-check 0.1.0  ·  Windows 11 Pro 26H2 (26300.10075)  ·  not elevated  ·  51 checks in 15.7s
 1 check(s) need administrator to read: run from an elevated terminal for all of them

 DEVICE
  MEDIUM   Attack surface reduction rules: 11 of 12 recommended rules block
           these Defender rules stop the moves real attacks make: Office spawning PowerShell, scripts
           launching downloads, dumping LSASS, loading vulnerable drivers, WMI persistence
           - Block abuse of exploited vulnerable signed drivers: not set
           fix (safe, in --fix script)
  MEDIUM   Drive encryption (BitLocker): off
           without encryption anyone with the PC or its disk reads every file and saved browser session
           fix (by hand): Settings > Privacy & security > Device encryption (or Control Panel > BitLocker).
           Save the recovery key somewhere off this PC first.
  LOW      Process command lines in the Security log: off
           event 4688 with the command line shows what ran and how; evtx-hunter and Sigma rules need it
           fix (safe, in --fix script)

 GOOD TO KNOW
  Programs accepting connections from the network: 9 port(s) open on all interfaces: 135 svchost,
  445 System, 5040 svchost, 5357 System, 49664 lsass, 49665 wininit, 49666 svchost, 49667 svchost, ...
  Network type: Ethernet: Private
  Stricter attack surface reduction rules: 0 of 6 on
  Credential Guard: needs Windows Enterprise or Education (this is Professional)
  Windows Script Host (.vbs/.js files): on (the Windows default)

 NOT READ
  Defender exclusions

 Grade B  (86/100)  ·  network A+ (100)  ·  device B (86)  ·  41 passed, 3 to fix
 write the fixes: harden-check --fix harden.ps1  (2 safe, 2 more with --level caution); nothing changes
 until you run it as administrator, and harden-undo.ps1 puts it all back
```

A real run on a hardened Windows 11 PC, as a standard user (the DNS line is left out here).

## Fixes that don't break your PC

`harden-check` itself never changes anything. `--fix harden.ps1` writes two scripts for you to read and run:

- **`harden.ps1`** tries to create a restore point, then applies each fix as its own step and prints `ok` or `fail` for
  each; one failing step never stops the rest.
- **`harden-undo.ps1`** puts back **the exact values the scan saw**, in reverse order: a registry value that wasn't
  there is removed again, a service gets its old start type back (and is started if it was running), an ASR rule
  that was in audit mode goes back to audit.

Every fix has a risk level:

| level | what it means | examples |
|---|---|---|
| **safe** (default) | changes nothing a normal home or office PC relies on | LLMNR off, WDigest off, NTLMv2 only, SMBv1 off, the 12 standard ASR rules, file extensions shown, PUA blocking, script block logging |
| **caution** (`--level caution`) | can break one specific thing, and the script says which | SMB signing (old NAS), LSA protection (old smart-card/VPN plug-ins), Windows Script Host off (.vbs installers), Remote Desktop off, the 6 stricter ASR rules, controlled folder access |
| **by hand** | no command can do it safely, so you get the exact place to click | Tamper Protection (no command exists, by design), memory integrity (Windows checks your drivers first), BitLocker (save the recovery key first), Secure Boot (firmware) |

Left alone on purpose: IPv6, mDNS, the WPAD service, the print spooler and network discovery. Turning those off
breaks casting, printers or Windows itself more often than it stops an attack on a home network.

**Checked on a real Windows, every push.** The `roundtrip` CI job runs on a fresh GitHub Windows VM: scan, apply
every safe fix for real (14 on the current runner image), re-scan to confirm each one now passes, run the undo,
and confirm every registry value and every Defender, firewall, SMB, service and Wi-Fi setting is back to exactly
what it was. Its first run caught a real trap: `Set-MpPreference` reports success even when a Group Policy
overrides it, so every Defender fix now checks that it took, and a policy that turns Defender off is reported as one.

## What it checks

**Network (21):** Windows Firewall on, with inbound blocked · inbound allow rules for programs in user folders
(njRAT adds one for itself), unsigned ones flagged · unsigned programs in user folders listening on every
interface · SMBv1 · SMB signing · insecure guest logons · LLMNR · NetBIOS over TCP/IP · NTLM level · LM hashes ·
anonymous enumeration · Remote Desktop and NLA · Remote Assistance · Remote Registry · WinRM · saved open Wi-Fi
that auto-connects (evil twin) · hosts file entries for security, update and login sites · a proxy or PAC
script · DNS servers · network type · shared folders.

**Device (30):** active antivirus · Defender real-time, Tamper Protection, cloud protection, PUA blocking,
network protection, signature age · Defender exclusions that cover a drive, a user folder or `.exe` · 12
recommended ASR rules (by GUID, from Microsoft's ASR reference) and 6 stricter ones · controlled folder access ·
SmartScreen · UAC · built-in Administrator/Guest · daily use as admin · LSA protection · memory integrity ·
Credential Guard · vulnerable driver blocklist · test signing, integrity checks and DEP at boot · Secure Boot ·
BitLocker · WDigest · AutoRun · hidden file extensions · PowerShell 2.0 · script block logging · process command
lines in event 4688 · Windows Script Host · Windows Update age and policy.

How it reads them: the registry directly, plus one PowerShell run for what only cmdlets know (Defender, firewall,
SMB, Device Guard, listening ports, Wi-Fi profiles, Authenticode signatures). As a standard user everything but
Defender's exclusions (and two Windows-feature states) is readable; run it elevated for all of them.

## Use

```powershell
git clone https://github.com/njuj/harden-check
cd harden-check
python -m hardencheck                       # the report
python -m hardencheck --all                 # also list what passed
python -m hardencheck --fix harden.ps1      # write harden.ps1 + harden-undo.ps1 (safe fixes)
python -m hardencheck --fix harden.ps1 --level caution
powershell -ExecutionPolicy Bypass -File .\harden.ps1     # as administrator, after reading it
python -m hardencheck --json                # machine-readable
```

`--save-snapshot FILE` keeps what was read and `--snapshot FILE` grades it later (or on another machine). A
snapshot holds your user folder paths and DNS servers: don't post it publicly.

Exit codes: `0` no high or critical failure, `1` a high or critical check failed, `2` could not scan.

## Tests

```powershell
python -m unittest discover -s tests -t .
```

34 tests: every check fed a hardened snapshot with one setting broken (57 cases) must fail that check and only
that check, at the right severity, with the right fix level. Also undo values (old value back, missing value
removed again, user settings written to the scanned user's hive even when an admin account runs the script),
quoting of hostile names, scripts parsed by PowerShell's own parser, the command line, and a live scan on
Windows. CI runs them on Ubuntu and Windows (Python 3.10 and 3.13), plus the apply-and-undo round trip above.

## License

MIT
