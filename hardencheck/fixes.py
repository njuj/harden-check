"""Turn the failed checks into two PowerShell scripts: one that applies the fixes and one that undoes them."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from . import __version__
from .checks import Check

PRELUDE = r"""#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$script:ok = 0; $script:bad = 0
function Step([string]$title, [scriptblock]$do) {
    $global:LASTEXITCODE = 0
    try {
        & $do
        if ($LASTEXITCODE -ne 0) { throw "a command exited with code $LASTEXITCODE" }
        $script:ok++; Write-Host "  ok    $title" -ForegroundColor Green
    } catch { $script:bad++; Write-Host "  fail  ${title}: $($_.Exception.Message)" -ForegroundColor Red }
}
"""


def chosen(checks: list[Check], level: str) -> list[Check]:
    allowed = ("safe",) if level == "safe" else ("safe", "caution")
    return [c for c in checks if c.fix and c.fix.risk in allowed and (c.status == "fail" or c.fix.risk == "caution")]


def _block(code: str) -> str:
    return "{\n    " + code.replace("\n", "\n    ") + "\n}"      # own lines: a trailing # comment can't eat the }


def scripts(checks: list[Check], level: str = "safe") -> tuple[str, str]:
    todo = chosen(checks, level)
    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    reboot = any(c.fix.reboot for c in todo)
    head = f"# harden-check {__version__}, written {stamp}: {len(todo)} fix(es), level '{level}'.\n"
    listing = "".join(f"#   [{c.fix.risk}] {c.title}: {c.detail}" + (f"  ({c.fix.note})" if c.fix.note else "") + "\n"
                      for c in todo)

    apply = [head, "# Undo everything with harden-undo.ps1 (written at the same time, with the values seen then).\n",
             listing, PRELUDE,
             f"Write-Host 'harden-check: applying {len(todo)} fix(es)'\n",
             "try { Checkpoint-Computer -Description 'harden-check' -RestorePointType MODIFY_SETTINGS; "
             "Write-Host '  ok    restore point created' -ForegroundColor Green }\n"
             "catch { Write-Host \"  note  no restore point ($($_.Exception.Message)); harden-undo.ps1 still works\" "
             "-ForegroundColor Yellow }\n"]
    apply += [f"Step {_ps(c.title)} {_block(c.fix.apply)}\n" for c in todo]
    tail = "Write-Host \"$script:ok applied, $script:bad failed.\""
    apply.append(tail + (" ; Write-Host 'Restart Windows to finish.' -ForegroundColor Yellow\n" if reboot else "\n"))

    undo = [head.replace("fix(es)", "undo step(s)"), "# Puts back what harden-check saw before harden.ps1 ran.\n",
            listing, PRELUDE, f"Write-Host 'harden-check: undoing {len(todo)} fix(es)'\n"]
    for c in reversed(todo):
        code = c.fix.undo.strip()
        if code.startswith("#") and "\n" not in code:
            undo.append(f"Write-Host {_ps('  note  ' + c.title + ': ' + code.lstrip('# '))}\n")
        else:
            undo.append(f"Step {_ps(c.title)} {_block(code)}\n")
    undo.append(tail.replace("applied", "undone") + (" ; Write-Host 'Restart Windows to finish.' -ForegroundColor Yellow\n" if reboot else "\n"))
    return "".join(apply), "".join(undo)


def _ps(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def write(checks: list[Check], path: Path, level: str = "safe") -> tuple[Path, Path, int]:
    apply, undo = scripts(checks, level)
    undo_path = path.with_name(path.stem + "-undo" + (path.suffix or ".ps1"))
    for p, text in ((path, apply), (undo_path, undo)):
        # BOM + CRLF: Windows PowerShell 5.1 reads BOM-less files as the ANSI code page and garbles Wi-Fi names
        p.write_bytes(b"\xef\xbb\xbf" + text.replace("\n", "\r\n").encode("utf-8"))
    return path, undo_path, len(chosen(checks, level))
