"""harden-check: grade this Windows PC's network and device security, and write the fixes as a reversible script.

Exit codes: 0 no high/critical failure · 1 a high or critical check failed · 2 could not scan.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time
from pathlib import Path

from . import __version__, checks as C, fixes

COLOR = {"critical": "1;97;41", "high": "1;91", "medium": "1;93", "low": "96", "dim": "90", "bold": "1", "ok": "92",
         "unknown": "95"}


def _console_utf8():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if sys.platform == "win32":
        os.system("")                                   # turns on ANSI colours in the classic console


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="harden-check", description=__doc__.splitlines()[0])
    ap.add_argument("--fix", type=Path, metavar="FILE.ps1",
                    help="write the fixes to FILE.ps1 and the undo to FILE-undo.ps1 (nothing is changed until you run it)")
    ap.add_argument("--level", choices=["safe", "caution"], default="safe",
                    help="safe: fixes that change nothing a normal PC relies on (default); caution: also the ones that "
                         "can break something specific, each one named")
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    ap.add_argument("--all", action="store_true", help="also list the checks that passed")
    ap.add_argument("--snapshot", type=Path, metavar="FILE", help="grade a saved snapshot instead of this PC")
    ap.add_argument("--save-snapshot", type=Path, metavar="FILE",
                    help="save what was read (contains your user folder paths and DNS servers: don't post it)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _os_name(snap) -> str:
    r = snap["reg"]
    product = str(r.get(C.R["product"]) or "Windows")
    if (snap.get("build") or 0) >= 22000:
        product = product.replace("Windows 10", "Windows 11")       # Windows 11 still reports "Windows 10" here
    ver, ubr = r.get(C.R["display"]), r.get(C.R["ubr"])
    return f"{product} {ver or ''} ({snap.get('build')}{f'.{ubr}' if ubr else ''})".replace("  ", " ")


def render(snap, results, color: bool, show_all: bool, seconds: float, level: str) -> str:
    def paint(text, key):
        return f"\033[{COLOR[key]}m{text}\033[0m" if color and key in COLOR else text

    fails = sorted((c for c in results if c.status == "fail"), key=lambda c: C.SEVERITIES.index(c.severity))
    unknown = [c for c in results if c.status == "unknown"]
    who = "administrator" if snap.get("elevated") else "not elevated"
    out = [paint(f" harden-check {__version__}", "bold") +
           paint(f"  ·  {_os_name(snap)}  ·  {who}  ·  {len(results)} checks in {seconds:.1f}s", "dim")]
    if unknown and not snap.get("elevated"):
        out.append(paint(f" {len(unknown)} check(s) need administrator to read: run from an elevated terminal for all of them", "dim"))
    out.append("")
    for area in ("network", "device"):
        mine = [c for c in fails if c.area == area]
        if not mine:
            continue
        out.append(paint(f" {area.upper()}", "bold"))
        for c in mine:
            out.append(f"  {paint(c.severity.upper().ljust(8), c.severity)} {c.title}: {c.detail}")
            out.append(paint(f"           {c.why}", "dim"))
            for item in [i for i in c.items if isinstance(i, str)][:6]:
                out.append(paint(f"           - {item}", "dim"))
            if c.fix:
                out.append(f"           fix ({c.fix.risk}{', needs restart' if c.fix.reboot else ''}, in --fix script)" +
                           (paint(f": {c.fix.note}", "dim") if c.fix.note else ""))
            elif c.manual:
                out.append(f"           fix (by hand): {c.manual}")
        out.append("")
    info = [c for c in results if c.status == "info" and c.detail]
    if info:
        out.append(paint(" GOOD TO KNOW", "bold"))
        for c in info:
            out.append(f"  {c.title}: " + paint(c.detail, "dim"))
        out.append("")
    if unknown:
        out.append(paint(" NOT READ", "bold"))
        out.append("  " + paint(", ".join(c.title for c in unknown), "dim"))
        out.append("")
    passed = [c for c in results if c.status == "pass"]
    if show_all and passed:
        out.append(paint(" PASSED", "bold"))
        out += [f"  {paint('ok', 'ok')}  {c.title}: " + paint(c.detail, "dim") for c in passed]
        out.append("")
    parts = []
    for area in ("network", "device"):
        mine = [c for c in results if c.area == area]
        parts.append(f"{area} {C.grade(mine)} ({C.score(mine)})")
    letter = C.grade(results)
    key = "ok" if letter.startswith("A") else "medium" if letter in ("B", "C") else "high"
    out.append(" " + paint(f"Grade {letter}  ({C.score(results)}/100)", key) + paint(
        f"  ·  {'  ·  '.join(parts)}  ·  {len(passed)} passed, {len(fails)} to fix", "dim"))
    safe = fixes.chosen(results, "safe")
    extra = len(fixes.chosen(results, "caution")) - len(safe)
    if safe or extra:
        out.append(paint(f" write the fixes: harden-check --fix harden.ps1  ({len(safe)} safe"
                         + (f", {extra} more with --level caution" if extra else "") + "); nothing changes until you "
                         "run it as administrator, and harden-undo.ps1 puts it all back", "dim"))
    return "\n".join(out) + "\n"


def to_json(snap, results) -> dict:
    return {"version": __version__, "os": _os_name(snap), "elevated": snap.get("elevated"),
            "grade": C.grade(results), "score": C.score(results),
            "areas": {a: {"grade": C.grade([c for c in results if c.area == a]),
                          "score": C.score([c for c in results if c.area == a])} for a in ("network", "device")},
            "checks": [dataclasses.asdict(c) for c in results]}


def main(argv: list[str] | None = None) -> int:
    _console_utf8()
    args = build_parser().parse_args(argv)
    started = time.perf_counter()
    try:
        if args.snapshot:
            snap = json.loads(args.snapshot.read_text(encoding="utf-8"))
        else:
            from . import gather
            snap = gather.snapshot()
    except (OSError, RuntimeError, ValueError) as e:
        print(f"harden-check: {e}", file=sys.stderr)
        return 2
    if args.save_snapshot:
        args.save_snapshot.write_text(json.dumps(snap, indent=1), encoding="utf-8")
    results = C.evaluate(snap)
    seconds = time.perf_counter() - started
    if args.json:
        print(json.dumps(to_json(snap, results), indent=2))
    else:
        color = not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        sys.stdout.write(render(snap, results, color, args.all, seconds, args.level))
    if args.fix:
        apply, undo, n = fixes.write(results, args.fix, args.level)
        print(f"wrote {apply} ({n} fix(es)) and {undo}. Run as administrator:\n"
              f"  powershell -ExecutionPolicy Bypass -File \"{apply.resolve()}\"", file=sys.stderr if args.json else sys.stdout)
    return 1 if any(c.status == "fail" and c.severity in ("critical", "high") for c in results) else 0
