"""CLI hardening-audit.

    python3 -m hardening_audit                     # audit lengkap, tampil di terminal
    python3 -m hardening_audit --format md,json --out ~/laporan
    python3 -m hardening_audit --only ssh,akses
    python3 -m hardening_audit --skip kernel.updates
    python3 -m hardening_audit --list              # daftar pemeriksaan
    python3 -m hardening_audit --fail-under 80     # cocok untuk CI
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import socket
import sys
from pathlib import Path

from . import __version__, registry, report as report_mod
from .model import Report, Severity, Status


def _split(v: str | None) -> list[str] | None:
    return [x.strip() for x in v.split(",") if x.strip()] if v else None


def cmd_list() -> int:
    registry.load_all()
    rows = registry.describe()
    print(f"{'KODE':<34}{'ROOT':<6}PEMERIKSAAN")
    for code, title, needs_root in rows:
        print(f"{code:<34}{'ya' if needs_root else '-':<6}{title}")
    print(f"\nTotal {len(rows)} pemeriksaan.")
    print("Filter memakai kode atau kategori, mis: --only ssh,berkas  --skip kernel.updates")
    return 0


def run_audit(args) -> int:
    registry.load_all()
    classes = registry.select(_split(args.only), _split(args.skip))
    if not classes:
        print("tidak ada pemeriksaan yang cocok dengan filter", file=sys.stderr)
        return 2

    ctx = {
        "is_root": registry.is_root(),
        "hostname": socket.gethostname(),
    }
    rep = Report(hostname=ctx["hostname"], platform=platform.platform(),
                 started=dt.datetime.now().isoformat(timespec="seconds"),
                 is_root=ctx["is_root"])

    for cls in classes:
        try:
            rep.findings.extend(cls().run(ctx) or [])
        except Exception as exc:                       # noqa: BLE001
            rep.errors.append(f"{cls.CODE}: {type(exc).__name__}: {exc}")

    rep.finished = dt.datetime.now().isoformat(timespec="seconds")

    if args.json and not args.out:
        print(report_mod.to_json(rep))
    else:
        print(report_mod.to_text(rep))

    if args.out:
        formats = _split(args.format) or ["text", "md", "json"]
        files = report_mod.write(Path(args.out).expanduser(), rep, formats)
        print()
        for f in files:
            print(f"  -> {f}")

    if args.fail_under is not None and rep.score < args.fail_under:
        print(f"\nskor {rep.score}% di bawah ambang {args.fail_under}%", file=sys.stderr)
        return 1
    critical = [f for f in rep.findings
                if f.status is Status.FAIL and f.severity is Severity.CRITICAL]
    return 1 if critical and args.fail_on_critical else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hardening_audit",
        description="Audit baseline keamanan server (read-only, tanpa mengubah sistem)")
    ap.add_argument("--only", help="jalankan hanya kode/kategori ini (dipisah koma)")
    ap.add_argument("--skip", help="lewati kode/kategori ini")
    ap.add_argument("--format", help="text,md,json (default: ketiganya saat --out)")
    ap.add_argument("--out", help="folder untuk menyimpan laporan")
    ap.add_argument("--json", action="store_true", help="cetak JSON ke stdout")
    ap.add_argument("--list", action="store_true", help="daftar pemeriksaan")
    ap.add_argument("--fail-under", type=int,
                    help="exit ≠ 0 bila skor di bawah angka ini (untuk CI)")
    ap.add_argument("--fail-on-critical", action="store_true",
                    help="exit ≠ 0 bila ada temuan CRITICAL yang FAIL")
    ap.add_argument("--version", action="version", version=f"hardening-audit {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        return cmd_list()
    return run_audit(args)
