"""Penyusun laporan: teks (terminal), Markdown, JSON."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .model import Report, Severity, Status

BAR = "=" * 72


def to_text(r: Report) -> str:
    L = [BAR, f"  LAPORAN HARDENING — {r.hostname}", BAR]
    L.append(f"platform   : {r.platform}")
    L.append(f"waktu      : {r.started} → {r.finished}")
    L.append(f"sebagai    : {'root' if r.is_root else 'user biasa (sebagian cek dilewati)'}")
    L.append(f"skor       : {r.score}%  ({r.count(Status.PASS)} lolos / {r.applicable} diperiksa, "
             f"{r.count(Status.SKIP)} dilewati)")
    L.append("")
    L.append(f"  ✅ PASS {r.count(Status.PASS):>3}   ❌ FAIL {r.count(Status.FAIL):>3}   "
             f"⚠️  WARN {r.count(Status.WARN):>3}   ➖ SKIP {r.count(Status.SKIP):>3}")
    L.append("")

    problems = r.by_severity()
    if problems:
        L.append("TEMUAN YANG PERLU DITINDAK (urut prioritas)")
        L.append("-" * 72)
        for f in problems:
            L.append(f"{f.status.symbol} [{f.severity.value}] {f.code} — {f.title}")
            if f.detail:
                L.append(f"    kondisi : {f.detail}")
            if f.remediation:
                L.append(f"    perbaikan: {f.remediation}")
            L.append("")
    else:
        L.append("Tidak ada temuan yang perlu ditindak. 🎉")
        L.append("")

    L.append("HASIL LENGKAP")
    L.append("-" * 72)
    for f in sorted(r.findings, key=lambda x: (x.category, x.code)):
        L.append(f"{f.status.symbol} {f.code:<22} {f.title}")
    if r.errors:
        L.append("")
        L.append("ERROR SAAT PEMERIKSAAN")
        L.append("-" * 72)
        for e in r.errors:
            L.append(f"  {e}")
    return "\n".join(L)


def to_markdown(r: Report) -> str:
    L = [f"# Laporan Hardening — `{r.hostname}`", ""]
    L.append(f"- **Platform**: {r.platform}")
    L.append(f"- **Waktu**: {r.started} → {r.finished}")
    L.append(f"- **Dijalankan sebagai**: {'root' if r.is_root else 'user biasa'}")
    L.append(f"- **Skor**: **{r.score}%** ({r.count(Status.PASS)} lolos / {r.applicable} diperiksa)")
    L.append("")
    L.append("| PASS | FAIL | WARN | SKIP |")
    L.append("|---|---|---|---|")
    L.append(f"| {r.count(Status.PASS)} | {r.count(Status.FAIL)} | "
             f"{r.count(Status.WARN)} | {r.count(Status.SKIP)} |")
    L.append("")

    problems = r.by_severity()
    L.append("## Temuan yang perlu ditindak")
    L.append("")
    if not problems:
        L.append("_Tidak ada. 🎉_")
    else:
        L.append("| Prioritas | Kode | Temuan | Perbaikan |")
        L.append("|---|---|---|---|")
        for f in problems:
            det = f.detail.replace("\n", " ").replace("|", "\\|")[:160]
            rem = f.remediation.replace("\n", " ").replace("|", "\\|")[:200]
            L.append(f"| {f.severity.value} | `{f.code}` | {f.title}<br><sub>{det}</sub> | {rem} |")
    L.append("")
    L.append("## Hasil lengkap")
    L.append("")
    L.append("| Status | Kode | Kategori | Pemeriksaan |")
    L.append("|---|---|---|---|")
    for f in sorted(r.findings, key=lambda x: (x.category, x.code)):
        L.append(f"| {f.status.value} | `{f.code}` | {f.category} | {f.title} |")
    if r.errors:
        L.append("")
        L.append("## Error")
        L.append("")
        for e in r.errors:
            L.append(f"- {e}")
    return "\n".join(L)


def to_json(r: Report) -> str:
    return json.dumps(r.as_dict(), indent=2, ensure_ascii=False)


def write(outdir: Path, r: Report, formats: list[str]) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"hardening-{r.hostname}-{stamp}"
    written: list[Path] = []
    if "text" in formats:
        p = outdir / f"{base}.txt"
        p.write_text(to_text(r), encoding="utf-8")
        written.append(p)
    if "md" in formats:
        p = outdir / f"{base}.md"
        p.write_text(to_markdown(r), encoding="utf-8")
        written.append(p)
    if "json" in formats:
        p = outdir / f"{base}.json"
        p.write_text(to_json(r), encoding="utf-8")
        written.append(p)
    return written
