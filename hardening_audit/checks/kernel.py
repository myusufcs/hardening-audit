"""Pemeriksaan kernel (sysctl), pembaruan, dan pencatatan log."""
from __future__ import annotations

from pathlib import Path

from ..model import Finding, Severity, Status
from ..registry import Check
from ..util import read, run, which

CATEGORY = "kernel"

# nama sysctl -> (nilai yang diharapkan, keparahan bila salah, penjelasan)
SYSCTLS = [
    ("net.ipv4.conf.all.rp_filter", {"1", "2"}, Severity.MEDIUM,
     "Anti-spoofing sumber (reverse path filter; 1 = ketat, 2 = longgar)"),
    ("net.ipv4.conf.all.accept_redirects", {"0"}, Severity.MEDIUM,
     "Tolak ICMP redirect"),
    ("net.ipv4.conf.all.accept_source_route", {"0"}, Severity.MEDIUM,
     "Tolak source routing"),
    ("net.ipv4.tcp_syncookies", {"1"}, Severity.MEDIUM,
     "Proteksi SYN flood"),
    ("net.ipv6.conf.all.accept_redirects", {"0"}, Severity.LOW,
     "Tolak ICMP redirect IPv6"),
    ("kernel.randomize_va_space", {"2"}, Severity.MEDIUM,
     "ASLR aktif penuh"),
    ("kernel.dmesg_restrict", {"1"}, Severity.LOW,
     "Batasi akses dmesg ke root"),
    ("kernel.kptr_restrict", {"1", "2"}, Severity.LOW,
     "Sembunyikan alamat kernel"),
    ("fs.protected_hardlinks", {"1"}, Severity.LOW,
     "Proteksi hardlink"),
    ("fs.protected_symlinks", {"1"}, Severity.LOW,
     "Proteksi symlink"),
    ("net.ipv4.ip_forward", {"0"}, Severity.INFO,
     "IP forwarding (1 wajar bila jadi router/NAT)"),
]


def _sysctl_value(name: str) -> str | None:
    p = Path("/proc/sys") / name.replace(".", "/")
    val = read(p, 200)
    return val.strip() if val is not None else None


class SysctlHardening(Check):
    CODE = "kernel.sysctl"
    TITLE = "Parameter kernel diperketat (sysctl)"
    CATEGORY = CATEGORY

    def run(self, ctx):
        out = []
        bad = []
        for name, expected, severity, desc in SYSCTLS:
            actual = _sysctl_value(name)
            if actual is None:
                out.append(Finding(f"{self.CODE}:{name}", f"{name} — {desc}",
                                   Status.SKIP, Severity.INFO, "tidak tersedia",
                                   category=CATEGORY))
                continue
            if actual in expected:
                out.append(Finding(f"{self.CODE}:{name}", f"{name} — {desc}",
                                   Status.PASS, Severity.INFO, f"{actual}",
                                   category=CATEGORY))
            else:
                bad.append(f"{name}={actual} (harap {','.join(sorted(expected))})")
                out.append(Finding(f"{self.CODE}:{name}", f"{name} — {desc}",
                                   Status.FAIL, severity, f"nilai {actual}",
                                   f"Set `sysctl -w {name}={sorted(expected)[0]}` dan simpan di "
                                   f"/etc/sysctl.d/99-hardening.conf",
                                   category=CATEGORY))
        summary = Finding(self.CODE, self.TITLE,
                          Status.FAIL if bad else Status.PASS,
                          max((f.severity for f in out if f.status is Status.FAIL),
                              key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                                             "LOW": 3, "INFO": 4}[s.value],
                              default=Severity.INFO),
                          f"{len(bad)} dari {len(SYSCTLS)} belum sesuai"
                          + (f": {'; '.join(bad[:4])}" if bad else ""),
                          "Tulis semua setelan di /etc/sysctl.d/99-hardening.conf lalu "
                          "`sysctl --system`." if bad else "",
                          category=CATEGORY)
        return [summary] + out


class Updates(Check):
    CODE = "kernel.updates"
    TITLE = "Pembaruan keamanan terpasang & otomatis"
    CATEGORY = CATEGORY

    def run(self, ctx):
        out = []
        if which("apt"):
            code, res = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=60)
            if code == 0:
                count = sum(1 for ln in res.splitlines() if ln.startswith("Inst "))
                if count == 0:
                    out.append(Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                                       "tidak ada paket menunggu", category=CATEGORY))
                else:
                    out.append(Finding(self.CODE, self.TITLE, Status.WARN,
                                       Severity.MEDIUM if count < 30 else Severity.HIGH,
                                       f"{count} paket menunggu diperbarui",
                                       "Jalankan `apt update && apt upgrade` segera.",
                                       category=CATEGORY))
            else:
                out.append(Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                                   "tidak bisa memeriksa apt (butuh root?)", category=CATEGORY))
        else:
            out.append(Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                               "manajer paket tidak dikenal", category=CATEGORY))

        auto = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        text = read(auto)
        if text is None:
            out.append(Finding("kernel.auto_updates", "Pembaruan otomatis aktif",
                               Status.WARN, Severity.LOW,
                               "20auto-upgrades tidak ada",
                               "Pasang `unattended-upgrades` dan aktifkan pembaruan keamanan otomatis.",
                               category=CATEGORY))
        elif "1" in text.replace('"', ""):
            out.append(Finding("kernel.auto_updates", "Pembaruan otomatis aktif",
                               Status.PASS, Severity.INFO, "terkonfigurasi",
                               category=CATEGORY))
        else:
            out.append(Finding("kernel.auto_updates", "Pembaruan otomatis aktif",
                               Status.WARN, Severity.LOW, "nonaktif",
                               "Set kedua opsi ke 1 di /etc/apt/apt.conf.d/20auto-upgrades.",
                               category=CATEGORY))
        return out


class Auditing(Check):
    CODE = "kernel.audit_log"
    TITLE = "Pencatatan aktivitas memadai (auditd/journald)"
    CATEGORY = CATEGORY

    def run(self, ctx):
        out = []
        if which("auditctl"):
            code, res = run(["auditctl", "-s"])
            if code == 0:
                enabled = "enabled" in res and "enabled=1" in res.replace(" ", "")
                out.append(Finding("kernel.auditd", "auditd berjalan", 
                                   Status.PASS if enabled else Status.WARN,
                                   Severity.LOW if enabled else Severity.MEDIUM,
                                   res.splitlines()[0][:120] if res else "?",
                                   "" if enabled else "Aktifkan auditd untuk jejak audit kernel.",
                                   category=CATEGORY))
        else:
            out.append(Finding("kernel.auditd", "auditd terpasang", Status.WARN,
                               Severity.LOW, "auditd tidak terpasang",
                               "Pasang `auditd` bila butuh jejak audit (compliance).",
                               category=CATEGORY))

        jd = read("/etc/systemd/journald.conf") or ""
        persistent = any(ln.strip().lower().startswith("storage=persistent")
                         for ln in jd.splitlines())
        out.append(Finding("kernel.journald", "Log journald persisten (tidak hilang saat reboot)",
                           Status.PASS if persistent else Status.WARN,
                           Severity.LOW if persistent else Severity.MEDIUM,
                           "Storage=persistent" if persistent else "default (volatile)",
                           "" if persistent else
                           "Set `Storage=persistent` di /etc/systemd/journald.conf — "
                           "tanpa ini, jejak insiden hilang setelah reboot.",
                           category=CATEGORY))
        return out
