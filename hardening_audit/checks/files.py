"""Pemeriksaan izin file & penjadwalan."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from ..model import Finding, Severity, Status
from ..registry import Check

CATEGORY = "berkas"

# SUID/SGID yang wajar ada di distro umum (dicocokkan sebagai awalan nama file)
SUID_ALLOW = {
    "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount", "umount",
    "fusermount", "fusermount3", "ping", "traceroute6.iputils", "mtr-packet",
    "suexec", "pkexec", "polkit-agent-helper-1", "dbus-daemon-launch-helper",
    "unix_chkpwd", "chage", "expiry", "ssh-keysign", "ssh-agent", "Xorg",
    "snap-confine", "crontab", "newuidmap", "newgidmap", "ntfs-3g", "at", "sg",
    "mount.nfs", "mount.cifs", "vmware-user-suid-wrapper", "Xorg.wrap",
    "chrome-sandbox", "bwrap", "gst-ptp-helper", "policykit-1", "pppd",
    "pam_extrausers_chkpwd", "pam_timestamp_check", "unix_chkpwd",
}

# world-writable yang memang bawaan distro (dikelola sistem)
WW_ALLOW = {
    "/etc/os-release", "/etc/lsb-release", "/etc/mtab", "/etc/resolv.conf",
    "/etc/ld.so.cache", "/etc/gai.conf", "/etc/rmt", "/etc/localtime",
}


def _walk_perms(root: Path, want_suid: bool = False, limit: int = 4000):
    hits = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        for name in filenames:
            full = Path(dirpath) / name
            try:
                if full.is_symlink():          # symlink selalu 777 di lstat
                    continue
                st = full.lstat()
            except OSError:
                continue
            if want_suid:
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    hits.append(full)
            elif st.st_mode & stat.S_IWOTH:
                hits.append(full)
            if len(hits) >= limit:
                return hits
    return hits


class WorldWritable(Check):
    CODE = "berkas.world_writable"
    TITLE = "Tidak ada file world-writable di /etc"
    CATEGORY = CATEGORY

    def run(self, ctx):
        hits = [h for h in _walk_perms(Path("/etc"), want_suid=False, limit=200)
                if str(h) not in WW_ALLOW]
        if hits:
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            f"{len(hits)} file bisa diubah semua user "
                            f"(contoh: {', '.join(str(h) for h in hits[:4])})",
                            "Cabut bit write untuk others: `chmod o-w <file>`. "
                            "File konfigurasi sistem tidak boleh world-writable.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "tidak ditemukan (default distro dikecualikan)", category=CATEGORY)]


class SuidBinaries(Check):
    CODE = "berkas.suid"
    TITLE = "Binary SUID/SGID wajar (tidak ada yang mencurigakan)"
    CATEGORY = CATEGORY

    def run(self, ctx):
        hits = []
        for base in ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"):
            p = Path(base)
            if p.is_dir():
                hits += _walk_perms(p, want_suid=True)
        unusual = [h for h in hits
                   if not any(h.name.lower().startswith(a.lower()) for a in SUID_ALLOW)]
        if unusual:
            listing = ", ".join(str(h) for h in unusual[:6])
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                            f"{len(hits)} binary SUID/SGID, {len(unusual)} belum lazim: {listing}",
                            "Tinjau satu per satu; cabut bit SUID bila tidak perlu "
                            "(`chmod u-s <file>`).",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        f"{len(hits)} binary SUID/SGID, semuanya lazim", category=CATEGORY)]


class HomePermissions(Check):
    CODE = "berkas.home_perms"
    TITLE = "Direktori home tidak bisa dibaca sembarang user"
    CATEGORY = CATEGORY

    def run(self, ctx):
        base = Path("/home")
        if not base.is_dir():
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "/home tidak ada", category=CATEGORY)]
        bad = []
        for d in base.iterdir():
            if not d.is_dir():
                continue
            try:
                mode = d.stat().st_mode & 0o777
            except OSError:
                continue
            if mode & 0o007:               # hanya bit "others" yang jadi masalah
                bad.append(f"{d.name} ({oct(mode)[2:]})")
        if bad:
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                            f"terbuka untuk user lain: {', '.join(bad[:6])}",
                            "Set `chmod 750 ~` (atau 700) supaya data pribadi tidak terbaca user lain.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "semua home sudah ketat", category=CATEGORY)]


class CronPermissions(Check):
    CODE = "berkas.cron"
    TITLE = "Berkas cron tidak bisa diubah user biasa"
    CATEGORY = CATEGORY

    def run(self, ctx):
        targets = [Path("/etc/crontab"), Path("/etc/anacrontab")]
        for d in (Path("/etc/cron.d"), Path("/etc/cron.hourly"), Path("/etc/cron.daily"),
                  Path("/etc/cron.weekly"), Path("/etc/cron.monthly"), Path("/var/spool/cron")):
            if d.is_dir():
                targets += [p for p in d.rglob("*") if p.is_file()]
        bad = []
        for f in targets:
            try:
                mode = f.stat().st_mode & 0o777
            except OSError:
                continue
            if mode & 0o022:
                bad.append(f"{f} ({oct(mode)[2:]})")
        if bad:
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            f"{len(bad)} berkas cron bisa diubah non-root: {bad[0]}",
                            "Set `chmod 644` untuk berkas dan `chmod 700` untuk direktorinya.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        f"{len(targets)} berkas diperiksa", category=CATEGORY)]
