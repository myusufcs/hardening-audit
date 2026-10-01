"""Pemeriksaan akun, sudo, dan kebijakan password."""
from __future__ import annotations

from pathlib import Path

from ..model import Finding, Severity, Status
from ..registry import Check
from ..util import read

CATEGORY = "akses"
NOLOGIN = {"nologin", "false", "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}


def _passwd_rows() -> list[list[str]]:
    text = read("/etc/passwd") or ""
    return [ln.split(":") for ln in text.splitlines() if ln.count(":") >= 6]


class UidZero(Check):
    CODE = "akses.uid0"
    TITLE = "Hanya root yang punya UID 0"
    CATEGORY = CATEGORY

    def run(self, ctx):
        others = [r[0] for r in _passwd_rows() if r[2] == "0" and r[0] != "root"]
        if others:
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.CRITICAL,
                            f"akun UID 0 selain root: {', '.join(others)}",
                            "Ubah UID akun tersebut atau hapus bila tidak dipakai — UID 0 = root.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "hanya root", category=CATEGORY)]


class EmptyPasswords(Check):
    CODE = "akses.empty_password"
    TITLE = "Tidak ada akun dengan password kosong"
    CATEGORY = CATEGORY
    NEEDS_ROOT = True

    def run(self, ctx):
        if not ctx.get("is_root"):
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "butuh root untuk membaca /etc/shadow", category=CATEGORY)]
        text = read("/etc/shadow")
        if text is None:
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "/etc/shadow tidak terbaca", category=CATEGORY)]
        hits = []
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                hits.append(parts[0])
        if hits:
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.CRITICAL,
                            f"akun tanpa password: {', '.join(hits[:8])}",
                            "Kunci akun (`passwd -l <user>`) atau set password kuat.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "semua akun punya password terisi", category=CATEGORY)]


class SudoNoPasswd(Check):
    CODE = "akses.sudo_nopasswd"
    TITLE = "Tidak ada aturan sudo NOPASSWD"
    CATEGORY = CATEGORY

    def run(self, ctx):
        files = [Path("/etc/sudoers")]
        d = Path("/etc/sudoers.d")
        if d.is_dir():
            files += [p for p in sorted(d.iterdir()) if p.is_file()]
        hits = []
        for f in files:
            text = read(f)
            if not text:
                continue
            for ln in text.splitlines():
                s = ln.strip()
                if s.startswith("#") or "NOPASSWD" not in s:
                    continue
                hits.append(f"{f}: {s[:60]}")
        if hits:
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                            f"{len(hits)} aturan NOPASSWD — {hits[0]}",
                            "Pastikan hanya untuk otomasi yang benar-benar perlu.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "tidak ditemukan", category=CATEGORY)]


class LoginShells(Check):
    CODE = "akses.shell_system_account"
    TITLE = "Akun sistem tidak punya shell login"
    CATEGORY = CATEGORY

    def run(self, ctx):
        bad = []
        for r in _passwd_rows():
            name, _, uid, _, _, _, shell = r[:7]
            if name == "root" or int(uid) >= 1000 or int(uid) < 1:
                continue
            if shell not in NOLOGIN and "nologin" not in shell and "false" not in shell:
                bad.append(f"{name}(uid {uid}, shell {shell})")
        if bad:
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                            f"{len(bad)} akun sistem punya shell: {', '.join(bad[:5])}",
                            "Set shell ke /usr/sbin/nologin bila tidak perlu login.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "bersih", category=CATEGORY)]


class PasswordPolicy(Check):
    CODE = "akses.password_policy"
    TITLE = "Kebijakan umur & panjang password diatur"
    CATEGORY = CATEGORY

    def run(self, ctx):
        text = read("/etc/login.defs") or ""
        vals = {}
        for ln in text.splitlines():
            s = ln.split("#", 1)[0].strip()
            if not s:
                continue
            parts = s.split()
            if len(parts) >= 2:
                vals[parts[0]] = parts[1]
        maxdays = vals.get("PASS_MAX_DAYS", "")
        minlen = vals.get("PASS_MIN_LEN", "")
        problems = []
        try:
            if int(maxdays) > 365 or int(maxdays) <= 0:
                problems.append(f"PASS_MAX_DAYS={maxdays}")
        except ValueError:
            problems.append(f"PASS_MAX_DAYS={maxdays or 'tidak diset'}")
        try:
            if int(minlen) < 8:
                problems.append(f"PASS_MIN_LEN={minlen}")
        except ValueError:
            problems.append(f"PASS_MIN_LEN={minlen or 'tidak diset'}")
        if problems:
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                            "; ".join(problems),
                            "Set PASS_MAX_DAYS=365 dan PASS_MIN_LEN=12 di /etc/login.defs.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        f"PASS_MAX_DAYS={maxdays}, PASS_MIN_LEN={minlen}",
                        category=CATEGORY)]
