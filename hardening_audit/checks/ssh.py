"""Pemeriksaan konfigurasi SSH server (read-only)."""
from __future__ import annotations

from ..model import Finding, Severity, Status
from ..registry import Check
from ..util import sshd_effective, strip_quotes

CATEGORY = "ssh"


def _cfg() -> dict[str, str]:
    return sshd_effective()


class SshInstalled(Check):
    CODE = "ssh.installed"
    TITLE = "Konfigurasi sshd dapat dibaca"
    CATEGORY = CATEGORY

    def run(self, ctx):
        cfg = _cfg()
        if not cfg:
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "sshd_config tidak ditemukan", category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        f"{len(cfg)} opsi terbaca", category=CATEGORY)]


class SshRootLogin(Check):
    CODE = "ssh.permit_root_login"
    TITLE = "Login root via SSH dibatasi"
    CATEGORY = CATEGORY

    def run(self, ctx):
        val = strip_quotes(_cfg().get("permitrootlogin", "prohibit-password")).lower()
        bad = val in {"yes", "without-password", "prohibit-password", "forced-commands-only"}
        if val == "no":
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "PermitRootLogin no", category=CATEGORY)]
        if val == "yes":
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            "PermitRootLogin yes — root bisa login langsung",
                            "Set `PermitRootLogin no` (atau minimal `prohibit-password` + kunci saja), "
                            "lalu `systemctl reload ssh`.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                        f"PermitRootLogin {val}",
                        "Lebih aman `PermitRootLogin no` dan masuk lewat user biasa + sudo.",
                        category=CATEGORY)]


class SshPasswordAuth(Check):
    CODE = "ssh.password_auth"
    TITLE = "Autentikasi SSH memakai kunci, bukan password"
    CATEGORY = CATEGORY

    def run(self, ctx):
        val = strip_quotes(_cfg().get("passwordauthentication", "yes")).lower()
        if val == "no":
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "PasswordAuthentication no", category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.HIGH,
                        "PasswordAuthentication aktif — rawan brute force",
                        "Pasang kunci publik, uji login, baru set "
                        "`PasswordAuthentication no` + `systemctl reload ssh`.",
                        category=CATEGORY)]


class SshEmptyPasswords(Check):
    CODE = "ssh.empty_passwords"
    TITLE = "Password kosong tidak diizinkan di SSH"
    CATEGORY = CATEGORY

    def run(self, ctx):
        val = strip_quotes(_cfg().get("permitemptypasswords", "no")).lower()
        if val == "yes":
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.CRITICAL,
                            "PermitEmptyPasswords yes — akun tanpa password bisa masuk",
                            "Set `PermitEmptyPasswords no` segera.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "PermitEmptyPasswords no", category=CATEGORY)]


class SshMaxAuthTries(Check):
    CODE = "ssh.max_auth_tries"
    TITLE = "Batas percobaan autentikasi wajar (≤ 6)"
    CATEGORY = CATEGORY

    def run(self, ctx):
        raw = strip_quotes(_cfg().get("maxauthtries", ""))
        if not raw:
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "default (6)", category=CATEGORY)]
        try:
            n = int(raw)
        except ValueError:
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                            f"nilai tidak dikenal: {raw}", category=CATEGORY)]
        if n <= 6:
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            f"MaxAuthTries {n}", category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                        f"MaxAuthTries {n} — terlalu longgar",
                        "Turunkan ke 3–6.", category=CATEGORY)]


class SshX11Forwarding(Check):
    CODE = "ssh.x11_forwarding"
    TITLE = "X11 forwarding tidak aktif"
    CATEGORY = CATEGORY

    def run(self, ctx):
        val = strip_quotes(_cfg().get("x11forwarding", "no")).lower()
        if val == "yes":
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW,
                            "X11Forwarding yes", "Nonaktifkan bila tidak dipakai.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "X11Forwarding tidak aktif", category=CATEGORY)]


class SshAlive(Check):
    CODE = "ssh.alive_interval"
    TITLE = "Sesi SSH menggantung diputus otomatis"
    CATEGORY = CATEGORY

    def run(self, ctx):
        cfg = _cfg()
        interval = strip_quotes(cfg.get("clientaliveinterval", "0"))
        count = strip_quotes(cfg.get("clientalivecountmax", "3"))
        try:
            ok = int(interval) > 0 and int(count) <= 3
        except ValueError:
            ok = False
        detail = f"ClientAliveInterval {interval}, ClientAliveCountMax {count}"
        if ok:
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            detail, category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.LOW, detail,
                        "Set `ClientAliveInterval 300` dan `ClientAliveCountMax 0` "
                        "agar sesi idle otomatis ditutup.",
                        category=CATEGORY)]


class SshRootKeys(Check):
    CODE = "ssh.root_authorized_keys"
    TITLE = "Tidak ada kunci SSH menempel di akun root"
    CATEGORY = CATEGORY
    NEEDS_ROOT = True

    def run(self, ctx):
        if not ctx.get("is_root"):
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "butuh root untuk membaca /root/.ssh",
                            category=CATEGORY)]
        from pathlib import Path
        p = Path("/root/.ssh/authorized_keys")
        if not p.is_file():
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "/root/.ssh/authorized_keys tidak ada", category=CATEGORY)]
        keys = [ln for ln in p.read_text(errors="replace").splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
        if not keys:
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "file ada tapi kosong", category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                        f"{len(keys)} kunci bisa login sebagai root",
                        "Hapus kunci root dan masuk lewat user biasa + sudo.",
                        category=CATEGORY)]
