"""Pemeriksaan port yang mendengarkan & firewall."""
from __future__ import annotations

import re
from pathlib import Path

from ..model import Finding, Severity, Status
from ..registry import Check
from ..util import read, run

CATEGORY = "jaringan"

# port yang sebaiknya tidak terekspos ke seluruh jaringan
SENSITIVE = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 111: "rpcbind", 135: "MS RPC",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker API (tanpa TLS)",
    3306: "MySQL/MariaDB", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
LOCAL_ONLY = ("127.0.0.1", "::1", "[::1]", "localhost")


def _listeners() -> list[tuple[str, int, str]]:
    """[(alamat, port, proses)] dari `ss -tulpnH`."""
    code, out = run(["ss", "-tulpnH"])
    if code != 0 or not out:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[4]
        proc = parts[6] if len(parts) > 6 else ""
        m = re.match(r"^(.*):(\d+)$", local)
        if not m:
            continue
        addr, port = m.group(1), int(m.group(2))
        rows.append((addr.strip("[]"), port, proc))
    return rows


class ListeningPorts(Check):
    CODE = "net.listening_ports"
    TITLE = "Tidak ada port sensitif terbuka ke jaringan"
    CATEGORY = CATEGORY
    NEEDS_ROOT = True

    def run(self, ctx):
        rows = _listeners()
        if not rows:
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "tidak bisa membaca daftar socket (butuh root untuk nama proses)",
                            category=CATEGORY)]
        exposed = [(a, p, pr) for a, p, pr in rows
                   if p in SENSITIVE and a not in LOCAL_ONLY]
        summary = f"{len(rows)} port mendengarkan"
        if exposed:
            detail = "; ".join(f"{SENSITIVE[p]}:{p} di {a or '0.0.0.0'}" for a, p, _ in exposed[:6])
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            f"{summary}; sensitif terbuka → {detail}",
                            "Batasi bind ke 127.0.0.1 atau tutup di firewall. "
                            "Untuk database/cache, jangan pernah terekspos publik.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        f"{summary}, tidak ada port sensitif terekspos ke luar",
                        category=CATEGORY)]


class Firewall(Check):
    CODE = "net.firewall"
    TITLE = "Firewall aktif"
    CATEGORY = CATEGORY

    def run(self, ctx):
        # 1) UFW: bisa dibaca dari konfigurasi walau bukan root
        ufw_conf = read("/etc/ufw/ufw.conf") or ""
        if "ENABLED=yes" in ufw_conf:
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            "UFW aktif (ENABLED=yes)", category=CATEGORY)]

        if not ctx.get("is_root"):
            return [Finding(self.CODE, self.TITLE, Status.SKIP, Severity.INFO,
                            "butuh root untuk memeriksa iptables/nftables/ufw secara pasti",
                            category=CATEGORY)]

        # 2) nftables
        code, out = run(["nft", "-s", "list", "ruleset"])
        if code == 0 and out and "table" in out:
            return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                            f"nftables punya aturan ({out.count('chain')} chain)",
                            category=CATEGORY)]

        # 3) iptables
        code, out = run(["iptables", "-S"])
        if code == 0:
            rules = [ln for ln in out.splitlines()
                     if ln.startswith("-A") and "ACCEPT" in ln]
            total = [ln for ln in out.splitlines() if ln.startswith("-A")]
            if not total:
                return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                                "iptables ada tapi tanpa aturan (policy default terbuka)",
                                "Pasang aturan dasar (mis. `ufw enable`) atau nftables.",
                                category=CATEGORY)]
            return [Finding(self.CODE, self.TITLE, Status.WARN, Severity.MEDIUM,
                            f"iptables: {len(total)} aturan ({len(rules)} ACCEPT)",
                            "Pastikan policy default DROP/REJECT dan hanya port perlu yang dibuka.",
                            category=CATEGORY)]

        return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                        "tidak ada UFW/nftables/iptables yang terdeteksi",
                        "Aktifkan firewall: `ufw default deny incoming && ufw enable`.",
                        category=CATEGORY)]


class RiskyServices(Check):
    CODE = "net.legacy_services"
    TITLE = "Layanan usang (telnet/FTP/rlogin) tidak terpasang"
    CATEGORY = CATEGORY

    def run(self, ctx):
        found = []
        for name, label in (("/usr/sbin/in.telnetd", "telnetd"),
                            ("/usr/sbin/vsftpd", "vsftpd"),
                            ("/usr/sbin/in.rlogind", "rlogind"),
                            ("/usr/sbin/tftpd", "tftpd")):
            if Path(name).exists():
                found.append(label)
        if found:
            return [Finding(self.CODE, self.TITLE, Status.FAIL, Severity.HIGH,
                            f"terpasang: {', '.join(found)} — protokol tanpa enkripsi",
                            "Hapus paketnya; ganti dengan SSH/SFTP.",
                            category=CATEGORY)]
        return [Finding(self.CODE, self.TITLE, Status.PASS, Severity.INFO,
                        "tidak ada", category=CATEGORY)]
