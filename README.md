# hardening-audit

**Audit baseline keamanan server** — satu perintah, temuan berprioritas, plus langkah perbaikannya.
**Read-only**: tidak pernah mengubah konfigurasi sistem.

[![CI](https://github.com/myusufcs/hardening-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/myusufcs/hardening-audit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Zero deps](https://img.shields.io/badge/dependencies-none-success)
![License](https://img.shields.io/badge/license-MIT-green)
![Checks](https://img.shields.io/badge/checks-23-informational)

---

## Kenapa ini ada

Setelah server dipasang, biasanya pertanyaannya: *"sebenarnya sudah aman belum?"*
Menjawabnya manual (buka sshd_config, cek sysctl satu-satu, lihat file permission, cek firewall)
makan waktu dan gampang kelewat. `hardening-audit` melakukan pemeriksaan itu secara konsisten,
memberi **skor**, dan menyusun temuan **urut prioritas** supaya bisa langsung ditindak.

## Keluaran contoh

```
$ python3 -m hardening_audit
========================================================================
  LAPORAN HARDENING — server-web
========================================================================
platform   : Linux-6.8.0-45-generic-x86_64-with-glibc2.39
waktu      : 2026-10-01T17:20:11 → 2026-10-01T17:20:13
sebagai    : root
skor       : 61%  (20 lolos / 33 diperiksa, 3 dilewati)

  ✅ PASS  20   ❌ FAIL   3   ⚠️  WARN  10   ➖ SKIP   3

TEMUAN YANG PERLU DITINDAK (urut prioritas)
------------------------------------------------------------------------
⚠️  [HIGH] ssh.password_auth — Autentikasi SSH memakai kunci, bukan password
    kondisi : PasswordAuthentication aktif — rawan brute force
    perbaikan: Pasang kunci publik, uji login, baru set
               `PasswordAuthentication no` + `systemctl reload ssh`

⚠️  [MEDIUM] kernel.journald — Log journald persisten (tidak hilang saat reboot)
    kondisi : default (volatile)
    perbaikan: Set `Storage=persistent` di /etc/systemd/journald.conf
...
```

Tersedia tiga format: **teks** (terminal), **Markdown**, dan **JSON**.

## Instalasi & pemakaian

Tanpa dependensi Python — cukup standard library 3.10+.

```bash
git clone https://github.com/myusufcs/hardening-audit
cd hardening-audit

python3 -m hardening_audit                              # audit lengkap
python3 -m hardening_audit --out ~/laporan --format md,json
python3 -m hardening_audit --only ssh,akses              # kategori tertentu
python3 -m hardening_audit --skip kernel.updates
python3 -m hardening_audit --list                        # daftar 23 pemeriksaan
sudo python3 -m hardening_audit                          # sebagai root = lebih lengkap
```

Sebagian pemeriksaan (kunci root, `/etc/shadow`, firewall, nama proses socket) hanya bermakna
sebagai **root**; yang lain otomatis berstatus `SKIP` dengan alasannya — bukan dianggap lolos.

## Pemeriksaan (23)

| Kategori | Kode | Yang diperiksa |
|---|---|---|
| **ssh** | `ssh.permit_root_login` | Login root via SSH dibatasi |
| | `ssh.password_auth` | Wajib kunci, bukan password |
| | `ssh.empty_passwords` | Password kosong ditolak |
| | `ssh.max_auth_tries` | Batas percobaan ≤ 6 |
| | `ssh.x11_forwarding` | X11 forwarding nonaktif |
| | `ssh.alive_interval` | Sesi menggantung diputus otomatis |
| | `ssh.root_authorized_keys` | Tidak ada kunci menempel di root *(root)* |
| **akses** | `akses.uid0` | Hanya root punya UID 0 |
| | `akses.empty_password` | Tidak ada akun tanpa password *(root)* |
| | `akses.sudo_nopasswd` | Tidak ada aturan sudo NOPASSWD |
| | `akses.shell_system_account` | Akun sistem tanpa shell login |
| | `akses.password_policy` | PASS_MAX_DAYS / PASS_MIN_LEN wajar |
| **jaringan** | `net.listening_ports` | Port sensitif (DB/Redis/Mongo/Docker) tidak terekspos |
| | `net.firewall` | UFW / nftables / iptables aktif |
| | `net.legacy_services` | Telnet/FTP/tftp tidak terpasang |
| **berkas** | `berkas.world_writable` | Tidak ada file world-writable di `/etc` |
| | `berkas.suid` | Binary SUID/SGID tidak ada yang mencurigakan |
| | `berkas.home_perms` | Home tidak bisa diakses user lain |
| | `berkas.cron` | Berkas cron hanya bisa diubah root |
| **kernel** | `kernel.sysctl` | 11 parameter kernel diperketat |
| | `kernel.updates` | Paket menunggu + pembaruan otomatis |
| | `kernel.audit_log` | auditd + journald persisten |

## Dipakai di CI

```yaml
- name: Audit hardening
  run: |
    python3 -m hardening_audit --out reports --format md,json \
      --fail-under 70 --fail-on-critical
```

`--fail-under N` membuat job gagal bila skor turun di bawah N — berguna sebagai pengaman
regresi konfigurasi. `--fail-on-critical` menggagalkan build hanya bila ada temuan CRITICAL.

Contoh timer systemd agar laporan dibuat rutin:

```ini
# ~/.config/systemd/user/hardening-audit.timer
[Timer]
OnCalendar=weekly
Persistent=true
```

## Desain

```
hardening_audit/
  cli.py         # argparse: --only/--skip/--format/--out/--fail-under/--list
  registry.py    # auto-register pemeriksaan; pemilihan berdasarkan kode atau kategori
  model.py       # Finding/Severity/Status + Report (skor, prioritas)
  report.py      # render teks / Markdown / JSON
  util.py        # baca file, jalankan perintah, parse sshd_config (+include dir)
  checks/        # ssh.py · access.py · network.py · files.py · kernel.py
```

Menambah pemeriksaan baru = buat kelas turunan `registry.Check` dan isi `run()` —
otomatis ikut terdaftar, tanpa menyentuh core.

```python
from ..model import Finding, Severity, Status
from ..registry import Check

class Uptime(Check):
    CODE = "kernel.uptime"
    TITLE = "Server tidak baru reboot"
    CATEGORY = "kernel"

    def run(self, ctx):
        from ..util import read
        secs = float((read("/proc/uptime") or "0").split()[0])
        ok = secs > 3600
        return [Finding(self.CODE, self.TITLE,
                        Status.PASS if ok else Status.WARN, Severity.LOW,
                        f"uptime {secs/3600:.1f} jam", category=self.CATEGORY)]
```

## Batasan yang jujur

- Ini **baseline**, bukan pengganti audit menyeluruh atau pemindai kerentanan
  (untuk CVE paket: `lynis`, `debsecan`, `trivy`).
- Nilai "wajar" mengikuti praktik umum (CIS/Debian/Ubuntu). Lingkungan khusus bisa punya
  kebutuhan berbeda — perlakukan tiap temuan sebagai **bahan pertimbangan**, bukan vonis.
- Beberapa pemeriksaan bergantung pada asumsi distro (path, nama layanan). Di distro lain
  statusnya akan `SKIP`, bukan salah lapor.
- Tool ini **tidak otomatis memperbaiki** apa pun. Sengaja — perubahan konfigurasi keamanan
  sebaiknya diputuskan manusia.

## Uji

```bash
python3 -m unittest discover -s tests -v     # 14 test
```

Termasuk uji end-to-end yang menjalankan **seluruh 23 pemeriksaan** di mesin apa pun dan
memastikan tidak ada satu pun yang melempar exception.

## Lisensi

MIT — lihat [LICENSE](LICENSE). Copyright (c) 2026 M Yusuf Chairul Saleh.
