"""Utilitas: baca file, jalankan perintah, parse konfigurasi."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def read(path: str | Path, limit: int = 400_000) -> str | None:
    try:
        return Path(path).read_text(errors="replace")[:limit]
    except Exception:                    # noqa: BLE001
        return None


def which(name: str) -> str | None:
    return shutil.which(name)


def run(args: list[str], timeout: int = 15) -> tuple[int, str]:
    """Jalankan perintah; kembalikan (exit code, stdout+stderr)."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, "perintah tidak ditemukan"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as exc:             # noqa: BLE001
        return 1, str(exc)


def sysctl(name: str) -> str | None:
    p = Path("/proc/sys") / name.replace(".", "/")
    val = read(p, 200)
    return val.strip() if val is not None else None


def sshd_effective(path: str | Path = "/etc/ssh/sshd_config",
                   include_dir: str | Path | None = "/etc/ssh/sshd_config.d") -> dict[str, str]:
    """Gabungkan sshd_config + sshd_config.d/*.conf. Opsi pertama yang muncul menang
    (perilaku sshd). Mengembalikan {opsi: nilai} dalam huruf kecil."""
    files: list[Path] = []
    main = Path(path)
    if main.is_file():
        files.append(main)
    if include_dir:
        inc = Path(include_dir)
        if inc.is_dir():
            files += sorted(inc.glob("*.conf"))

    out: dict[str, str] = {}
    for f in files:
        text = read(f)
        if not text:
            continue
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or " " not in line and "\t" not in line:
                continue
            key, _, value = line.partition(" ")
            if not value:
                key, _, value = line.partition("\t")
            out.setdefault(key.strip().lower(), value.strip())
    return out


def strip_quotes(value: str) -> str:
    return value.strip().strip('"').strip("'")
