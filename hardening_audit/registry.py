"""Registry pemeriksaan: auto-register + pemilihan."""
from __future__ import annotations

import importlib
import os
import pkgutil
from typing import Any

ALL_CHECKS: list[type] = []


class Check:
    """Kontrak satu pemeriksaan.

    CODE     : id unik (dipakai --only / --skip)
    TITLE    : judul singkat
    CATEGORY : pengelompokan di laporan
    NEEDS_ROOT: True kalau pemeriksaan hanya bermakna sebagai root
    """

    CODE = "?"
    TITLE = ""
    CATEGORY = "umum"
    NEEDS_ROOT = False

    def __init_subclass__(cls, **kw: Any) -> None:
        super().__init_subclass__(**kw)
        if getattr(cls, "CODE", "?") != "?":
            ALL_CHECKS.append(cls)

    def run(self, ctx: dict) -> list:
        raise NotImplementedError


def load_all() -> None:
    from . import checks as pkg
    for info in pkgutil.iter_modules(pkg.__path__):
        if info.name.startswith("_"):
            continue
        importlib.import_module(f"hardening_audit.checks.{info.name}")


def select(only: list[str] | None = None, skip: list[str] | None = None) -> list[type]:
    out = []
    for cls in ALL_CHECKS:
        if only and cls.CODE not in only and cls.CATEGORY not in only:
            continue
        if skip and (cls.CODE in skip or cls.CATEGORY in skip):
            continue
        out.append(cls)
    return sorted(out, key=lambda c: (c.CATEGORY, c.CODE))


def describe() -> list[tuple[str, str, bool]]:
    return [(c.CODE, c.TITLE, c.NEEDS_ROOT) for c in sorted(ALL_CHECKS, key=lambda c: c.CODE)]


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
