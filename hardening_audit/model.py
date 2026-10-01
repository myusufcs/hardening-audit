"""Model temuan & laporan."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    PASS = "PASS"          # sudah sesuai
    FAIL = "FAIL"          # tidak sesuai, perlu tindakan
    WARN = "WARN"          # perlu ditinjau
    SKIP = "SKIP"          # tidak bisa diperiksa (butuh root / tool tidak ada)

    @property
    def symbol(self) -> str:
        return {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️ ", "SKIP": "➖"}[self.value]


ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
         Severity.LOW: 3, Severity.INFO: 4}


@dataclass
class Finding:
    code: str
    title: str
    status: Status
    severity: Severity = Severity.INFO
    detail: str = ""
    remediation: str = ""
    category: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d


@dataclass
class Report:
    hostname: str
    platform: str
    started: str
    finished: str = ""
    is_root: bool = False
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # ---- ringkasan
    def count(self, status: Status) -> int:
        return sum(1 for f in self.findings if f.status is status)

    @property
    def applicable(self) -> int:
        return sum(1 for f in self.findings if f.status is not Status.SKIP)

    @property
    def score(self) -> int:
        """Persentase pemeriksaan yang LOLOS dari yang bisa diperiksa."""
        if not self.applicable:
            return 0
        return round(100 * self.count(Status.PASS) / self.applicable)

    def by_severity(self) -> list[Finding]:
        return sorted((f for f in self.findings if f.status in (Status.FAIL, Status.WARN)),
                      key=lambda f: (ORDER[f.severity], f.code))

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "platform": self.platform,
            "started": self.started,
            "finished": self.finished,
            "is_root": self.is_root,
            "score": self.score,
            "summary": {s.value: self.count(s) for s in Status},
            "findings": [f.as_dict() for f in self.findings],
            "errors": self.errors,
        }
