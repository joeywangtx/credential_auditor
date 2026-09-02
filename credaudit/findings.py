from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]


@dataclass
class Finding:
    category: str
    severity: Severity
    title: str
    detail: str
    location: str
    recommendation: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "location": self.location,
            "recommendation": self.recommendation,
            "metadata": self.metadata,
        }
