from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class ProcessContext:
    pid: int
    name: str
    parent_pid: int
    parent_name: str
    command_line: str
    created_at: datetime = field(default_factory=datetime.now)
    events: List[dict] = field(default_factory=list)
    score: int = 0
    triggered_rules: List[dict] = field(default_factory=list)
    detected_at: Optional[datetime] = None

    def add_event(self, event: dict):
        self.events.append(event)

    def add_rule_hit(self, rule_name: str, weight: int, reason: str,
                     behavior: str = "", offensive_context: str = "", mitre: str = ""):
        existing = [r["rule"] for r in self.triggered_rules]
        if rule_name not in existing:
            self.score += weight
            self.triggered_rules.append({
                "rule": rule_name,
                "weight": weight,
                "reason": reason,
                "behavior": behavior,
                "offensive_context": offensive_context,
                "mitre": mitre
            })

            if self.score >= 30 and self.detected_at is None:
                self.detected_at = datetime.now()

    def classification(self) -> str:
        if self.score >= 90:
            return "CRITICAL"
        elif self.score >= 60:
            return "OFFENSIVE-LIKE"
        elif self.score >= 30:
            return "SUSPICIOUS"
        else:
            return "BENIGN"