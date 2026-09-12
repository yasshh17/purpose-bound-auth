"""Decision logging (allow/deny + reason), feeding the results table."""

import json
import time
from dataclasses import dataclass, field


@dataclass
class AuditLog:
    entries: list = field(default_factory=list)

    def record(
        self,
        *,
        task_id: str,
        agent_id: str,
        purpose: str | None,
        fields,
        tool: str | None,
        decision: bool,
        reason: str,
        latency_us: float | None = None,
    ) -> dict:
        entry = {
            "timestamp": time.time(),
            "task_id": task_id,
            "agent_id": agent_id,
            "purpose": purpose,
            "fields": sorted(fields),
            "tool": tool,
            "decision": "allow" if decision else "deny",
            "reason": reason,
            "latency_us": latency_us,
        }
        self.entries.append(entry)
        return entry

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(e) for e in self.entries)
