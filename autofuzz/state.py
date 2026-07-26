"""Checkpoint state so a run can be resumed with --resume."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RunState:
    completed_targets: set[str] = field(default_factory=set)
    state_file: Path = Path("results/.autofuzz_state.json")

    @classmethod
    def load(cls, output_dir: Path) -> "RunState":
        state_file = output_dir / ".autofuzz_state.json"
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text(encoding="utf-8"))
                return cls(completed_targets=set(data.get("completed_targets", [])), state_file=state_file)
            except (json.JSONDecodeError, OSError):
                pass
        return cls(state_file=state_file)

    def mark_done(self, target: str) -> None:
        self.completed_targets.add(target)
        self._flush()

    def is_done(self, target: str) -> bool:
        return target in self.completed_targets

    def _flush(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(
            json.dumps({"completed_targets": sorted(self.completed_targets)}, indent=2),
            encoding="utf-8",
        )

    def clear(self) -> None:
        self.completed_targets.clear()
        if self.state_file.exists():
            self.state_file.unlink()
