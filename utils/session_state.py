"""
Session state manager for checkpoint/resume support.

Stores incremental workflow checkpoints and final results under the
active session directory.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SessionState:
    """Manage checkpoint and resume metadata for a Perfodia session."""

    def __init__(self, session_dir: Path):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self.checkpoint_path = self.session_dir / "session_checkpoint.json"
        self.results_path = self.session_dir / "results.json"

        self._completed_phases: List[str] = []
        self._last_checkpoint: Dict[str, Any] = {}

    def has_checkpoint(self) -> bool:
        """Return True if a checkpoint exists and is readable JSON."""
        if not self.checkpoint_path.exists():
            return False
        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                json.load(f)
            return True
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Checkpoint exists but is unreadable: %s", exc)
            return False

    def load_checkpoint(self) -> Dict[str, Any]:
        """Load and return checkpoint data; returns empty dict on failure."""
        if not self.checkpoint_path.exists():
            logger.info("No checkpoint file found for session %s", self.session_dir)
            self._completed_phases = []
            self._last_checkpoint = {}
            return {}

        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            completed = data.get("_completed_phases", [])
            self._completed_phases = [p for p in completed if isinstance(p, str)]
            self._last_checkpoint = data
            logger.info(
                "Loaded checkpoint with %d completed phase(s)",
                len(self._completed_phases),
            )
            return data
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to load checkpoint: %s", exc)
            self._completed_phases = []
            self._last_checkpoint = {}
            return {}

    def save_checkpoint(self, results: Dict[str, Any], completed_phase: str) -> None:
        """
        Save checkpoint atomically.

        The checkpoint includes all serializable current results plus
        `_completed_phases` metadata used by resume logic.
        """
        completed = list(results.get("_completed_phases", []))
        if not completed and self.has_checkpoint():
            previous = self.load_checkpoint()
            completed = list(previous.get("_completed_phases", []))

        if completed_phase and completed_phase not in completed:
            completed.append(completed_phase)

        checkpoint_payload = dict(results)
        checkpoint_payload["_completed_phases"] = completed
        checkpoint_payload["_last_updated"] = datetime.utcnow().isoformat() + "Z"

        self._atomic_json_write(self.checkpoint_path, checkpoint_payload)
        self._completed_phases = completed
        self._last_checkpoint = checkpoint_payload
        logger.debug("Checkpoint saved: %s", completed_phase)

    def should_skip_phase(self, phase_name: str) -> bool:
        """Return True if `phase_name` is already completed in checkpoint."""
        return phase_name in self._completed_phases

    def get_resume_info(self) -> Optional[Dict[str, Any]]:
        """Return concise resume metadata or None if no checkpoint."""
        if not self.has_checkpoint():
            return None

        data = self.load_checkpoint()
        if not data:
            return None

        return {
            "session_id": data.get("session_id", self.session_dir.name),
            "targets": data.get("targets", []),
            "mode": data.get("mode"),
            "completed_phases": data.get("_completed_phases", []),
            "last_updated": data.get("_last_updated"),
        }

    def finalize(self, results: Dict[str, Any]) -> None:
        """
        Persist final results and remove checkpoint to mark successful completion.
        """
        payload = dict(results)
        payload["_finalized_at"] = datetime.utcnow().isoformat() + "Z"

        self._atomic_json_write(self.results_path, payload)

        if self.checkpoint_path.exists():
            try:
                self.checkpoint_path.unlink()
            except OSError as exc:
                logger.warning("Could not remove checkpoint file: %s", exc)

    @staticmethod
    def _ensure_parent(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass

    def _atomic_json_write(self, path: Path, data: Dict[str, Any]) -> None:
        self._ensure_parent(path)
        tmp = path.with_suffix(path.suffix + ".tmp")

        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
