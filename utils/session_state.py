"""
Session State — checkpoint and resume capability for long-running engagements.

After each phase completes, the full result state is saved to a checkpoint
file.  If the session is interrupted, ``--resume --session <name>`` restores
the state and continues from the last completed phase.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

CHECKPOINT_FILE = "session_checkpoint.json"


class SessionState:
    """
    Manages session checkpoint files for resume capability.

    Usage:
        state = SessionState(session_dir)

        # Check if resuming
        if state.has_checkpoint():
            results = state.load_checkpoint()
            completed = state.get_completed_phases()

        # After each phase completes:
        state.save_checkpoint(results, completed_phase="scan")

        # At end of session:
        state.finalize(results)
    """

    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self.checkpoint_path = session_dir / CHECKPOINT_FILE
        self._state: Dict[str, Any] = {}

    def has_checkpoint(self) -> bool:
        """Check if a resumable checkpoint exists."""
        return self.checkpoint_path.exists()

    def load_checkpoint(self) -> Dict[str, Any]:
        """
        Load state from the checkpoint file.

        Returns:
            The full results dictionary as it was when the checkpoint was saved.

        Raises:
            FileNotFoundError if no checkpoint exists.
        """
        if not self.checkpoint_path.exists():
            raise FileNotFoundError(f"No checkpoint at {self.checkpoint_path}")

        try:
            with open(self.checkpoint_path, "r") as f:
                self._state = json.load(f)

            completed = self._state.get("_completed_phases", [])
            logger.info(
                f"[RESUME] Loaded checkpoint — completed phases: "
                f"{', '.join(completed) if completed else 'none'}"
            )
            logger.info(
                f"[RESUME] Checkpoint saved at: {self._state.get('_checkpoint_time', 'unknown')}"
            )

            return self._state

        except json.JSONDecodeError as e:
            logger.error(f"[RESUME] Corrupt checkpoint file: {e}")
            raise
        except Exception as e:
            logger.error(f"[RESUME] Failed to load checkpoint: {e}")
            raise

    def save_checkpoint(
        self,
        results: Dict[str, Any],
        completed_phase: str,
    ):
        """
        Save a checkpoint after a phase completes.

        Args:
            results:         The full results dictionary so far
            completed_phase: Name of the phase that just finished
        """
        # Track completed phases
        completed = results.get("_completed_phases", [])
        if completed_phase not in completed:
            completed.append(completed_phase)
        results["_completed_phases"] = completed
        results["_checkpoint_time"] = datetime.now().isoformat()
        results["_checkpoint_phase"] = completed_phase

        try:
            with open(self.checkpoint_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(
                f"[CHECKPOINT] Saved after '{completed_phase}' phase — "
                f"{len(completed)} phases complete"
            )
        except Exception as e:
            logger.error(f"[CHECKPOINT] Failed to save: {e}")

    def get_completed_phases(self) -> List[str]:
        """Return list of phases completed in the loaded checkpoint."""
        return self._state.get("_completed_phases", [])

    def should_skip_phase(self, phase_name: str) -> bool:
        """Check if a phase was already completed in a previous run."""
        return phase_name in self.get_completed_phases()

    def finalize(self, results: Dict[str, Any]):
        """
        Mark the session as complete and save final results.

        Renames the checkpoint to indicate completion.
        """
        results["_session_complete"] = True
        results["_finalized_at"] = datetime.now().isoformat()

        # Save final results.json
        results_path = self.session_dir / "results.json"
        try:
            with open(results_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"[SESSION] Final results saved to {results_path}")
        except Exception as e:
            logger.error(f"[SESSION] Failed to save final results: {e}")

        # Keep checkpoint for reference but add completion marker
        self.save_checkpoint(results, "_finalized")

    def get_resume_info(self) -> Optional[Dict[str, Any]]:
        """
        Get human-readable resume information for display.

        Returns:
            Dict with session details, or None if no checkpoint.
        """
        if not self.has_checkpoint():
            return None

        try:
            data = self.load_checkpoint()
            return {
                "session_id": data.get("session_id", "unknown"),
                "started": data.get("start_time", "unknown"),
                "checkpoint_time": data.get("_checkpoint_time", "unknown"),
                "completed_phases": data.get("_completed_phases", []),
                "targets": data.get("targets", []),
                "mode": data.get("mode", "unknown"),
            }
        except Exception:
            return None
