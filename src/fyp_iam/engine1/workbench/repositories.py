"""Repository boundary. The in-memory store is for unit tests, not the API."""

from typing import Protocol

from fyp_iam.engine1.workbench.domain import WorkbenchSnapshot


class WorkbenchRepository(Protocol):
    """Save and reload one import. Implementations must be idempotent by content hash."""

    def save_import(self, snapshot: WorkbenchSnapshot) -> str:
        """Return ``created`` or ``unchanged``."""

    def get_import(self, pin_id: str) -> WorkbenchSnapshot | None:
        """Return the stored import, or None when the pin has not been saved."""
