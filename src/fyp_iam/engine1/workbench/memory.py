"""In-memory workbench store used by unit tests."""

from fyp_iam.engine1.workbench.domain import WorkbenchSnapshot


class MemoryWorkbenchStore:
    """Test double. The API does not fall back to this store."""

    def __init__(self) -> None:
        self._by_hash: dict[str, WorkbenchSnapshot] = {}
        self._by_pin: dict[str, str] = {}

    def save_import(self, snapshot: WorkbenchSnapshot) -> str:
        if snapshot.content_hash in self._by_hash:
            return "unchanged"
        self._by_hash[snapshot.content_hash] = snapshot
        self._by_pin[snapshot.pin_id] = snapshot.content_hash
        return "created"

    def get_import(self, pin_id: str) -> WorkbenchSnapshot | None:
        content_hash = self._by_pin.get(pin_id)
        if content_hash is None:
            return None
        return self._by_hash[content_hash]
