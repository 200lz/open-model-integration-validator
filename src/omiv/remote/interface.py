"""Provider-neutral repository metadata boundary."""

from __future__ import annotations

from typing import Protocol

from omiv.remote.models import RepositorySnapshot


class RemoteRepositoryAdapter(Protocol):
    provider: str

    def snapshot(
        self,
        *,
        repo_id: str,
        revision: str,
        path_prefix: str | None,
        patterns: list[str],
        strict_subtree: bool = True,
    ) -> RepositorySnapshot:
        """Resolve an immutable revision and enumerate selected metadata only."""
