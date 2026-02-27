from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from agentsafe.policy.evaluate import Decision


class PolicyBackend(ABC):
    @abstractmethod
    def evaluate_run(self, cmd: list[str], workspace_root: Path) -> Decision:
        raise NotImplementedError

    @abstractmethod
    def evaluate_path(self, candidate: str, workspace_root: Path) -> Decision:
        raise NotImplementedError

    @abstractmethod
    def evaluate_fetch(self, url: str) -> Decision:
        raise NotImplementedError

    @abstractmethod
    def env_allowlist(self) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def network_mode(self) -> str:
        raise NotImplementedError
