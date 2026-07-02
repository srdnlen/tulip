from abc import ABC, abstractmethod
from typing import Iterable

from .flagid import FlagId


class FlagIdProtocol(ABC):

    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint

    @abstractmethod
    def get_services(self) -> set[str]:
        pass

    @abstractmethod
    def get_flagstores(self) -> set[str]:
        pass

    @abstractmethod
    def get_service_flagstores_mappings(self) -> dict[str, list[str]]:
        pass

    @abstractmethod
    def destroy_cache(self) -> None:
        pass

    @abstractmethod
    def get_flagids(self, team_id: str) -> Iterable[FlagId]:
        pass
