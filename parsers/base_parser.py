from abc import ABC, abstractmethod
from typing import Any

class InterfaceLogParser(ABC):
    @abstractmethod
    def parse(self, raw_log: str) -> dict[str, Any]:
        '''Fa il parsing di una string di log e restituisce un dizionario normalizzato'''
        pass