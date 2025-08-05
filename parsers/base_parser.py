from abc import ABC, abstractmethod
from typing import Any

class InterfaceLogParser(ABC):
    '''
    Interfaccia astratta per i parser di log.
    '''
    @abstractmethod
    def parse(self, raw_log: str) -> dict[str, Any]:
        '''Fa il parsing di una string di log e restituisce un dizionario normalizzato'''
        pass # pragma: no cover