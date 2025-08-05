from abc import ABC, abstractmethod
from typing import Dict, Any

class InterfaceDataPublisher(ABC):
    '''
    Interfaccia astratta per i publisher che inviano log strutturati
    a sistemi esterni.
    '''
    @abstractmethod
    def publish(self, log: Dict[str, Any]) -> None:
        '''Pubblica un log strutturato verso un canale specifico.'''
        pass # pragma: no cover