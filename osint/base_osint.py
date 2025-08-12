from abc import ABC, abstractmethod
import requests
from logger.log_manager import LogManager

logger = LogManager.get_instance().get_logger()

class OSINTService(ABC):
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    @abstractmethod
    def query(self, ip: str) -> dict:
        pass

    def handle_request(self, url: str, headers: dict = None, params: dict = None) -> dict:
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Request error: {e}")
            return {}
