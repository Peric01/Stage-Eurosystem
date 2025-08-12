from osint.base_osint import OSINTService
import requests
import logging
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger("LogSystem")

class Shodan(OSINTService):
    def query(self, ip: str) -> dict:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            # Maschera la chiave API rimuovendo la query string dal URL
            parsed_url = urlparse(url)
            safe_url = urlunparse(parsed_url._replace(query=""))
            logger.error(f"Shodan error for {ip}: for url: {safe_url}")
            return {}
