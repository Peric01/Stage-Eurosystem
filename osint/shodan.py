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
        except requests.HTTPError as e:
            status_code = e.response.status_code if e.response else "unknown"
            reason = e.response.reason if e.response else str(e)
            logger.error(f"Shodan HTTPError for {ip}: {status_code} {reason}")
            return {}
        except Exception as e:
            logger.error(f"Shodan error for {ip}: {str(e)}")
            return {}
