from osint.base_osint import OSINTService
import requests
import logging

logger = logging.getLogger("LogSystem")

class Shodan(OSINTService):
    def query(self, ip: str) -> dict:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Shodan error for {ip}: {e}")
            return {}