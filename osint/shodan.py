from osint.base_osint import OSINTService
import requests
import logging
import re

logger = logging.getLogger("LogSystem")

class Shodan(OSINTService):
    def query(self, ip: str) -> dict:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            # Converte l'eccezione in stringa
            error_str = str(e)
            # Rimuove la parte key=QUALCOSA (anche se è in mezzo a un URL)
            clean_error_str = re.sub(r'key=[^&\s]+', 'key=****', error_str)
            logger.error(f"Shodan error for {ip}: {clean_error_str}")
            return {}
