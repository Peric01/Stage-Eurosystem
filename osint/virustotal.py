from osint.base_osint import OSINTService
import requests
import logging

logger = logging.getLogger("LogSystem")

class VirusTotal(OSINTService):
    def query(self, ip: str) -> dict:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": self.virustotal_key
        }
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()["data"]
        except Exception as e:
            logger.error(f"VirusTotal error for {ip}: {e}")
            return {}