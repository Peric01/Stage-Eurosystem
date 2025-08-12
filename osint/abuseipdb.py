from osint.base_osint import OSINTService  # Adjust the import path as needed
import requests
import logging

logger = logging.getLogger("LogSystem")

class AbuseIPDB(OSINTService):
    def query(self, ip: str) -> dict:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.abuseipdb_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()["data"]
        except Exception as e:
            logger.error(f"AbuseIPDB error for {ip}: {e}")
            return {}