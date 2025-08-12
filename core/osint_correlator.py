import requests
from logger.log_manager import LogManager

logger = LogManager.get_instance().get_logger()

class OSINTCorrelator:
    def __init__(self, abuseipdb_key: str, shodan_key: str, virustotal_key: str):
        self.abuseipdb_key = abuseipdb_key
        self.shodan_key = shodan_key
        self.virustotal_key = virustotal_key

    def query_abuseipdb(self, ip: str) -> dict:
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

    def query_shodan(self, ip: str) -> dict:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Shodan error for {ip}: {e}")
            return {}

    def query_virustotal(self, ip: str) -> dict:
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
