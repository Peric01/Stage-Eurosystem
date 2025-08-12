from osint.base_osint import OSINTService  # Adjust the import path as needed

class AbuseIPDB(OSINTService):
    def query(self, ip: str) -> dict:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        result = self.handle_request(url, headers, params)
        return result.get("data", {})