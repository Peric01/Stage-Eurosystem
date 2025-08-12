from osint.base_osint import OSINTService

class VirusTotal(OSINTService):
    def query(self, ip: str) -> dict:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": self.api_key
        }
        result = self.handle_request(url, headers=headers)
        return result.get("data", {})