from osint.base_osint import OSINTService

class Shodan(OSINTService):
    def query(self, ip: str) -> dict:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
        result = self.handle_request(url)
        return result