from osint.base_osint import OSINTService
from osint.abuseipdb import AbuseIPDB
from osint.shodan import Shodan
from osint.virustotal import VirusTotal
from logger.log_manager import LogManager

logger = LogManager.get_instance().get_logger()

class OSINTServiceFactory:
    @staticmethod
    def get_service(service_name: str, api_key: str) -> OSINTService:
        if service_name == "abuseipdb":
            return AbuseIPDB(api_key)
        elif service_name == "shodan":
            return Shodan(api_key)
        elif service_name == "virustotal":
            return VirusTotal(api_key)
        else:
            logger.error(f"Unsupported service: {service_name}")
            return None