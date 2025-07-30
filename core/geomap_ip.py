import geocoder
import ipaddress
from logger.log_manager import LogManager

logger = LogManager.get_instance().get_logger()

class GeomapIP:
    @staticmethod
    def fetch_location(IP: str) -> tuple[float, float] | None:
        try:
            if ipaddress.ip_address(IP).is_private:
                logger.info(f"Skipping geolocation for private IP: {IP}")
                return None
        except ValueError:
            logger.warning(f"Invalid IP format: {IP}")
            return None

        geo_ip = geocoder.ip(IP)
        if not geo_ip.ok or not geo_ip.latlng:
            logger.error(f"Failed to fetch geolocation for IP: {IP}")
            return None
        return geo_ip.latlng