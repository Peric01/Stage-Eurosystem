import geocoder
from logger.log_manager import LogManager

logger = LogManager.get_instance().get_logger()

class GeomapIP:
    """Class to handle IP geolocation mapping."""

    def fetch_location(IP: str):
        geo_ip = geocoder.ip(IP)
        if not geo_ip.ok:
            logger.error(f"Failed to fetch geolocation for IP: {IP}")
            return None
        return geo_ip.latlng

    