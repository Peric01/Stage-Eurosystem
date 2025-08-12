from parsers.base_parser import InterfaceLogParser
import json
from typing import Any
import logging

logger = logging.getLogger("LogSystem")

class OSINTParser(InterfaceLogParser):
    '''
    Parser for OSINT data in JSON format.
    Extracts specific fields from abuseipdb, shodan, and virustotal responses.
    '''

    def parse(self, raw_log: str) -> dict[str, Any]:
        try:
            data = json.loads(raw_log)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return {}

        result = {}

        # abuseipdb fields
        abuseipdb_data = data.get("abuseipdb", {})
        if abuseipdb_data:
            result["abuseipdb"] = {
                "abuseConfidenceScore": abuseipdb_data.get("abuseConfidenceScore"),
                "totalReports": abuseipdb_data.get("totalReports"),
            }

        # shodan fields
        shodan_data = data.get("shodan", {})
        if shodan_data:
            result["shodan"] = {
                "vulns": shodan_data.get("vulns", []),  # list of CVEs
                "port": shodan_data.get("port")         # port number or list
            }

        # virustotal fields
        virustotal_data = data.get("virustotal", {})
        if virustotal_data:
            last_analysis_stats = virustotal_data.get("last_analysis_stats", {})
            tags = virustotal_data.get("tags", [])
            result["virustotal"] = {
                "last_analysis_stats": last_analysis_stats,
                "tags": tags
            }

        return result
