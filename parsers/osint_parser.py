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

    def parse(self, raw_log: Any) -> dict[str, Any]:
        # Decodifica robusta
        try:
            if isinstance(raw_log, dict):
                data = raw_log
            else:
                data = json.loads(raw_log)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"JSON decode error in OSINTParser: {e}")
            return {}

        logger.debug(f"OSINTParser received data: {data}")

        result = {}

        # --- abuseipdb ---
        abuseipdb_data = data.get("abuseipdb") or data.get("AbuseIPDB") or {}
        if abuseipdb_data:
            result["abuseipdb"] = {
                "abuseConfidenceScore": abuseipdb_data.get("abuseConfidenceScore"),
                "totalReports": abuseipdb_data.get("totalReports"),
            }

        # --- shodan ---
        shodan_data = data.get("shodan") or data.get("Shodan") or {}
        if shodan_data:
            result["shodan"] = {
                "vulns": shodan_data.get("vulns", []),
                "port": shodan_data.get("port")
            }

        # --- virustotal ---
        virustotal_data = data.get("virustotal") or data.get("VirusTotal") or {}
        if virustotal_data:
            result["virustotal"] = {
                "last_analysis_stats": virustotal_data.get("last_analysis_stats", {}),
                "tags": virustotal_data.get("tags", [])
            }

        # Se non abbiamo trovato niente, logghiamo per debug
        if not result:
            logger.warning(f"OSINTParser: Nessun dato estratto da {data}")

        return result
