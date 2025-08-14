from parsers.base_parser import InterfaceLogParser
import json
from typing import Any
import logging

logger = logging.getLogger("LogSystem")

class OSINTParser(InterfaceLogParser):
    '''
    Parser for OSINT data in JSON format.
    Returns all fields from the OSINT query, plus a cleaned summary of key services.
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

        # Copia completa (così pubblichi tutto ciò che è arrivato)
        result = dict(data)

        # Estratto pulito dei campi chiave
        summary = {}

        abuseipdb_data = data.get("abuseipdb") or data.get("AbuseIPDB") or {}
        if abuseipdb_data:
            summary["abuseipdb"] = {
                "abuseConfidenceScore": abuseipdb_data.get("abuseConfidenceScore"),
                "totalReports": abuseipdb_data.get("totalReports"),
            }

        shodan_data = data.get("shodan") or data.get("Shodan") or {}
        if shodan_data:
            summary["shodan"] = {
                "vulns": shodan_data.get("vulns", []),
                "port": shodan_data.get("port")
            }

        virustotal_data = data.get("virustotal") or data.get("VirusTotal") or {}
        if virustotal_data:
            summary["virustotal"] = {
                "last_analysis_stats": virustotal_data.get("last_analysis_stats", {}),
                "tags": virustotal_data.get("tags", [])
            }

        # Se abbiamo estratto qualcosa, aggiungilo sotto una chiave "summary"
        if summary:
            result["summary"] = summary
        else:
            logger.warning("OSINTParser: Nessun dato estratto per le chiavi note.")

        return result
