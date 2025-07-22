from parsers.base_parser import InterfaceLogParser
import json
from typing import Any
import logging
from core.geomap_ip import GeomapIP

logger = logging.getLogger("LogSystem")

class CowrieParser(InterfaceLogParser):
    '''
    Parser per log generati da Cowrie Honeypot

    Questo parser trasforma una stringa JSON in un dizionario standardizzato
    utile per l'analisi di eventi di attacco e attività sospette, estraendo i campi rilevanti
    '''

    def parse(self, raw_log: str) -> dict[str, Any]:
        try:
            log_data = json.loads(raw_log)
            latitude, longitude = GeomapIP.fetch_location(log_data.get("src_ip"))

            return {
                "timestamp": str(log_data.get("timestamp")),
                "src_ip": str(log_data.get("src_ip")),
                "src_port": str(log_data.get("src_port")),
                "latitude": str(latitude),
                "longitude": str(longitude),
                "dst_ip": str(log_data.get("dst_ip")),
                "dst_port": str(log_data.get("dst_port")),
                "event": str(log_data.get("eventid")),
                "message": str(log_data.get("message")),
                "username": str(log_data.get("username")),
                "password": str(log_data.get("password")),
                "command": str(log_data.get("command") or log_data.get("input")),
                "session": str(log_data.get("session")),
                "protocol": str(log_data.get("protocol")),
                "ssh_version": str(log_data.get("version")),
                "hassh": str(log_data.get("hassh")),
                "ttylog": str(log_data.get("ttylog")),
                "duration": str(log_data.get("duration")),
                "sensor": str(log_data.get("sensor")),
            }
        except json.JSONDecodeError:
            logger.error(f"Failed to parse log: {raw_log}")
            return []