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
            logger.debug(f"test1")
            latitude, longitude = GeomapIP.fetch_location(log_data.get("src_ip"))
            logger.debug(f"test2")
            return {
                "timestamp": log_data.get("timestamp"),
                "src_ip": log_data.get("src_ip"),   # Indirizzo IP sorgente (chi effettua la connessione)
                "src_port": log_data.get("src_port"),
                "latitude": latitude,
                "longitude": longitude,
                "dst_ip": log_data.get("dst_ip"),   # Indirizzo IP destinazione (honeypot che riceve la connessione)
                "dst_port": log_data.get("dst_port"),
                "event": log_data.get("eventid"),
                "message": log_data.get("message"),
                "username": log_data.get("username"),
                "password": log_data.get("password"),
                "command": log_data.get("command") or log_data.get("input"),
                "session": log_data.get("session"),
                "protocol": log_data.get("protocol"),
                "ssh_version": log_data.get("version"),
                "hassh": log_data.get("hassh"),
                "ttylog": log_data.get("ttylog"),
                "duration": log_data.get("duration"),
                "sensor": log_data.get("sensor"),
            }
        except json.JSONDecodeError:
            logger.error(f"Failed to parse log: {raw_log}")
            return []