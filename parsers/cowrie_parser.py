from parsers.base_parser import InterfaceLogParser
import json
from typing import Any
import logging

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
            return {
                "timestamp": log_data.get("timestamp"),
                "src_ip": log_data.get("src_ip"),
                #"src_port": log_data.get("src_port"),
                "dst_port": log_data.get("dst_port"),
                "event": log_data.get("eventid"),
                "message": log_data.get("message"),
                "username": log_data.get("username"),
                "password": log_data.get("password"),
                "command": log_data.get("command"),
                "session": log_data.get("session"),
                "protocol": log_data.get("protocol"),
                "raw": raw_log
            }
        except json.JSONDecodeError:
            logger.exception(f"Failed to parse log: {raw_log}")
            return {
                "error": "Failed to parse log",
                "raw": raw_log
            }