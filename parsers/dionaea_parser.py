from parsers.base_parser import InterfaceLogParser
import json
from typing import Any
import logging

logger = logging.getLogger("LogSystem")

class DionaeaParser(InterfaceLogParser):
    '''
    Parser per log generati da Dionaea Honeypot (formato JSON)
   
    Esempio:
    {"timestamp": "2025-06-30T13:50:23", "connection": {"protocol": "tcp", "sport": 22, "dport": 445, "remote_host": "192.168.0.1"}, "payload": "some hex data"}
    '''
    def parse(self, raw_log: str) -> dict[str, Any]:
        try:
            log_data = json.loads(raw_log)
            conn = log_data.get("connection", {})

            return {
                "timestamp": log_data.get("timestamp"),
                "src_ip": conn.get("remote_host"),
                "src_port": conn.get("sport"),
                "dst_port": conn.get("dport"),
                "protocol": conn.get("protocol"),
                "payload": log_data.get("payload"),
            }

        except json.JSONDecodeError:
            logger.error(f"Failed to parse Dionaea log: {raw_log}")
            return {
                "error": "Failed to parse Dionaea log",
                "raw": raw_log
            }