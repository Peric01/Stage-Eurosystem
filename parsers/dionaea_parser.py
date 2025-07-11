import re
from parsers.base_parser import InterfaceLogParser
from typing import Any
import logging
import datetime

logger = logging.getLogger("LogSystem")

class DionaeaParser(InterfaceLogParser):
    """
    Parser per log testuali di Dionaea Honeypot.

    Esempi riconosciuti:
    - accettazione connessioni
    - comandi FTP
    - incident generici
    """

    def parse(self, raw_log: str) -> list[dict[str, Any]]:
        parsed_logs = []

        raw_timestamp = re.search(r'\[(\d{2})(\d{2})(\d{4}) (\d{2}):(\d{2}):(\d{2})\]', raw_log)
        if not raw_timestamp:
            logger.warning("No valid timestamp found in log entry")
        timestamp = datetime.datetime(
            year=int(raw_timestamp.group(3)),
            month=int(raw_timestamp.group(2)),
            day=int(raw_timestamp.group(1)),
            hour=int(raw_timestamp.group(4)),
            minute=int(raw_timestamp.group(5)),
            second=int(raw_timestamp.group(6))
        )
        parsed_logs.append({"timestamp": timestamp.isoformat()})
        sip_cleanup_event = re.search(
            r'\] sip .+?-warning: Cleanup', raw_log
        )
        if sip_cleanup_event:
            return
        event = re.search(r'\] (\w+) /', raw_log)
        if event:
            event_name = event.group(1)
            # Puoi aggiungere l'evento al dizionario dei log se necessario
            parsed_logs.append({"event_name": event_name})

        message = re.search(r'(?:debug|info|warning|critical|error):\s*(.*)', raw_log)
        if message:
            parsed_logs.append({"message": message.group(1)})

        username = re.search(r'username:\s*\(string\)\s*(\S+)', raw_log)
        if username:
            parsed_logs.append({"username": username.group(1)})

        password = re.search(r'password:\s*\(string\)\s*(\S+)', raw_log)
        if username:
            parsed_logs.append({"password": password.group(1)})
        
        command = re.search(r'command:\s*\(string\)\s*(\S+)', raw_log)
        if username:
            parsed_logs.append({"command": command.group(1)})

        conn_match = re.search(
            r'connection from ([\d\.]+):(\d+) to ([\d\.]+):(\d+)', raw_log
        )
        if conn_match:
            parsed_logs.append({
            "src_ip": conn_match.group(1),
            "src_port": conn_match.group(2),
            "dst_ip": conn_match.group(3),
            "dst_port": conn_match.group(4)
            })
        
        attack_id = re.search(r'attackid\s+(\d+)', raw_log)
        if attack_id:
            parsed_logs.append({"attack_id": attack_id.group(1)})
        return parsed_logs