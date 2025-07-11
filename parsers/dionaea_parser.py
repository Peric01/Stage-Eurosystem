import re
from parsers.base_parser import InterfaceLogParser
from typing import Any
import logging

logger = logging.getLogger("LogSystem")

class DionaeaParser(InterfaceLogParser):
    """
    Parser per log testuali di Dionaea Honeypot.

    Supporta:
    - Connessioni TCP accettate
    - Comandi FTP
    - Incident segnalati
    """

    def parse(self, raw_log: str) -> list[dict[str, Any]]:
        entries = []
        lines = raw_log.strip().splitlines()

        for line in lines:
            try:
                # Timestamp nel formato [DDMMYYYY HH:MM:SS]
                match_ts = re.match(r"\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\]", line)
                timestamp = None
                if match_ts:
                    day, month, year, time = match_ts.groups()
                    timestamp = f"{year}-{month}-{day} {time}"

                # Ignora cleanup
                if "warning: Cleanup" in line:
                    continue

                # Connessione accettata
                match_conn = re.search(
                    r"accepted connection from ([\d.]+):(\d+) to ([\d.]+):(\d+)", line)
                if match_conn:
                    entries.append({
                        "type": "connection",
                        "timestamp": timestamp,
                        "src_ip": match_conn.group(1),
                        "src_port": int(match_conn.group(2)),
                        "dst_ip": match_conn.group(3),
                        "dst_port": int(match_conn.group(4)),
                    })
                    continue

                # Comando FTP: 'processing line 'b'USER anonymous''
                match_ftp = re.search(r"processing line 'b'(.*?)''", line)
                if match_ftp:
                    entries.append({
                        "type": "ftp_command",
                        "timestamp": timestamp,
                        "command": match_ftp.group(1),
                    })
                    continue

                # Incident: incident ... dionaea.connection.tcp.accept
                match_incident = re.search(r"incident [^ ]+ ([\w\.\-]+)", line)
                if match_incident:
                    entries.append({
                        "type": "incident",
                        "timestamp": timestamp,
                        "incident_type": match_incident.group(1),
                    })
                    continue

            except Exception as e:
                logger.warning(f"Parsing error on line: {line} | Error: {str(e)}")
                continue

        if not entries:
            logger.warning("No known Dionaea patterns found in log.")
            return [{"warning": "No parsable Dionaea entries found", "raw": raw_log}]

        return entries