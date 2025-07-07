import re
from parsers.base_parser import InterfaceLogParser
from typing import Any
import logging

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
        entries = []
        lines = raw_log.strip().splitlines()

        for line in lines:
            try:
                if re.search(r"\bwarning:\s*Cleanup\b", line, re.IGNORECASE):
                    continue  # Ignora le linee di warning di cleanup
                # Timestamp
                match_ts = re.match(r"\[(\d{8} \d{2}:\d{2}:\d{2})\]", line)
                timestamp = match_ts.group(1) if match_ts else None

                # Connessione accettata (connessione TCP)
                if "accepted connection from" in line:
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

                # Comando FTP
                if "ftp.py" in line and "processing line" in line:
                    match_cmd = re.search(r"processing line 'b'(.*?)'", line)
                    if match_cmd:
                        entries.append({
                            "type": "ftp_command",
                            "timestamp": timestamp,
                            "command": match_cmd.group(1),
                        })
                        continue

                # Incident report
                if "incident" in line and "incident" in line:
                    match_incident = re.search(r"incident [^:]+: ([\w\.\-]+)", line)
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
