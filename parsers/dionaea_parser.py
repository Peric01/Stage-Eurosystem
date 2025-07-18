import re
from parsers.base_parser import InterfaceLogParser
from typing import Any
import logging
import datetime
from core.geomap_ip import GeomapIP

logger = logging.getLogger("LogSystem")

class DionaeaParser(InterfaceLogParser):
    """
    Parser per log testuali di Dionaea Honeypot.
    Riconosce eventi come:
    - accettazione connessioni
    - comandi FTP
    - credenziali
    """

    def parse(self, raw_log: str) -> dict[str, Any]:
        parsed_log: dict[str, Any] = {
            "event": "dionaea_event"
        }
        logger.debug(f"Parsing raw log: {raw_log}")
        try:
            # --- Parsing del timestamp ---
            raw_timestamp = re.search(r'\[(\d{2})(\d{2})(\d{4}) (\d{2}):(\d{2}):(\d{2})\]', raw_log)
            if not raw_timestamp:
                logger.warning("No valid timestamp found in log entry")
                return parsed_log

            timestamp = datetime.datetime(
                year=int(raw_timestamp.group(3)),
                month=int(raw_timestamp.group(2)),
                day=int(raw_timestamp.group(1)),
                hour=int(raw_timestamp.group(4)),
                minute=int(raw_timestamp.group(5)),
                second=int(raw_timestamp.group(6))
            )
            parsed_log["timestamp"] = timestamp.isoformat()

            # --- Ignora eventi noti da escludere ---
            if re.search(r'\] sip .+?-warning: Cleanup', raw_log):
                logger.debug("Ignoring SIP cleanup event")
                return parsed_log

            # --- Event name ---
            # event = re.search(r'\] (\w+) /', raw_log)
            # if event:
            #     parsed_log["event"] = event.group(1)

            # --- Messaggio log ---
            message = re.search(r'(?:debug|info|warning|critical|error):\s*(.*)', raw_log)
            if message:
                parsed_log["message"] = message.group(1)

            # --- Credenziali (solo se presenti) ---
            username = re.search(r'username:\s*\(string\)\s*(\S+)', raw_log)
            if username:
                parsed_log["username"] = username.group(1)

            password = re.search(r'password:\s*\(string\)\s*(\S+)', raw_log)
            if password:
                parsed_log["password"] = password.group(1)

            command = re.search(r'command:\s*\(string\)\s*(\S+)', raw_log)
            if command:
                parsed_log["command"] = command.group(1)

            # --- Connessione ---
            conn_match = re.search(
                r'connection from ([\d\.]+):(\d+) to ([\d\.]+):(\d+)', raw_log
            )
            if conn_match:
                parsed_log["src_ip"] = conn_match.group(1)
                parsed_log["src_port"] = conn_match.group(2)
                parsed_log["dst_ip"] = conn_match.group(3)
                parsed_log["dst_port"] = conn_match.group(4)

            # latitude, longitude = GeomapIP.fetch_location(parsed_log["src_ip"])
            # parsed_log["latitude"] = latitude
            # parsed_log["longitude"] = longitude

            # --- Attack ID ---
            attack_id = re.search(r'attackid\s+(\d+)', raw_log)
            if attack_id:
                parsed_log["attack_id"] = attack_id.group(1)

        except Exception as e:
            logger.error(f"Error during parsing log: {e}", exc_info=True)

        return parsed_log