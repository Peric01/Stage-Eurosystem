from parsers.base_parser import InterfaceLogParser
import logging
import re
from typing import Any

logger = logging.getLogger("LogSystem")

class CowrieParser(InterfaceLogParser):
    '''
    Parser per log generati da Cowrie Honeypot.
    Estrae i campi principali e li normalizza.
    '''

    def parse(self, raw_log: str) -> dict[str, Any]:
        parsed_log: dict[str, Any] = {
            "raw": raw_log
        }

        # Estrai il timestamp (es. 2025-06-30T14:06:45+0000)
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4})', raw_log)
        if timestamp_match:
            parsed_log["timestamp"] = timestamp_match.group(1)
        else:
            logger.warning(f"[CowrieParser] Timestamp non trovato in log: {raw_log}")

        # Estrai il nome della classe o dell'istanza dentro le parentesi quadre
        class_match = re.search(r'\[([^\]]+)\]', raw_log)
        if class_match:
            class_name = class_match.group(1)
            parsed_log["class_name"] = class_name.split(',')[0]  # prendi solo la prima parte
            # Estrai anche l'IP se disponibile nella forma ,<IP>]
            ip_match = re.search(r'\[.*?,(\d{1,3}(?:\.\d{1,3}){3})\]', raw_log)
            if ip_match:
                parsed_log["ip"] = ip_match.group(1)

            # Pulizia opzionale del campo "system", se esiste
            system_match = re.search(r'#\s*([^]]+)\]', raw_log)
            if system_match:
                parsed_log["system"] = system_match.group(1).strip()

        login_match = re.search(r"b'([^']+)'\s+(?:authenticated with|trying auth)\s+b'([^']+)'", raw_log)
        if login_match:
            parsed_log["username"] = login_match.group(1)
            parsed_log["password"] = login_match.group(2)
        else:
            # fallback: login attempt [b'user'/b'pass']
            login_alt = re.search(r"login attempt\s+\[b'([^']+)'/b'([^']+)'\]", raw_log)
            if login_alt:
                parsed_log["username"] = login_alt.group(1)
                parsed_log["password"] = login_alt.group(2)

        # 4. COMANDI (CMD o Command found)
        cmd_match = re.search(r'(?:CMD|Command found):\s*(.+)', raw_log)
        if cmd_match:
            parsed_log["command"] = cmd_match.group(1).strip()

        # Estrai il messaggio dopo l'ultima parentesi quadra
        msg_match = re.search(r'\]\s+(.*)$', raw_log)
        if msg_match:
            parsed_log["message"] = msg_match.group(1).strip()

        

        logger.debug(f"Parsed log: {parsed_log}")
        return parsed_log