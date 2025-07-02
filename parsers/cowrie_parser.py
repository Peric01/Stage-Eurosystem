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

        # Estrai username e password da pattern tipo:
        # - b'user' trying auth b'pass'
        # - login attempt [b'user'/b'pass'] failed
        login1 = re.search(r"b'([^']+)'\s+trying auth\s+b'([^']+)'", raw_log)
        login2 = re.search(r"login attempt\s+\[b'([^']*)'/b'([^']*)'\]", raw_log)

        if login1:
            parsed_log["username"] = login1.group(1)
            parsed_log["password"] = login1.group(2)
        elif login2:
            parsed_log["username"] = login2.group(1)
            parsed_log["password"] = login2.group(2)

        # Estrai il messaggio dopo l'ultima parentesi quadra
        msg_match = re.search(r'\]\s+(.*)$', raw_log)
        if msg_match:
            parsed_log["message"] = msg_match.group(1).strip()

        # Pulizia opzionale del campo "system", se esiste
        if "system" in parsed_log:
            parsed_log["system"] = parsed_log["system"].split('#')[0]

        logger.debug(f"[CowrieParser] Parsed log: {parsed_log}")
        return parsed_log