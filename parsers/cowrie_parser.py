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

        # Estrai il timestamp
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4})', raw_log)
        if timestamp_match:
            parsed_log["timestamp"] = timestamp_match.group(1)
        else:
            logger.warning(f"[CowrieParser] Timestamp non trovato in log: {raw_log}")

        # Estrai classe e IP tra parentesi quadre
        class_match = re.search(r'\[([^\]]+)\]', raw_log)
        if class_match:
            full_class = class_match.group(1)
            parsed_log["class_name"] = full_class.split(',')[0]  # es. HoneyPotSSHTransport
            # Estrai IP se presente dopo una virgola
            ip_match = re.search(r',(\d{1,3}(?:\.\d{1,3}){3})', full_class)
            if ip_match:
                parsed_log["ip"] = ip_match.group(1)

        # Estrai username/password da varie forme:
        login_match_1 = re.search(r"[b']?([a-zA-Z0-9_\-@.]+)[']?\s+trying auth\s+[b']?([a-zA-Z0-9_\-@.]+)[']?", raw_log)
        login_match_2 = re.search(r"login attempt\s+\[b'([^']*)'/b'([^']*)'\]", raw_log)

        if login_match_1:
            parsed_log["username"] = login_match_1.group(1)
            parsed_log["password"] = login_match_1.group(2)
        elif login_match_2:
            parsed_log["username"] = login_match_2.group(1)
            parsed_log["password"] = login_match_2.group(2)

        # Estrai il messaggio dopo l'ultima parentesi quadra
        msg_match = re.search(r'\]\s+(.*)$', raw_log)
        if msg_match:
            parsed_log["message"] = msg_match.group(1).strip()

        # Se esiste campo 'system' (es. in JSON), puliscilo dal cancelletto
        if 'system' in parsed_log:
            parsed_log['system'] = parsed_log['system'].split('#')[0]

        logger.debug(f"[CowrieParser] Parsed log: {parsed_log}")
        return parsed_log
