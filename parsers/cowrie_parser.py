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
            "raw": raw_log,
            "event": "generic",  # valore di default
        }

        try:
            # Timestamp (ISO 8601 con timezone)
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4})', raw_log)
            if timestamp_match:
                parsed_log["timestamp"] = timestamp_match.group(1)
            else:
                logger.warning(f"[CowrieParser] Timestamp non trovato in log: {raw_log}")

            # Classe log e IP sorgente
            class_match = re.search(r'\[([^\]]+)\]', raw_log)
            if class_match:
                full_class = class_match.group(1)

                # Classe (prima della virgola o #)
                class_name_clean = re.split(r'[,#]', full_class)[0]
                parsed_log["class_name"] = class_name_clean

                # src_ip (dopo virgola)
                ip_match = re.search(r',(\d{1,3}(?:\.\d{1,3}){3})', full_class)
                if ip_match:
                    parsed_log["src_ip"] = ip_match.group(1)

                # protocol/system (dopo cancelletto, se presente)
                system_match = re.search(r'#\s*([^]]+)\]', raw_log)
                if system_match:
                    parsed_log["protocol"] = system_match.group(1).strip()

            # Login
            login_match = re.search(r"b'([^']+)'\s+(?:authenticated with|trying auth|failed auth)\s+b'([^']+)'", raw_log)
            if login_match:
                parsed_log["username"] = login_match.group(1)
                parsed_log["password"] = login_match.group(2)
                parsed_log["event"] = "login_attempt"
            else:
                login_alt = re.search(r"login attempt\s+\[b'([^']+)'/b'([^']+)'\]", raw_log)
                if login_alt:
                    parsed_log["username"] = login_alt.group(1)
                    parsed_log["password"] = login_alt.group(2)
                    parsed_log["event"] = "login_attempt"

            # Comandi
            cmd_match = re.search(r'(?:CMD|Command found):\s*(.+?)(?:\\n|$)', raw_log)
            if cmd_match:
                parsed_log["command"] = cmd_match.group(1).strip()
                parsed_log["event"] = "command_input"

            # Sessione (es: session x opened)
            session_match = re.search(r'session (\d+)', raw_log)
            if session_match:
                parsed_log["session"] = session_match.group(1)

            # Messaggio generale
            msg_match = re.search(r'\]\s+(.*)$', raw_log)
            if msg_match:
                parsed_log["message"] = msg_match.group(1).strip()
            logger.debug(f"[CowrieParser] Parsed log: {parsed_log}")
            return parsed_log

        except Exception as e:
            logger.error(f"[CowrieParser] Errore durante il parsing: {e}", exc_info=True)
            parsed_log["event"] = "parse_error"
            return parsed_log
