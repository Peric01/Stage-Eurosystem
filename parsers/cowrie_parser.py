from parsers.base_parser import InterfaceLogParser
import json
from typing import Any
import logging
import re

logger = logging.getLogger("LogSystem")

class CowrieParser(InterfaceLogParser):
    '''
    Parser per log generati da Cowrie Honeypot

    Questo parser trasforma una stringa JSON in un dizionario standardizzato
    utile per l'analisi di eventi di attacco e attività sospette, estraendo i campi rilevanti

    es. di Raw log: 
    2025-06-30T14:06:45+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'test' trying auth b'password'
    2025-06-30T14:06:45+0000 [HoneyPotSSHTransport,1,62.110.23.211] Could not read etc/userdb.txt, default database activated 
    '''
    def parse(self, raw_log: str) -> dict[str, Any]:
        try:
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4})', raw_log)
            if not timestamp_match:
                logger.error(f"Timestamp not found in log: {raw_log}")
                return {
                    "error": "Timestamp not found",
                    "raw": raw_log
                }
            class_name_match = re.search(r'\[(.*?)\]', raw_log)
            ip_match = re.search(r'\[.*?,\d+,(\d{1,3}(?:\.\d{1,3}){3})\]', raw_log)
            username_match = re.search(r"b'([^']+)'\s+trying auth", raw_log)
            password_match = re.search(r"auth\s+b'([^']+)'", raw_log)
            message_match = re.search(r"\[[^\]]+\]\s+(?!.*b'[^']+')(.+)", raw_log)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse log: {raw_log}")
            return {
                "error": "Failed to parse log",
                "raw": raw_log
            }