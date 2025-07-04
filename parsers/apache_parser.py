from parsers.base_parser import InterfaceLogParser
from typing import Any
import re
import logging

logger = logging.getLogger("LogSystem")

class ApacheParser(InterfaceLogParser):
    '''
    Parser per log Apache HTTPD (anche da container) in formato variabile.

    Esempi:
    93.41.255.167 - - [04/Jul/2025:07:12:37 +0000] "GET / HTTP/1.1" 200 269
    93.41.255.167 - - [04/Jul/2025:07:13:46 +0000] "-" 408 -
    93.41.255.167 - - [03/Jul/2025:09:12:22 +0000] "SSH-2.0-OpenSSH_for_Windows_9.5" 400 226
    '''
    def parse(self, raw_log: str) -> dict[str, Any]:
        parsed_log: dict[str, Any] = {
            "raw": raw_log,
            "event": "apache_access"
        }

        try:
            # Regex generico per log in stile Apache container (semplificato)
            pattern = (
                r'(?P<ip>\S+) - - '
                r'\[(?P<timestamp>[^\]]+)\] '
                r'"(?P<request>[^"]+)" '
                r'(?P<status>\d{3}) '
                r'(?P<size>\d+|-)'
            )

            match = re.match(pattern, raw_log)
            if not match:
                raise ValueError("Formato log non riconosciuto")

            parsed_log["ip"] = match.group("ip")
            parsed_log["timestamp"] = match.group("timestamp")
            parsed_log["status"] = int(match.group("status"))

            # Alcuni log hanno "-" al posto della dimensione
            size = match.group("size")
            parsed_log["size"] = int(size) if size.isdigit() else 0

            request = match.group("request")

            # Gestione richieste HTTP e non
            if request == "-":
                parsed_log["method"] = None
                parsed_log["path"] = None
                parsed_log["protocol"] = None
                parsed_log["event"] = "empty_request"
            elif re.match(r'^\S+ /.* HTTP/\d+\.\d+$', request):
                # es: GET / HTTP/1.1
                parts = request.split()
                parsed_log["method"] = parts[0]
                parsed_log["path"] = parts[1]
                parsed_log["protocol"] = parts[2]
            else:
                # Richiesta non HTTP ma stringa (es: SSH banner)
                parsed_log["raw_request"] = request
                parsed_log["event"] = "non_http_request"

            return parsed_log

        except Exception as e:
            logger.error(f"[ApacheParser] Errore durante il parsing: {e} — Log: {raw_log}", exc_info=True)
            parsed_log["event"] = "parse_error"
            return parsed_log
