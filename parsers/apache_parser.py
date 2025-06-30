from parsers.base_parser import InterfaceLogParser
from typing import Any
import re
import logging

logger = logging.getLogger("LogSystem")

class ApacheParser(InterfaceLogParser):
    '''
    Parser per log Apache HTTPD in formato Common Log Format

    Esempio:
    127.0.0.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    '''
    def parse(self, raw_log: str) -> dict[str, Any]:
        try:
            pattern = r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+)'
            match = re.match(pattern, raw_log)

            if not match:
                raise ValueError("No match")

            return {
                "ip": match.group("ip"),
                "user": match.group("user"),
                "timestamp": match.group("timestamp"),
                "method": match.group("method"),
                "path": match.group("path"),
                "protocol": match.group("protocol"),
                "status": int(match.group("status")),
                "size": int(match.group("size")),
            }

        except Exception as e:
            logger.error(f"Failed to parse Apache log: {raw_log} — {e}")
            return {
                "error": "Failed to parse Apache log",
                "raw": raw_log
            }
