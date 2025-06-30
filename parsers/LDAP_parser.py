from parsers.base_parser import InterfaceLogParser
from typing import Any
import re
import logging

logger = logging.getLogger("LogSystem")

class LDAPParser(InterfaceLogParser):
    '''
    Parser per log LDAP (es. OpenLDAP)

    Esempio di log:
    Jun 30 10:52:18 server slapd[1234]: conn=1000 op=2 BIND dn="uid=admin,dc=example,dc=com" method=128
    '''
    def parse(self, raw_log: str) -> dict[str, Any]:
        try:
            pattern = r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+).*slapd\[\d+\]: conn=(?P<conn_id>\d+) op=(?P<operation>\d+) (?P<event>[A-Z]+) dn="(?P<dn>[^"]+)"(?: method=(?P<method>\d+))?'
            match = re.search(pattern, raw_log)

            if not match:
                raise ValueError("No match")

            return {
                "timestamp": match.group("timestamp"),
                "connection_id": match.group("conn_id"),
                "operation": match.group("operation"),
                "event": match.group("event"),
                "dn": match.group("dn"),
                "method": match.group("method"),
            }

        except Exception as e:
            logger.error(f"Failed to parse LDAP log: {raw_log} — {e}")
            return {
                "error": "Failed to parse LDAP log",
                "raw": raw_log
            }