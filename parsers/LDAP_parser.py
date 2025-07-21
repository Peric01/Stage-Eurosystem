from parsers.base_parser import InterfaceLogParser
from typing import Any
import re
import logging
from core.geomap_ip import GeomapIP

logger = logging.getLogger("LogSystem")

class LDAPParser(InterfaceLogParser):
    '''
    Parser avanzato per log OpenLDAP: connessioni e operazioni (bind, search, add, modify, delete, etc.)

    Esempi supportati:
    - conn=1005 op=0 BIND dn="cn=admin,dc=example,dc=com" method=128
    - conn=1005 op=1 SEARCH RESULT tag=101 err=32 nentries=0 text=
    - conn=1005 op=2 ADD dn="cn=newuser,dc=example,dc=com"
    - conn=1005 fd=12 closed (connection lost)
    '''

    def parse(self, raw_log: str) -> dict[str, Any] | None:
        parsed: dict[str, Any] = {
            "event": "ldap_event"
        }

        try:
            pattern = (
                r'(?P<timestamp>[a-f0-9]+)\s+'
                r'conn=(?P<conn_id>\d+)'                          # conn=1011
                r'(?:\s+fd=(?P<fd>\d+))?'                         # fd=12
                r'(?:\s+op=(?P<op_id>\d+))?'                      # op=0
                r'\s+(?P<event_type>[A-Z_]+|closed|ACCEPT)'       # BIND, RESULT, SEARCH_RESULT, etc.
                r'(?:\s+dn="(?P<dn>[^"]*)")?'                     # dn=""
                r'(?:\s+method=(?P<method>\d+))?'                 # method=128
                r'(?:\s+base="(?P<base>[^"]*)")?'                 # base="dc=example,dc=com"
                r'(?:\s+scope=(?P<scope>\d+))?'                   # scope=2
                r'(?:\s+deref=(?P<deref>\d+))?'                   # deref=0
                r'(?:\s+filter="(?P<filter>[^"]*)")?'             # filter="(objectClass=*)"
                r'(?:\s+RESULT\s+tag=\d+\s+err=(?P<err>\d+))?'    # RESULT tag=... err=...
                r'(?:\s+nentries=(?P<nentries>\d+))?'             # nentries=0
                r'(?:\s+text=(?P<text>.*?))?'                     # text=... (può essere vuoto)
                r'(?:\s+ACCEPT from IP=(?P<src_ip>[\d\.]+):(?P<src_port>\d+))?'  # IP
            )

            match = re.search(pattern, raw_log)
            if not match:
                logger.warning(f"Log non riconosciuto: {raw_log}")
                return None

            groups = match.groupdict()

            parsed.update({
                "timestamp": groups["timestamp"],
                "connection_id": int(groups["conn_id"]),
                "operation_id": int(groups["op_id"]) if groups["op_id"] else None,
                "event": groups["event_type"].replace(" ", "_").lower(),
                "fd": int(groups["fd"]) if groups["fd"] else None,
                "dn": groups["dn"],
                "method": int(groups["method"]) if groups["method"] else None,
                "base": groups["base"],
                "scope": int(groups["scope"]) if groups["scope"] else None,
                "deref": int(groups["deref"]) if groups["deref"] else None,
                "filter": groups["filter"],
                "error_code": int(groups["err"]) if groups["err"] else None,
                "entries": int(groups["nentries"]) if groups["nentries"] else None,
                "error_text": groups["text"] if groups["text"] is not None else None,
                "src_ip": groups["src_ip"],
                "src_port": int(groups["src_port"]) if groups["src_port"] else None,
            })

            if parsed.get("src_ip"):
                latitude, longitude = GeomapIP.fetch_location(parsed["src_ip"])
                parsed["latitude"] = latitude
                parsed["longitude"] = longitude

            return parsed

        except Exception as e:
            logger.error(f"[LDAPParser] Errore parsing log: {e} — Log: {raw_log}", exc_info=False)
            return None
