from parsers.base_parser import InterfaceLogParser
from typing import Any
import re
import logging

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

    def parse(self, raw_log: str) -> dict[str, Any]:
        parsed: dict[str, Any] = {
            "event": "ldap_event"
        }

        try:
            # Pattern generico
            pattern = (
                r'(?P<timestamp>[a-f0-9]+)'                         # timestamp es: 686fc767
                r'\s+conn=(?P<conn_id>\d+)'                         # connessione
                r'(?:\s+fd=(?P<fd>\d+))?'                           # file descriptor
                r'(?:\s+op=(?P<op_id>\d+))?'                        # operation ID
                r'\s+(?P<event_type>[A-Z]+|closed|ACCEPT)'          # evento in MAIUSCOLO o closed/ACCEPT
                r'(?:\s+dn="(?P<dn>[^"]*)")?'                       # DN
                r'(?:\s+method=(?P<method>\d+))?'                   # metodo
                r'(?:\s+base="(?P<base>[^"]*)")?'                   # base search
                r'(?:\s+scope=(?P<scope>\d+))?'                     # scope
                r'(?:\s+deref=(?P<deref>\d+))?'                     # deref
                r'(?:\s+filter="(?P<filter>[^"]*)")?'               # filtro
                r'(?:\s+RESULT\s+tag=\d+\s+err=(?P<err>\d+))?'      # codice errore
                r'(?:\s+nentries=(?P<nentries>\d+))?'               # numero risultati
                r'(?:\s+text=(?P<text>.*))?'                        # testo errore
                r'(?:\s+ACCEPT from IP=(?P<src_ip>[\d\.]+):(?P<src_port>\d+))?'  # ACCEPT info IP
            )

            match = re.search(pattern, raw_log)
            if not match:
                logger.warning(f"Log non riconosciuto: {raw_log}")
                return []

            groups = match.groupdict()

            # Assegna campi utili
            parsed.update({
                "timestamp": groups["timestamp"],
                "connection_id": int(groups["conn_id"]),
                "operation_id": int(groups["op_id"]) if groups["op_id"] else None,
                "event": groups["event_type"].lower(),  # bind, search, etc.
                "fd": int(groups["fd"]) if groups["fd"] else None,
                "dn": groups["dn"],
                "method": int(groups["method"]) if groups["method"] else None,
                "base": groups["base"],
                "scope": int(groups["scope"]) if groups["scope"] else None,
                "deref": int(groups["deref"]) if groups["deref"] else None,
                "filter": groups["filter"],
                "error_code": int(groups["err"]) if groups["err"] else None,
                "entries": int(groups["nentries"]) if groups["nentries"] else None,
                "error_text": groups["text"],
                "src_ip": groups["src_ip"],
                "src_port": int(groups["src_port"]) if groups["src_port"] else None,
            })

            return parsed

        except Exception as e:
            logger.error(f"[LDAPParser] Errore parsing log: {e} — Log: {raw_log}", exc_info=False)
            return []