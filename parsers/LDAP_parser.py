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

    import re
from parsers.base_parser import InterfaceLogParser
from typing import Any
import logging
from core.geomap_ip import GeomapIP

logger = logging.getLogger("LogSystem")

class LDAPParser(InterfaceLogParser):
    """
    Parser avanzato per log OpenLDAP.
    Riconosce eventi di tipo:
    - connessioni (ACCEPT / closed)
    - operazioni LDAP (BIND, SEARCH, RESULT, UNBIND, etc.)
    """

    def parse(self, raw_log: str) -> dict[str, Any]:
        parsed_log: dict[str, Any] = {
            "event": "ldap_event"
        }

        logger.debug(f"Parsing raw log: {raw_log}")

        try:
            # --- Estrattore principale (regex combinata flessibile) ---
            pattern = (
                r'(?P<timestamp>[a-f0-9]+)\s+'
                r'conn=(?P<conn_id>\d+)'
                r'(?:\s+fd=(?P<fd>\d+))?'
                r'(?:\s+op=(?P<op_id>\d+))?'
                r'\s+(?P<event_type>[A-Z_]+|closed|ACCEPT)'
                r'(?:\s+dn="(?P<dn>[^"]*)")?'
                r'(?:\s+method=(?P<method>\d+))?'
                r'(?:\s+base="(?P<base>[^"]*)")?'
                r'(?:\s+scope=(?P<scope>\d+))?'
                r'(?:\s+deref=(?P<deref>\d+))?'
                r'(?:\s+filter="(?P<filter>[^"]*)")?'
                r'(?:\s+RESULT\s+tag=\d+\s+err=(?P<err>\d+))?'
                r'(?:\s+nentries=(?P<nentries>\d+))?'
                r'(?:\s+text=(?P<text>.*?))?'
                r'(?:\s+ACCEPT from IP=(?P<src_ip>[\d\.]+):(?P<src_port>\d+))?'
            )

            match = re.search(pattern, raw_log)
            if not match:
                logger.warning(f"Log non riconosciuto: {raw_log}")
                return parsed_log  # fallback vuoto

            g = match.groupdict()

            # --- Timestamp (hex form, no datetime conversion) ---
            parsed_log["timestamp"] = g["timestamp"]

            # --- Informazioni connessione ---
            parsed_log["connection_id"] = int(g["conn_id"])
            parsed_log["fd"] = int(g["fd"]) if g["fd"] else None
            parsed_log["operation_id"] = int(g["op_id"]) if g["op_id"] else None

            # --- Evento primario ---
            parsed_log["event"] = g["event_type"].replace(" ", "_").lower()

            # --- Campi LDAP ---
            parsed_log["dn"] = g["dn"]
            parsed_log["method"] = int(g["method"]) if g["method"] else None
            parsed_log["base"] = g["base"]
            parsed_log["scope"] = int(g["scope"]) if g["scope"] else None
            parsed_log["deref"] = int(g["deref"]) if g["deref"] else None
            parsed_log["filter"] = g["filter"]

            # --- Risultato operazione ---
            parsed_log["error_code"] = int(g["err"]) if g["err"] else None
            parsed_log["entries"] = int(g["nentries"]) if g["nentries"] else None
            parsed_log["error_text"] = g["text"] if g["text"] is not None else None

            # --- IP sorgente ---
            if g["src_ip"]:
                parsed_log["src_ip"] = g["src_ip"]
                parsed_log["src_port"] = int(g["src_port"])
                try:
                    latitude, longitude = GeomapIP.fetch_location(g["src_ip"])
                    parsed_log["latitude"] = latitude
                    parsed_log["longitude"] = longitude
                except Exception as geo_err:
                    logger.warning(f"Geolocalizzazione fallita per IP {g['src_ip']}: {geo_err}")

        except Exception as e:
            logger.error(f"[LDAPParser] Errore durante il parsing: {e}", exc_info=True)

        return parsed_log
