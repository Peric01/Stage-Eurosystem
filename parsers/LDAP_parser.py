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

            conn_id_match = re.search(r'conn=(\d+)', raw_log)
            if conn_id_match:
                parsed_log["connection_id"] = conn_id_match.group(1)
            
            op_id_match = re.search(r'op=(\d+)', raw_log)
            if op_id_match:
                parsed_log["operation_id"] = op_id_match.group(1)
            fd_match = re.search(r'fd=(\d+)', raw_log)
            if fd_match:
                parsed_log["fd"] = int(fd_match.group(1))
            dn_match = re.search(r'dn="([^"]+)"', raw_log)
            if dn_match:
                parsed_log["dn"] = dn_match.group(1)
            # Estrai l'evento dopo fd= o op= (es: ACCEPT, BIND, SEARCH, UNBIND, ecc. anche in minuscolo)
            event_match = re.search(r'(?:fd=\d+\s+|op=\d+\s+)([A-Za-z]+)', raw_log)
            if event_match:
                parsed_log["event"] = event_match.group(1)
                # Se l'evento è BIND, estrai la CN come username
                if event_match.group(1).upper() == "BIND" and dn_match:
                    cn_match = re.search(r'cn=([^,]+)', dn_match.group(1))
                    if cn_match:
                        parsed_log["username"] = cn_match.group(1)
            err_match = re.search(r'err=(\d+)', raw_log)
            if err_match:
                parsed_log["error"] = err_match.group(1)
            src_ip_match = re.search(r'IP=(\d+\.\d+\.\d+\.\d+):(\d+)', raw_log)
            if src_ip_match:
                parsed_log["src_ip"] = src_ip_match.group(1)
                parsed_log["src_port"] = int(src_ip_match.group(2))
                latitude, longitude = GeomapIP.fetch_location(parsed_log["src_ip"])
                parsed_log["latitude"] = latitude
                parsed_log["longitude"] = longitude
            # L'IP di destinazione è sempre 0.0.0.0, estrai solo la porta dopo i due punti
            
            dst_port_match = re.search(r'IP=0\.0\.0\.0:(\d+)', raw_log)
            if dst_port_match:
                parsed_log["dst_port"] = int(dst_port_match.group(1))

        except Exception as e:
            logger.error(f"[LDAPParser] Errore durante il parsing: {e}", exc_info=True)

        return parsed_log
