from .cowrie_parser import CowrieParser
from .dionaea_parser import DionaeaParser
from .LDAP_parser import LDAPParser
from .apache_parser import ApacheParser

'''
Factory per la creazione di parser in base al tipo richiesto.

La factory consente di istanziare il parser corretto in modo dinamico
senza dover scrivere il codice di una classe specifica nel codice di alto livello.

'''

def get_parser(name: str):
    if name.lower() == "cowrie":
        return CowrieParser()
    elif name.lower() == "dionaea":
        return DionaeaParser()
    elif name.lower() == "openldap":
        return LDAPParser()
    elif name.lower() == "apache":
        return ApacheParser()
    else:
        raise ValueError(f"No parser found for {name}")