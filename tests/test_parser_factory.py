import pytest
from parsers.parser_factory import get_parser
from parsers.cowrie_parser import CowrieParser
from parsers.dionaea_parser import DionaeaParser
from parsers.LDAP_parser import LDAPParser
from parsers.apache_parser import ApacheParser

def test_get_cowrie_parser():
    parser = get_parser("cowrie")
    assert isinstance(parser, CowrieParser)

def test_get_dionaea_parser():
    parser = get_parser("dionaea")
    assert isinstance(parser, DionaeaParser)

def test_get_openldap_parser():
    parser = get_parser("openldap")
    assert isinstance(parser, LDAPParser)

def test_get_apache_parser():
    parser = get_parser("apache")
    assert isinstance(parser, ApacheParser)

def test_get_parser_invalid():
    with pytest.raises(ValueError, match="No parser found for unknown"):
        get_parser("unknown")
