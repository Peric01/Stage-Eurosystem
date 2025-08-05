import pytest
from parsers.LDAP_parser import LDAPParser
from unittest.mock import patch

@patch("parsers.LDAP_parser.GeomapIP.fetch_location", return_value=(48.0, 10.0))
def test_parse_bind_event(mock_geo):
    log = 'conn=1005 op=0 BIND dn="cn=admin,dc=example,dc=com" method=128 IP=192.168.1.10:56789 IP=0.0.0.0:389 err=0'
    parser = LDAPParser()
    parsed = parser.parse(log)

    assert parsed["connection_id"] == "1005"
    assert parsed["operation_id"] == "0"
    assert parsed.get("fd") is None  # invece di parsed["fd"]
    assert parsed["event"].upper() == "BIND"
    assert parsed["username"] == "admin"
    assert parsed["dn"] == "cn=admin,dc=example,dc=com"
    assert parsed["src_ip"] == "192.168.1.10"
    assert parsed["src_port"] == 56789
    assert parsed["dst_port"] == 389
    assert parsed["latitude"] == 48.0

def test_parse_search_result():
    log = 'conn=1005 op=1 SEARCH RESULT tag=101 err=32 nentries=0 text='
    parser = LDAPParser()
    parsed = parser.parse(log)

    assert parsed["event"].upper() == "SEARCH"
    assert parsed["operation_id"] == "1"
    assert parsed["error"] == "32"

def test_parse_log_with_no_match():
    log = 'some garbage string'
    parser = LDAPParser()
    parsed = parser.parse(log)

    # Deve restituire comunque un dizionario base
    assert parsed["event"] == "ldap_event"

@patch("parsers.LDAP_parser.GeomapIP.fetch_location", return_value=(0.0, 0.0))
def test_parse_err_field(mock_geo):
    log = 'conn=123 op=2 SEARCH dn="cn=admin,dc=example,dc=com" IP=192.168.1.10:12345 IP=0.0.0.0:389 err=13'
    parser = LDAPParser()
    parsed = parser.parse(log)
    assert parsed["error"] == "13"

@patch("parsers.LDAP_parser.GeomapIP.fetch_location", side_effect=Exception("Fake error"))
def test_parse_exception_handling(mock_geo):
    log = 'conn=99 op=3 BIND dn="cn=broken" IP=1.2.3.4:9999 IP=0.0.0.0:389'
    parser = LDAPParser()
    parsed = parser.parse(log)
    assert parsed["event"] == "BIND"  # anche se c'è errore nella geolocalizzazione


@patch("parsers.LDAP_parser.GeomapIP.fetch_location", return_value=(10.0, 20.0))
def test_parse_with_fd(mock_geo):
    log = 'conn=2001 fd=12 closed IP=192.168.0.1:12345 IP=0.0.0.0:389'
    parser = LDAPParser()
    parsed = parser.parse(log)
    assert parsed["fd"] == 12