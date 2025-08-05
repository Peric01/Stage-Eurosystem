import pytest
from parsers.dionaea_parser import DionaeaParser
from unittest.mock import patch

@patch("parsers.dionaea_parser.GeomapIP.fetch_location", return_value=(44.0, 11.0))
def test_parse_full_log(mock_geo):
    log = '[03082025 15:45:00] info: connection from 1.2.3.4:4444 to 5.6.7.8:21 username: (string) admin password: (string) secret command: (string) LIST attackid 1234'
    parser = DionaeaParser()
    parsed = parser.parse(log)

    assert parsed["timestamp"] == "2025-08-03T15:45:00"
    assert parsed["src_ip"] == "1.2.3.4"
    assert parsed["latitude"] == 44.0
    assert parsed["username"] == "admin"
    assert parsed["password"] == "secret"
    assert parsed["command"] == "LIST"
    assert parsed["attack_id"] == "1234"
    assert parsed["event"] == "dionaea_event"

def test_parse_log_without_timestamp():
    log = 'info: malformed log entry'
    parser = DionaeaParser()
    parsed = parser.parse(log)

    assert "timestamp" not in parsed
    assert parsed["event"] == "dionaea_event"

def test_parse_cleanup_event():
    log = '[03082025 12:00:00] sip connection-warning: Cleanup completed'
    parser = DionaeaParser()
    parsed = parser.parse(log)

    # Ignora log ma restituisce comunque il dizionario
    assert parsed["event"] == "dionaea_event"

@patch("parsers.dionaea_parser.GeomapIP.fetch_location", return_value=(10.0, 20.0))
def test_dionaea_attack_id(mock_geo):
    log = '[03082025 15:45:00] info: connection from 1.2.3.4:4444 to 5.6.7.8:21 attackid 7777'
    parser = DionaeaParser()
    parsed = parser.parse(log)
    assert parsed["attack_id"] == "7777"

@patch("parsers.dionaea_parser.GeomapIP.fetch_location", side_effect=Exception("Geo lookup failed"))
def test_dionaea_parser_exception(mock_geo):
    log = '[03082025 15:45:00] info: connection from 1.2.3.4:4444 to 5.6.7.8:21'
    parser = DionaeaParser()
    result = parser.parse(log)
    assert result["event"] == "dionaea_event"

@patch("parsers.dionaea_parser.GeomapIP.fetch_location", return_value=(44.0, 11.0))
def test_parse_custom_event(mock_geo):
    log = '[03082025 12:00:00] foobar / info: connection from 1.1.1.1:1000 to 2.2.2.2:21'
    parser = DionaeaParser()
    parsed = parser.parse(log)
    assert parsed["event"] == "foobar"