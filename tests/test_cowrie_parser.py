import pytest
from parsers.cowrie_parser import CowrieParser
from unittest.mock import patch

valid_log = '''
{
  "timestamp": "2024-01-01T12:00:00Z",
  "src_ip": "1.2.3.4",
  "src_port": 1234,
  "dst_ip": "5.6.7.8",
  "dst_port": 22,
  "eventid": "cowrie.session.connect",
  "message": "Connection established",
  "username": "root",
  "password": "toor",
  "input": "ls -la",
  "session": "abc123",
  "protocol": "ssh",
  "version": "SSH-2.0-OpenSSH_7.4",
  "hassh": "12345",
  "ttylog": "logfile",
  "duration": 12.3,
  "sensor": "honeypot-1"
}
'''

@patch("parsers.cowrie_parser.GeomapIP.fetch_location", return_value=[45.0, 9.0])
def test_parse_valid_log(mock_location):
    parser = CowrieParser()
    result = parser.parse(valid_log)

    assert result["src_ip"] == "1.2.3.4"
    assert result["latitude"] == 45.0
    assert result["longitude"] == 9.0
    assert result["command"] == "ls -la"
    assert result["event"] == "cowrie.session.connect"

@patch("parsers.cowrie_parser.GeomapIP.fetch_location", return_value=None)
def test_parse_missing_location(mock_location):
    parser = CowrieParser()
    result = parser.parse(valid_log)

    assert result["latitude"] is None
    assert result["longitude"] is None

def test_parse_invalid_json(caplog):
    parser = CowrieParser()
    result = parser.parse("invalid_json")
    assert result == {}
    assert "Failed to parse log" in caplog.text

@patch("parsers.cowrie_parser.GeomapIP.fetch_location", side_effect=Exception("boom"))
def test_parse_raises_generic_exception(mock_location, caplog):
    parser = CowrieParser()
    result = parser.parse(valid_log)
    assert result == {}
    assert "Unhandled error in CowrieParser" in caplog.text
