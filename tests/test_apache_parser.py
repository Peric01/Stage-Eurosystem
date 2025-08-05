import pytest
from parsers.apache_parser import ApacheParser
from unittest.mock import patch

@patch("parsers.apache_parser.GeomapIP.fetch_location", return_value=(45.0, 9.0))
def test_parse_valid_http_log(mock_fetch):
    log = '93.41.255.167 - - [04/Jul/2025:07:12:37 +0000] "GET / HTTP/1.1" 200 269'
    parser = ApacheParser()
    parsed = parser.parse(log)

    assert parsed["src_ip"] == "93.41.255.167"
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/"
    assert parsed["protocol"] == "HTTP/1.1"
    assert parsed["status"] == 200
    assert parsed["size"] == 269
    assert parsed["latitude"] == 45.0

@patch("parsers.apache_parser.GeomapIP.fetch_location", return_value=(None, None))
def test_parse_log_with_dash_request(mock_fetch):
    log = '93.41.255.167 - - [04/Jul/2025:07:13:46 +0000] "-" 408 -'
    parser = ApacheParser()
    parsed = parser.parse(log)

    assert parsed["event"] == "empty_request"
    assert parsed["method"] is None

@patch("parsers.apache_parser.GeomapIP.fetch_location", return_value=(None, None))
def test_parse_non_http_request(mock_fetch):
    log = '93.41.255.167 - - [03/Jul/2025:09:12:22 +0000] "SSH-2.0-OpenSSH_for_Windows_9.5" 400 226'
    parser = ApacheParser()
    parsed = parser.parse(log)

    assert parsed["event"] == "non_http_request"
    assert "raw_request" in parsed
    assert parsed["status"] == 400

def test_parse_invalid_format(caplog):
    parser = ApacheParser()
    parsed = parser.parse("invalid format")
    assert parsed == []
    assert "Log non riconosciuto" in caplog.text

@patch("parsers.apache_parser.GeomapIP.fetch_location", side_effect=Exception("Geo error"))
def test_apache_parser_exception_handling(mock_geo):
    log = '93.41.255.167 - - [04/Jul/2025:07:12:37 +0000] "GET / HTTP/1.1" 200 269'
    parser = ApacheParser()
    result = parser.parse(log)
    assert result == []  # ritorna lista vuota in caso di errore
