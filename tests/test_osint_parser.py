import pytest
from parsers.osint_parser import OSINTParser
import logging

parser = OSINTParser()

def test_parse_valid_full_json():
    raw = '''
    {
        "abuseipdb": {
            "abuseConfidenceScore": 10,
            "totalReports": 5
        },
        "shodan": {
            "vulns": ["CVE-1234", "CVE-5678"],
            "port": 80
        },
        "virustotal": {
            "last_analysis_stats": {"malicious": 1, "undetected": 10},
            "tags": ["tag1", "tag2"]
        }
    }
    '''
    parsed = parser.parse(raw)
    assert parsed == {
        "abuseipdb": {"abuseConfidenceScore": 10, "totalReports": 5},
        "shodan": {"vulns": ["CVE-1234", "CVE-5678"], "port": 80},
        "virustotal": {
            "last_analysis_stats": {"malicious": 1, "undetected": 10},
            "tags": ["tag1", "tag2"]
        }
    }

def test_parse_missing_fields():
    parser = OSINTParser()
    raw_log = "{}"  # json senza dati osint

    result = parser.parse(raw_log)

    assert result == {}


def test_parse_partial_data():
    raw = '{"abuseipdb": {"abuseConfidenceScore": 5}}'
    parsed = parser.parse(raw)
    assert parsed == {
        "abuseipdb": {"abuseConfidenceScore": 5, "totalReports": None}
    }

def test_parse_invalid_json(caplog):
    bad_raw = '{"abuseipdb": "missing end}'
    with caplog.at_level(logging.ERROR):
        parsed = parser.parse(bad_raw)
        assert parsed == {}
        assert "JSON decode error" in caplog.text
