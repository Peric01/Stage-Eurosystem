import pytest
from unittest.mock import patch
from osint.osint_factory import OSINTServiceFactory
from osint.abuseipdb import AbuseIPDB
from osint.shodan import Shodan
from osint.virustotal import VirusTotal

def test_get_service_abuseipdb():
    service = OSINTServiceFactory.get_service("abuseipdb", "key123")
    assert isinstance(service, AbuseIPDB)
    assert service.api_key == "key123"

def test_get_service_shodan():
    service = OSINTServiceFactory.get_service("shodan", "key123")
    assert isinstance(service, Shodan)
    assert service.api_key == "key123"

def test_get_service_virustotal():
    service = OSINTServiceFactory.get_service("virustotal", "key123")
    assert isinstance(service, VirusTotal)
    assert service.api_key == "key123"

@patch("osint.osint_factory.logger")
def test_get_service_unsupported_service(mock_logger):
    result = OSINTServiceFactory.get_service("unknown_service", "key123")
    assert result is None
    mock_logger.error.assert_called_once_with("Unsupported service: unknown_service")
