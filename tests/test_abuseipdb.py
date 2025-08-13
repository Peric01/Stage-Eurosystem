import pytest
from unittest import mock
from osint.abuseipdb import AbuseIPDB
import requests

class DummyOSINTService:
    def __init__(self, api_key):
        self.api_key = api_key

@pytest.fixture
def abuseipdb():
    # AbuseIPDB inherits from OSINTService, but for testing we can patch it
    class TestAbuseIPDB(AbuseIPDB, DummyOSINTService):
        pass
    return TestAbuseIPDB(api_key="test_api_key")

def test_query_success(abuseipdb):
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 10}}
    with mock.patch("requests.get", return_value=mock_response):
        result = abuseipdb.query("1.2.3.4")
        assert result == {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 10}

def test_query_http_error(abuseipdb):
    mock_response = mock.Mock()
    mock_response.raise_for_status.side_effect = requests.HTTPError("Bad request")
    with mock.patch("requests.get", return_value=mock_response), \
         mock.patch("osint.abuseipdb.logger") as mock_logger:
        result = abuseipdb.query("1.2.3.4")
        assert result == {}
        mock_logger.error.assert_called_once()
        assert "AbuseIPDB error for 1.2.3.4" in mock_logger.error.call_args[0][0]

def test_query_exception(abuseipdb):
    with mock.patch("requests.get", side_effect=Exception("Network error")), \
         mock.patch("osint.abuseipdb.logger") as mock_logger:
        result = abuseipdb.query("1.2.3.4")
        assert result == {}
        mock_logger.error.assert_called_once()
        assert "AbuseIPDB error for 1.2.3.4" in mock_logger.error.call_args[0][0]

def test_query_headers_and_params(abuseipdb):
    with mock.patch("requests.get") as mock_get:
        abuseipdb.query("8.8.8.8")
        args, kwargs = mock_get.call_args
        assert kwargs["headers"]["Key"] == "test_api_key"
        assert kwargs["headers"]["Accept"] == "application/json"
        assert kwargs["params"]["ipAddress"] == "8.8.8.8"
        assert kwargs["params"]["maxAgeInDays"] == 90