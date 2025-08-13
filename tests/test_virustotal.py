import pytest
from unittest.mock import patch, MagicMock
from osint.virustotal import VirusTotal

@pytest.fixture
def virustotal():
    return VirusTotal(api_key="dummy_api_key")

@patch("osint.virustotal.requests.get")
def test_query_success(mock_get, virustotal):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "data": {"id": "1.2.3.4", "attributes": {"country": "US"}}
    }
    mock_get.return_value = mock_response

    result = virustotal.query("1.2.3.4")

    mock_get.assert_called_once_with(
        "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        headers={"x-apikey": "dummy_api_key"}
    )
    assert result == {"id": "1.2.3.4", "attributes": {"country": "US"}}

@patch("osint.virustotal.requests.get")
@patch("osint.virustotal.logger")
def test_query_http_error_logs_and_returns_empty(mock_logger, mock_get, virustotal):
    from requests.exceptions import HTTPError

    mock_get.side_effect = HTTPError("403 Client Error")

    result = virustotal.query("1.2.3.4")

    assert result == {}
    mock_logger.error.assert_called_once()
    assert "VirusTotal error for 1.2.3.4" in mock_logger.error.call_args[0][0]

@patch("osint.virustotal.requests.get")
@patch("osint.virustotal.logger")
def test_query_generic_exception_logs_and_returns_empty(mock_logger, mock_get, virustotal):
    mock_get.side_effect = Exception("something went wrong")

    result = virustotal.query("1.2.3.4")

    assert result == {}
    mock_logger.error.assert_called_once()
    assert "VirusTotal error for 1.2.3.4" in mock_logger.error.call_args[0][0]
