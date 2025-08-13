import pytest
from unittest.mock import patch, MagicMock
from osint.shodan import Shodan

@pytest.fixture
def shodan():
    return Shodan(api_key="secret_api_key")

@patch("osint.shodan.requests.get")
def test_query_success(mock_get, shodan):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"data": "some data"}
    mock_get.return_value = mock_response

    result = shodan.query("1.2.3.4")

    mock_get.assert_called_once_with("https://api.shodan.io/shodan/host/1.2.3.4?key=secret_api_key")
    assert result == {"data": "some data"}

@patch("osint.shodan.requests.get")
@patch("osint.shodan.logger")
def test_query_http_error_with_key_in_message(mock_logger, mock_get, shodan):
    from requests.exceptions import HTTPError

    # L'errore contiene la chiave nel messaggio (simuliamo)
    err_msg = "403 Client Error: Forbidden for url: https://api.shodan.io/shodan/host/1.2.3.4?key=secret_api_key"
    mock_get.side_effect = HTTPError(err_msg)

    result = shodan.query("1.2.3.4")

    assert result == {}
    # Verifica che la chiave sia censurata nel messaggio di log
    logged_msg = mock_logger.error.call_args[0][0]
    assert "key=****" in logged_msg
    assert "secret_api_key" not in logged_msg

@patch("osint.shodan.requests.get")
@patch("osint.shodan.logger")
def test_query_generic_exception(mock_logger, mock_get, shodan):
    mock_get.side_effect = Exception("generic error")

    result = shodan.query("1.2.3.4")

    assert result == {}
    assert "generic error" in mock_logger.error.call_args[0][0]
