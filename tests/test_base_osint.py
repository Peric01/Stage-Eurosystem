import pytest
from unittest.mock import patch, Mock
from osint.base_osint import OSINTService

class DummyOSINT(OSINTService):
    def query(self, ip: str) -> dict:
        return {"ip": ip}

def test_query_method():
    svc = DummyOSINT("fake_api_key")
    assert svc.query("1.2.3.4") == {"ip": "1.2.3.4"}

@patch("osint.base_osint.requests.get")
def test_handle_request_success(mock_get):
    svc = DummyOSINT("key")
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"success": True}
    mock_get.return_value = mock_response

    result = svc.handle_request("http://fakeurl")
    assert result == {"success": True}
    mock_get.assert_called_once_with("http://fakeurl", headers=None, params=None)
    mock_response.raise_for_status.assert_called_once()

@patch("osint.base_osint.requests.get")
def test_handle_request_http_error(mock_get):
    svc = DummyOSINT("key")
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = Exception("error")
    mock_get.return_value = mock_response

    result = svc.handle_request("http://fakeurl")
    assert result == {}  # on error returns empty dict

def test_api_key_storage():
    key = "my_key"
    svc = DummyOSINT(key)
    assert svc.api_key == key
