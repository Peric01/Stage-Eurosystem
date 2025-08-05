import pytest
from core.geomap_ip import GeomapIP
from unittest.mock import patch, MagicMock


def test_private_ip_returns_none(caplog):
    result = GeomapIP.fetch_location("192.168.1.1")
    assert result is None
    assert "Skipping geolocation for private IP" in caplog.text


def test_invalid_ip_returns_none(caplog):
    result = GeomapIP.fetch_location("invalid_ip")
    assert result is None
    assert "Invalid IP format" in caplog.text


@patch("core.geomap_ip.geocoder.ip")
def test_failed_geolocation(mock_geocoder, caplog):
    mock_geocoder.return_value.ok = False
    mock_geocoder.return_value.latlng = None

    result = GeomapIP.fetch_location("8.8.8.8")
    assert result is None
    assert "Failed to fetch geolocation" in caplog.text


@patch("core.geomap_ip.geocoder.ip")
def test_successful_geolocation(mock_geocoder):
    mock_geocoder.return_value.ok = True
    mock_geocoder.return_value.latlng = (37.7749, -122.4194)

    result = GeomapIP.fetch_location("8.8.8.8")
    assert result == (37.7749, -122.4194)
