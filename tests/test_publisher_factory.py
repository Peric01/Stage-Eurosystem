import pytest
from publishers.publisher_factory import get_publisher
from publishers.mqtt_publisher import MqttPublisher

def test_get_mqtt_publisher():
    publisher = get_publisher("mqtt", "localhost", "test/topic")
    assert isinstance(publisher, MqttPublisher)
    assert publisher.broker_address == "localhost"
    assert publisher.topic == "test/topic"

def test_get_publisher_invalid_name():
    with pytest.raises(ValueError) as excinfo:
        get_publisher("http", "localhost", "test/topic")
    assert "No publisher found for http" in str(excinfo.value)
