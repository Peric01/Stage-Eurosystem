import pytest
from unittest.mock import patch, MagicMock
from publishers.mqtt_publisher import MqttPublisher

@patch("publishers.mqtt_publisher.mqtt.Client")
@patch("publishers.mqtt_publisher.LogManager.get_instance")
def test_mqtt_publisher_initialization(mock_log_manager, mock_mqtt_client):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger
    mock_client_instance = MagicMock()
    mock_mqtt_client.return_value = mock_client_instance

    publisher = MqttPublisher("test-broker", "test/topic")

    assert publisher.broker_address == "test-broker"
    assert publisher.topic == "test/topic"
    mock_client_instance.connect.assert_called_once_with("test-broker", 8883)
    mock_client_instance.loop_start.assert_called_once()

@patch("publishers.mqtt_publisher.mqtt.Client")
@patch("publishers.mqtt_publisher.LogManager.get_instance")
def test_mqtt_publish_sends_payload(mock_log_manager, mock_mqtt_client):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger
    mock_client_instance = MagicMock()
    mock_mqtt_client.return_value = mock_client_instance

    publisher = MqttPublisher("localhost", "test/topic")
    test_log = {"level": "info", "message": "test message"}

    publisher.publish(test_log)

    import json
    expected_payload = json.dumps(test_log)
    mock_client_instance.publish.assert_called_once_with("test/topic", expected_payload)

@patch("publishers.mqtt_publisher.mqtt.Client")
@patch("publishers.mqtt_publisher.LogManager.get_instance")
def test_mqtt_publish_exception_handling(mock_log_manager, mock_mqtt_client):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger
    mock_client_instance = MagicMock()
    mock_client_instance.publish.side_effect = Exception("Publish failed")
    mock_mqtt_client.return_value = mock_client_instance

    publisher = MqttPublisher("localhost", "test/topic")
    publisher.publish({"error": "simulated"})

    mock_logger.exception.assert_called_once_with("Failed to publish log to MQTT: Publish failed")
