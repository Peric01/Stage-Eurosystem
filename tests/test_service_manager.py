import pytest
from unittest.mock import patch, MagicMock
from core.service_manager import ServiceManager

@patch("core.service_manager.get_publisher")
@patch("core.service_manager.get_parser")
@patch("core.service_manager.LogCollector")
@patch("core.service_manager.LogManager.get_instance")
def test_initialize_services_success(mock_log_manager, mock_log_collector_cls, mock_get_parser, mock_get_publisher):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger

    mock_parser = MagicMock()
    mock_get_parser.return_value = mock_parser

    mock_publisher = MagicMock()
    mock_get_publisher.return_value = mock_publisher

    mock_collector = MagicMock()
    mock_log_collector_cls.return_value = mock_collector

    manager = ServiceManager()
    result = manager.initialize_services()

    assert result is True
    assert "log_collectors" in manager.services
    assert len(manager.services["log_collectors"]) > 0

@patch("core.service_manager.get_publisher", side_effect=Exception("Connection failed"))
@patch("core.service_manager.LogManager.get_instance")
def test_initialize_services_fail_on_publisher(mock_log_manager, mock_get_publisher):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger

    manager = ServiceManager()
    result = manager.initialize_services()

    assert result is False

@patch("core.service_manager.ThreadManager")
@patch("core.service_manager.LogManager.get_instance")
def test_start_services_success(mock_log_manager, mock_thread_manager_cls):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger

    mock_thread_manager = MagicMock()
    mock_thread_manager_cls.return_value = mock_thread_manager

    manager = ServiceManager()
    mock_collector = MagicMock()
    manager.services["log_collectors"] = [("test", mock_collector)]

    result = manager.start_services()
    assert result is True
    mock_thread_manager.run_thread.assert_called_once()

@patch("core.service_manager.ThreadManager")
@patch("core.service_manager.LogManager.get_instance")
def test_stop_services(mock_log_manager, mock_thread_manager_cls):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger

    mock_thread_manager = MagicMock()
    mock_thread_manager_cls.return_value = mock_thread_manager

    manager = ServiceManager()
    mock_collector = MagicMock()
    manager.services["log_collectors"] = [("test", mock_collector)]

    manager.stop_services()

    mock_collector.stop.assert_called_once()
    mock_thread_manager.wait_all.assert_called_once()

@patch("core.service_manager.get_parser", side_effect=Exception("parser error"))
@patch("core.service_manager.get_publisher")
@patch("core.service_manager.LogManager.get_instance")
def test_initialize_services_fail_on_collector(mock_log_manager, mock_get_publisher, mock_get_parser):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger

    mock_get_publisher.return_value = MagicMock()

    manager = ServiceManager()
    result = manager.initialize_services()

    assert result is True  # perché il metodo non fallisce completamente
    assert "log_collectors" in manager.services
    assert len(manager.services["log_collectors"]) == 0
    mock_logger.error.assert_any_call("Failed to initialize collector for cowrie: parser error")

@patch("core.service_manager.ThreadManager")
@patch("core.service_manager.LogManager.get_instance")
def test_start_services_exception(mock_log_manager, mock_thread_manager_cls):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger

    mock_thread_manager = MagicMock()
    mock_thread_manager.run_thread.side_effect = Exception("Thread error")
    mock_thread_manager_cls.return_value = mock_thread_manager

    manager = ServiceManager()
    mock_collector = MagicMock()
    manager.services["log_collectors"] = [("test", mock_collector)]

    result = manager.start_services()
    assert result is False
    mock_logger.exception.assert_called_once_with("Failed to start services")

