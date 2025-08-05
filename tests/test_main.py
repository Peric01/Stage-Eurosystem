import pytest
from unittest.mock import patch, MagicMock
import core.main

@patch("core.main.sys.argv", ["main.py", "2"])
@patch("core.main.LogManager.get_instance")
@patch("core.main.ServiceManager")
@patch("core.main.ask_log_level", return_value="INFO")
def test_main_initialize_success(mock_ask_log, mock_service_manager_cls, mock_log_manager):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger

    mock_service_manager = MagicMock()
    mock_service_manager.initialize_services.return_value = True
    mock_service_manager.run_event.is_set.side_effect = [True, False]  # loop una sola volta
    mock_service_manager_cls.return_value = mock_service_manager

    core.main.main()

    mock_logger.setLevel.assert_called_once_with("INFO")
    mock_service_manager.initialize_services.assert_called_once()
    mock_service_manager.start_services.assert_called_once()
    mock_service_manager.stop_services.assert_called_once()

@patch("core.main.sys.argv", ["main.py"])
@patch("core.main.LogManager.get_instance")
@patch("core.main.ServiceManager")
@patch("core.main.ask_log_level", return_value="DEBUG")
def test_main_initialize_failure(mock_ask_log, mock_service_manager_cls, mock_log_manager):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger

    mock_service_manager = MagicMock()
    mock_service_manager.initialize_services.return_value = False
    mock_service_manager_cls.return_value = mock_service_manager

    core.main.main()

    mock_logger.setLevel.assert_called_once_with("DEBUG")
    mock_service_manager.initialize_services.assert_called_once()
    mock_service_manager.start_services.assert_not_called()
    mock_service_manager.stop_services.assert_not_called()

@patch("core.main.sys.argv", ["main.py"])
@patch("core.main.LogManager.get_instance")
@patch("core.main.ServiceManager")
@patch("core.main.ask_log_level", return_value="WARNING")
def test_main_keyboard_interrupt(mock_ask_log, mock_service_manager_cls, mock_log_manager):
    mock_logger = MagicMock()
    mock_log_manager.return_value.get_logger.return_value = mock_logger

    mock_service_manager = MagicMock()
    mock_service_manager.initialize_services.return_value = True
    mock_service_manager.run_event.is_set.side_effect = KeyboardInterrupt
    mock_service_manager_cls.return_value = mock_service_manager

    core.main.main()

    mock_logger.setLevel.assert_called_once_with("WARNING")
    mock_service_manager.start_services.assert_called_once()
    mock_service_manager.stop_services.assert_called_once()
