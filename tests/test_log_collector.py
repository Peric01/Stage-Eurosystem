import pytest
from unittest.mock import MagicMock, mock_open, patch
from core.log_collector import LogCollector

@pytest.fixture
def setup_collector():
    mock_logger = MagicMock()
    mock_parser = MagicMock()
    mock_publisher = MagicMock()
    mock_osint = MagicMock()
    collector = LogCollector(mock_logger, mock_parser, mock_publisher, "dummy.log", mock_osint)
    return collector, mock_logger, mock_parser, mock_publisher

@patch("builtins.open", new_callable=mock_open, read_data="line1\nline2\n")
def test_start_success(mock_file, setup_collector):
    collector, logger, _, _ = setup_collector
    collector._collect_loop = MagicMock()

    collector.start()

    mock_file.assert_called_with("dummy.log", "r")
    assert collector._file is not None
    collector._collect_loop.assert_called_once()
    logger.info.assert_called_with("LogCollector started.")

@patch("builtins.open", side_effect=Exception("open error"))
def test_start_file_open_error(mock_file, setup_collector):
    collector, logger, _, _ = setup_collector

    collector.start()

    logger.error.assert_called_with("Could not open log file: open error")

def test_stop_success(setup_collector):
    collector, logger, *_ = setup_collector
    mock_file = MagicMock()
    collector._file = mock_file

    collector.stop()

    mock_file.close.assert_called_once()
    logger.info.assert_called_with("LogCollector stopping...")

def test_stop_with_close_exception(setup_collector):
    collector, logger, *_ = setup_collector
    mock_file = MagicMock()
    mock_file.close.side_effect = Exception("close error")
    collector._file = mock_file

    collector.stop()

    logger.warning.assert_called_with("Error closing file: close error")

def test_collect_logs_success(setup_collector):
    collector, logger, parser, publisher = setup_collector
    collector._read_from_source = MagicMock(return_value=["raw log line"])
    parser.parse.return_value = {"event": "test_event"}

    collector.collect_logs()

    logger.debug.assert_any_call("Raw log received: raw log line")
    logger.debug.assert_any_call("Parsed log: {'event': 'test_event'}")
    publisher.publish.assert_called_with({"event": "test_event"})

    # Controlla che almeno una chiamata info contenga "Published event"
    calls = [call.args[0] for call in logger.info.call_args_list]
    assert any("Published event" in msg for msg in calls)


def test_collect_logs_parser_error(setup_collector):
    collector, logger, parser, publisher = setup_collector
    collector._read_from_source = MagicMock(return_value=["bad log"])
    parser.parse.side_effect = Exception("parse error")

    collector.collect_logs()

    logger.error.assert_called()
    publisher.publish.assert_not_called()

def test_read_from_source_success(setup_collector):
    collector, logger, *_ = setup_collector
    mock_file = MagicMock()
    mock_file.readline.side_effect = ["line1\n", "line2\n", ""]
    collector._file = mock_file

    result = collector._read_from_source()

    assert result == ["line1", "line2"]
    logger.error.assert_not_called()

def test_read_from_source_exception(setup_collector):
    collector, logger, *_ = setup_collector
    mock_file = MagicMock()
    mock_file.readline.side_effect = Exception("read error")
    collector._file = mock_file

    result = collector._read_from_source()

    assert result == []
    logger.error.assert_called_with("Failed reading new log lines: read error")

def test_collect_loop_handles_exception(setup_collector):
    collector, logger, *_ = setup_collector
    collector._run_event.set()
    collector.collect_logs = MagicMock(side_effect=Exception("unexpected error"))

def test_collect_loop_with_exception(setup_collector):
    collector, logger, *_ = setup_collector
    collector._run_event.set()
    
    # La prima chiamata a collect_logs lancia un'eccezione
    collector.collect_logs = MagicMock(side_effect=Exception("unexpected error"))

    collector._collect_loop()

    logger.exception.assert_called_with("Unexpected error in log collection loop")

