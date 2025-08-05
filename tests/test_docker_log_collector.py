import time
import pytest
from unittest.mock import MagicMock, patch
from core.docker_log_collector import DockerLogCollector


# Fixture che crea un DockerLogCollector con docker.from_env patchato
@pytest.fixture
@patch("core.docker_log_collector.docker.from_env")
def setup_collector(mock_from_env):
    mock_docker_client = MagicMock()
    mock_from_env.return_value = mock_docker_client

    mock_logger = MagicMock()
    mock_parser = MagicMock()
    mock_publisher = MagicMock()

    collector = DockerLogCollector(mock_logger, "test_container", mock_parser, mock_publisher)
    return collector, mock_logger, mock_parser, mock_publisher, mock_docker_client


def test_start_and_stop(setup_collector):
    collector, logger, *_ = setup_collector

    collector.start()
    time.sleep(0.1)  # Lascia partire il thread

    assert collector._run_event.is_set()
    logger.info.assert_called_with("DockerLogCollector for 'test_container' started.")

    collector.stop()
    assert not collector._run_event.is_set()
    logger.info.assert_called_with("DockerLogCollector for 'test_container' stopping...")


def test_collect_loop_success(setup_collector):
    collector, logger, parser, _, mock_docker_client = setup_collector

    mock_container = MagicMock()
    mock_container.logs.return_value = iter([b'log1\n', b'log2\n'])
    mock_docker_client.containers.get.return_value = mock_container

    parser.parse.side_effect = [{"event": "e1"}, {"event": "e2"}]

    collector._run_event.set()
    collector._collect_loop()

    logger.debug.assert_any_call("[test_container] Raw log: log1")
    logger.debug.assert_any_call("[test_container] Raw log: log2")
    assert parser.parse.call_count == 2


def test_collect_loop_parser_exception(setup_collector):
    collector, logger, parser, _, mock_docker_client = setup_collector

    mock_container = MagicMock()
    mock_container.logs.return_value = iter([b'bad log\n'])
    mock_docker_client.containers.get.return_value = mock_container

    parser.parse.side_effect = Exception("parse error")

    collector._run_event.set()
    collector._collect_loop()

    logger.error.assert_called_with(
        "Error processing log from test_container: parse error",
        exc_info=True
    )


def test_collect_loop_container_exception(setup_collector):
    collector, logger, _, _, mock_docker_client = setup_collector

    mock_docker_client.containers.get.side_effect = Exception("container not found")

    collector._run_event.set()
    collector._collect_loop()

    logger.error.assert_called_with(
        "Failed to stream logs from test_container: container not found",
        exc_info=True
    )

def test_collect_loop_stops_when_run_event_is_cleared(setup_collector):
    collector, logger, parser, _, mock_docker_client = setup_collector

    # Simula log docker con più righe
    mock_container = MagicMock()
    mock_container.logs.return_value = iter([b'log1\n', b'log2\n'])
    mock_docker_client.containers.get.return_value = mock_container

    # Disattiva il run_event prima del ciclo
    collector._run_event.clear()

    collector._collect_loop()

    # Deve uscire prima di processare i log
    parser.parse.assert_not_called()
