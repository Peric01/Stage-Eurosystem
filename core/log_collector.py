import threading
import time
from typing import List
from logger.log_manager import LogManager
from parsers.base_parser import InterfaceLogParser
from publishers.base_publisher import InterfaceDataPublisher

class LogCollector:
    """
    Collects, parses, and dispatches logs from various sources.
    Reads only newly appended lines (like tail -f).
    """

    def __init__(self, logger, parser: InterfaceLogParser, publisher: InterfaceDataPublisher, log_path: str) -> None:
        self.logger = logger
        self.parser = parser
        self.publisher = publisher
        self.log_path = log_path
        self._run_event = threading.Event()
        self._file = None  # Per tenere traccia del file aperto

    def start(self) -> None:
        """Starts the log collection process in a background thread."""
        self._run_event.set()
        try:
            self._file = open(self.log_path, 'r')
            self._file.seek(0, 2)  # Vai alla fine del file (come tail -f)
        except Exception as e:
            self.logger.error(f"Could not open log file: {e}")
            return

        self.logger.info("LogCollector started.")
        self._collect_loop()

    def stop(self) -> None:
        """Stops the log collection process."""
        self._run_event.clear()
        if self._file:
            try:
                self._file.close()
            except Exception as e:
                self.logger.warning(f"Error closing file: {e}")
        self.logger.info("LogCollector stopping...")

    def _collect_loop(self) -> None:
        """Main collection loop that runs in a background thread."""
        try:
            while self._run_event.is_set():
                self.collect_logs()
                time.sleep(2)  # pragma: no cover
        except Exception as e:
            self.logger.exception("Unexpected error in log collection loop")

    def collect_logs(self) -> None:
        """Reads, parses, and dispatches newly appended log lines."""
        raw_logs = self._read_from_source()

        for raw_log in raw_logs:
            self.logger.debug(f"Raw log received: {raw_log}")
            try:
                parsed = self.parser.parse(raw_log)
                self.logger.debug(f"Parsed log: {parsed}")
                if parsed:
                    self.publisher.publish(parsed)
                    self.logger.info(f"Published event: {parsed.get('event', 'unknown')}")
            except Exception as e:
                self.logger.error(f"Error during log processing: {e}", exc_info=True)

    def _read_from_source(self) -> List[str]:
        """Reads new lines added to the file since the last read."""
        logs = []
        try:
            while True:
                line = self._file.readline()
                if not line:
                    break
                logs.append(line.strip())
        except Exception as e:
            self.logger.error(f"Failed reading new log lines: {e}")

        return logs