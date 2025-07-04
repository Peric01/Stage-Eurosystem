import threading
import time
from typing import List, Optional
from logger.log_manager import LogManager
from parsers.base_parser import InterfaceLogParser
from publishers.base_publisher import InterfaceDataPublisher

class LogCollector:
    """
    Collects, parses, and dispatches logs from various sources.
    """

    def __init__(self, logger, parser: InterfaceLogParser, publisher: InterfaceDataPublisher, log_path: str):
        self.logger = logger
        self.parser = parser
        self.publisher = publisher
        self.log_path = log_path
        self._run_event = threading.Event()

    def start(self):
        """Starts the log collection process in a background thread."""
        self._run_event.set()
        threading.Thread(target=self._collect_loop, daemon=True).start()
        self.logger.info("LogCollector started.")

    def stop(self):
        """Stops the log collection process."""
        self._run_event.clear()
        self.logger.info("LogCollector stopping...")

    def _collect_loop(self):
        """Main collection loop that runs in a background thread."""
        try:
            while self._run_event.is_set():
                self.collect_logs()
                time.sleep(2)
        except Exception as e:
            self.logger.exception("Unexpected error in log collection loop")

    def collect_logs(self):
        """Reads, parses, and dispatches logs from source."""
        raw_logs = self._read_from_source()

        for raw_log in raw_logs:
            self.logger.debug(f"Raw log received: {raw_log}")
            try:
                parsed = self.parser.parse(raw_log)
                if parsed is not None:
                    self.publisher.publish(parsed)
                    for entry in parsed:
                        self.logger.info(f"Published event: {entry.get('type', 'unknown')}")
                else:
                    self.logger.warning("Parsed log is None - skipped")
            except Exception as e:
                self.logger.error(f"Error during log processing: {e}", exc_info=True)

    def _read_from_source(self) -> List[str]:
        logs = []
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
                logs.extend([line.strip() for line in lines if line.strip()])
        except Exception as e:
            self.logger.error(f"Failed to read log file at {self.log_path}: {e}")

        return logs

