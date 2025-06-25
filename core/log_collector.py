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

    def __init__(self, logger, parser: InterfaceLogParser, publisher: InterfaceDataPublisher):
        self.logger = logger
        self.parser = parser
        self.publisher = publisher
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
                    self.dispatcher.publish(parsed)
                    self.logger.info(f"Published event: {parsed.get('event', 'unknown')}")
                else:
                    self.logger.warning("Parsed log is None - skipped")
            except Exception as e:
                self.logger.error(f"Error during log processing: {e}", exc_info=True)

    def _read_from_source(self) -> List[str]:
        """
        Reads raw logs from the actual log source.
        This mock version returns static logs.
        Replace this with real input (e.g., tailing a file, socket listener).
        """
        return [
            #'{"timestamp": "2023-01-01T12:00:00", "eventid": "cowrie.login", "src_ip": "1.2.3.4", "message": "login attempt"}',
            #'{"timestamp": "2023-01-01T12:01:00", "eventid": "cowrie.command", "src_ip": "5.6.7.8", "message": "executed command", "command": "whoami"}',
            #'{"timestamp": "2023-01-01T12:02:00", "eventid": "cowrie.session", "src_ip": "9.10.11.12", "message": "session opened", "session": "abc123"}',
            #'INVALID_JSON_ENTRY'  # Will trigger JSONDecodeError
        ]
