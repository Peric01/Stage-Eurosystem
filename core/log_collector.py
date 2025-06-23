# log_collector.py
import threading
import time
from typing import List
from logger.log_manager import LogManager
from parsers.base_parser import InterfaceLogParser
from publishers.base_publisher import InterfaceDataPublisher

class LogCollector:
    """
    Collects, parses, and dispatches logs from various sources.
   
    Args:
        logger: Logger instance for logging messages
        parser: Parser implementing InterfaceLogParser for parsing raw logs
        dispatcher: Dispatcher implementing InterfaceDataPublisher for publishing parsed logs
    """
   
    def __init__(self, logger, parser: InterfaceLogParser, dispatcher: InterfaceDataPublisher):
        self.logger = logger
        self.parser = parser
        self.dispatcher = dispatcher
        self._run_event = threading.Event()
       
    def start(self):
        """Starts the log collection process in a background thread."""
        self._run_event.set()
        threading.Thread(target=self._collect_loop, daemon=True).start()
        self.logger.info("Log collector started")
       
    def stop(self):
        """Stops the log collection process."""
        self._run_event.clear()
        self.logger.info("Log collector stopping")
       
    def _collect_loop(self):
        """Main collection loop that runs in a background thread."""
        try:
            while self._run_event.is_set():
                self.collect_logs()
                time.sleep(2)  # Interval between collection attempts
        except Exception as e:
            self.logger.exception("Error in log collection loop")
           
    def collect_logs(self):
        """Collects logs from sources, parses them, and dispatches them."""
        # In a real implementation, this would read from actual log sources
        # For now, we'll use fake logs as per your example
        fake_logs = self._generate_fake_logs()
       
        for raw_log in fake_logs:
            try:
                self.logger.debug(f"Processing raw log: {raw_log}")
                parsed = self.parser.parse(raw_log)
                if parsed and not parsed.get('error'):
                    self.dispatcher.publish(parsed)
                    self.logger.info(f"Successfully processed log: {parsed.get('event', 'unknown')}")
            except Exception as e:
                self.logger.error(f"Failed to process log: {raw_log}", exc_info=True)
               
    def _generate_fake_logs(self) -> List[str]:
        """Generates example logs for demonstration purposes."""
        return [
            '{"timestamp": "2023-01-01T12:00:00", "eventid": "cowrie.login", "src_ip": "1.2.3.4", "message": "login attempt"}',
            '{"timestamp": "2023-01-01T12:01:00", "eventid": "cowrie.command", "src_ip": "5.6.7.8", "message": "executed command", "command": "whoami"}',
            '{"timestamp": "2023-01-01T12:02:00", "eventid": "cowrie.session", "src_ip": "9.10.11.12", "message": "session opened", "session": "abc123"}',
            'invalid log entry',  # This will test error handling
        ]

def start_log_collector(run_event: threading.Event, parser: InterfaceLogParser, publisher: InterfaceDataPublisher):
    """
    Convenience function to start the log collector with default dependencies.
   
    Args:
        run_event: Event to control the collector's execution
        parser: Parser to use for log processing
        publisher: Publisher to use for dispatching logs
    """
    logger = LogManager.get_instance().get_logger()
    collector = LogCollector(logger, parser, publisher)
   
    try:
        collector.start()
        while run_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        collector.stop()