import threading
import docker
from parsers.base_parser import InterfaceLogParser
from publishers.base_publisher import InterfaceDataPublisher
from logger.log_manager import LogManager
from datetime import datetime

class DockerLogCollector:
    """
    Colleziona i log direttamente dal container Docker (stdout/stderr).
    """

    def __init__(self, logger, container_name: str, parser: InterfaceLogParser, publisher: InterfaceDataPublisher):
        self.logger = logger
        self.container_name = container_name
        self.parser = parser
        self.publisher = publisher
        self._run_event = threading.Event()
        self.client = docker.from_env()

    def start(self):
        self._run_event.set()
        threading.Thread(target=self._collect_loop, daemon=True).start()
        self.logger.info(f"DockerLogCollector for '{self.container_name}' started.")

    def stop(self):
        self._run_event.clear()
        self.logger.info(f"DockerLogCollector for '{self.container_name}' stopping...")

    def _collect_loop(self):
        try:
            container = self.client.containers.get(self.container_name)
            start_time = int(datetime.now().timestamp())
            for log_line in container.logs(stream=True, follow=True, since=start_time):
                if not self._run_event.is_set():
                    break
                line = log_line.decode("utf-8").strip()
                self.logger.debug(f"[{self.container_name}] Raw log: {line}")
                try:
                    parsed = self.parser.parse(line)
                    self.logger.debug(f"[{self.container_name}] Parsed log: {parsed}")
                    #if parsed:
                    #    self.publisher.publish(parsed)
                    #    self.logger.info(f"[{self.container_name}] Published event: {parsed.get('event', 'unknown')}")
                except Exception as e:
                    self.logger.error(f"Error processing log from {self.container_name}: {e}", exc_info=True)

        except Exception as e:
            self.logger.error(f"Failed to stream logs from {self.container_name}: {e}", exc_info=True)