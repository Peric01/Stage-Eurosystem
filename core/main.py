from logger.log_manager import LogManager
from core.thread_manager import ThreadManager
from parsers.parser_factory import get_parser
from publishers.mqtt_publisher import MqttPublisher
from core.log_collector import LogCollector
import threading
import time
from core.connection_listener import start_connection_listener
from core.container_handler import start_container_handler

class ServiceManager:
    def __init__(self):
        self.logger = LogManager.get_instance().get_logger()
        self.run_event = threading.Event()
        self.thread_manager = ThreadManager()
        self.services = {}

    def initialize_services(self):
        try:
            parser = get_parser("cowrie")

            max_retries = 3
            retry_delay = 5
            publisher = None

            for attempt in range(max_retries):
                try:
                    publisher = MqttPublisher("localhost", "honeypot/logs")
                    break
                except Exception as e:
                    self.logger.warning(f"MQTT connection failed (attempt {attempt + 1}): {e}")
                    time.sleep(retry_delay)

            if not publisher:
                self.logger.error("Could not connect to MQTT broker. Exiting.")
                return False

            log_collector = LogCollector(self.logger, parser, publisher)

            self.services = {
                'parser': parser,
                'publisher': publisher,
                'log_collector': log_collector
            }
            return True

        except Exception:
            self.logger.exception("Service initialization failed")
            return False

    def start_services(self):
        try:
            self.run_event.set()

            self.thread_manager.run_thread(start_connection_listener, args=(self.run_event,))
            self.thread_manager.run_thread(start_container_handler, args=(self.run_event,))

            log_collector = self.services.get('log_collector')
            if log_collector:
                self.thread_manager.run_thread(log_collector.start)
            else:
                self.logger.warning("LogCollector not initialized")

            self.logger.info("All services started.")
            return True

        except Exception:
            self.logger.exception("Failed to start services")
            return False

    def stop_services(self):
        self.logger.info("Shutting down services...")
        self.run_event.clear()

        if self.services.get('log_collector'):
            self.services['log_collector'].stop()

        self.thread_manager.wait_all()
        self.logger.info("All services stopped.")

def main():
    service_manager = ServiceManager()

    if not service_manager.initialize_services():
        return

    try:
        service_manager.start_services()
        while service_manager.run_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        service_manager.stop_services()

if __name__ == "__main__":
    main()
