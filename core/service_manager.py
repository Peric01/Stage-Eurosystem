from core.connection_listener import start_connection_listener
from core.container_handler import start_container_handler
from logger.log_manager import LogManager
from core.thread_manager import ThreadManager
import time
import threading
from core.log_collector import LogCollector
from parsers.parser_factory import get_parser
from publishers.mqtt_publisher import MqttPublisher

class ServiceManager:
    """
    Classe responsabile dell'inizializzazione, avvio e arresto
    dei componenti principali del sistema di raccolta e pubblicazione dei log.
    """
    def __init__(self):
        self.logger = LogManager.get_instance().get_logger()
        self.run_event = threading.Event()
        self.thread_manager = ThreadManager()
        self.services = {}

    def initialize_services(self):
        """
        Inizializza i servizi senza avviarli subito.
        """
        try:
            parser = get_parser("cowrie")

            max_retries = 3
            retry_delay = 5
            publisher = None

            for attempt in range(max_retries):
                try:
                    publisher = MqttPublisher("127.0.0.1", "honeypot/logs") # Replace with actual broker address
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
        """
        Avvia i servizi inizializzati.
        """
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
        """
        Interrompe i servizi attivi in modo sicuro.
        """
        self.logger.info("Shutting down services...")
        self.run_event.clear()

        if self.services.get('log_collector'):
            self.services['log_collector'].stop()

        self.thread_manager.wait_all()
        self.logger.info("All services stopped.")