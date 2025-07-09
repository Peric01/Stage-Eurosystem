from core.connection_listener import start_connection_listener
from core.container_handler import start_container_handler
from logger.log_manager import LogManager
from core.thread_manager import ThreadManager
import time
import threading
from core.log_collector import LogCollector
from core.docker_log_collector import DockerLogCollector
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
        try:
            max_retries = 3
            retry_delay = 5
            publisher = None
            log_collectors = []
            publishers = {}
            # Mappa: sorgente -> (parser_name, log_path)
            sources = {
                            #'cowrie':   ("cowrie",   "/var/lib/docker/containers/26f9f9ed1d8cb4e7146e66190b1f6433f29e605af78a497f485dcb252a6f90a0/26f9f9ed1d8cb4e7146e66190b1f6433f29e605af78a497f485dcb252a6f90a0-json.log", False),
                            #'apache':   ("apache",   "/var/lib/docker/containers/71e33be57c278a945262974fd87f5b3c9285591a62cfb2e6f0fb06d67fa4ede3/71e33be57c278a945262974fd87f5b3c9285591a62cfb2e6f0fb06d67fa4ede3-json.log", False),
                            'openldap': ("openldap", "/var/lib/docker/containers/14d00ea249268b8a278c1816145914549f2addb972b86004a4ea3d6282a80750/14d00ea249268b8a278c1816145914549f2addb972b86004a4ea3d6282a80750-json.log", False),
                            #'dionaea':  ("dionaea", "/var/lib/docker/containers/20181f677794a874fcb88fa7691b392ee68b7fddbd6bb0da5a52be4a4708d0fc/20181f677794a874fcb88fa7691b392ee68b7fddbd6bb0da5a52be4a4708d0fc-json.log" , False)
                        }

            for name, (parser_name, path_or_container, is_docker) in sources.items():
                topic = f"honeypot/logs/{parser_name}"
                publisher = None
                for attempt in range(max_retries):
                    try:
                        publisher = MqttPublisher("46.62.130.53", topic)
                        break
                    except Exception as e:
                        self.logger.warning(f"MQTT connection failed for {parser_name} (attempt {attempt + 1}): {e}")
                        time.sleep(retry_delay)

                if not publisher:
                    self.logger.error(f"Could not connect to MQTT broker for {parser_name}. Exiting.")
                    return False

                publishers[parser_name] = publisher

            for name, (parser_name, path_or_container, is_docker) in sources.items():
                try:
                    parser = get_parser(parser_name)
                    publisher = publishers[parser_name]
                    if is_docker:
                        collector = DockerLogCollector(self.logger, path_or_container, parser, publisher)
                    else:
                        collector = LogCollector(self.logger, parser, publisher, path_or_container)
                    log_collectors.append((name, collector))
                    self.logger.info(f"Initialized log collector for {name}")
                except Exception as e:
                    self.logger.error(f"Failed to initialize collector for {name}: {e}")

            self.services = {
                'publisher': publisher,
                'log_collectors': log_collectors
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

            log_collectors = self.services.get('log_collectors', [])
            for name, collector in log_collectors:
                self.thread_manager.run_thread(collector.start)
                self.logger.info(f"{name.capitalize()} LogCollector started")

            self.logger.info("All services started.")
            return True

        except Exception:
            self.logger.exception("Failed to start services")
            return False

    def stop_services(self):
        self.logger.info("Shutting down services...")
        self.run_event.clear()

        for name, collector in self.services.get('log_collectors', []):
            collector.stop()

        self.thread_manager.wait_all()
        self.logger.info("All services stopped.")