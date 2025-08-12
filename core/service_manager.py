from core.connection_listener import start_connection_listener
from core.container_handler import start_container_handler
from logger.log_manager import LogManager
from core.thread_manager import ThreadManager
import time
import threading
from core.log_collector import LogCollector
from core.docker_log_collector import DockerLogCollector
from parsers.parser_factory import get_parser
from publishers.publisher_factory import get_publisher
from osint.osint_factory import OSINTServiceFactory  # aggiunto import OSINT

class ServiceManager:
    """
    Classe responsabile dell'inizializzazione, avvio e arresto
    dei componenti principali del sistema di raccolta e pubblicazione dei log.
    """
    def __init__(self) -> None:
        self.logger = LogManager.get_instance().get_logger()
        self.run_event = threading.Event()
        self.thread_manager = ThreadManager()
        self.services = {
            'osint_services': {},
            'publisher': None,
            'log_collectors': []
        }

    def initialize_services(self) -> bool:
        try:
            max_retries = 3
            retry_delay = 5
            publisher = None
            log_collectors = []
            publishers = {}
            
            api_keys = {
                "abuseipdb": "API_KEY_ABUSEIPDB",
                "shodan": "API_KEY_SHODAN",
                "virustotal": "API_KEY_VIRUSTOTAL"
            }
            for service_name, api_key in api_keys.items():
                service = OSINTServiceFactory.get_service(service_name, api_key)
                if service:
                    self.services['osint_services'][service_name] = service
                    self.logger.info(f"OSINT service initialized: {service_name}")
                else:
                    self.logger.warning(f"OSINT service not initialized: {service_name}")
            # --------------------------------------------------

            # Mappa: sorgente -> (parser_name, log_path)
            sources = {
                'cowrie':   ("cowrie",   "/opt/honeypot/logs/cowrie/cowrie.json", False),
                'apache':   ("apache",   "/opt/honeypot/logs/apache/access.log", False),
                'openldap': ("openldap", "/opt/honeypot/logs/openldap/openldap.log", False),
                'dionaea':  ("dionaea",  "/opt/honeypot/logs/dionaea/dionaea.log" , False)
            }

            # Connessione MQTT per ogni sorgente
            for name, (parser_name, path_or_container, is_docker) in sources.items():
                topic = f"honeypot/logs/{parser_name}"
                publisher = None
                for attempt in range(max_retries):
                    try:
                        publisher = get_publisher("mqtt", "46.62.130.53", topic)  # usa la factory qui
                        break
                    except Exception as e:
                        self.logger.warning(f"MQTT connection failed for {parser_name} (attempt {attempt + 1}): {e}")
                        time.sleep(retry_delay)

                if not publisher:
                    self.logger.error(f"Could not connect to MQTT broker for {parser_name}. Exiting.")
                    return False

                publishers[parser_name] = publisher

            # Inizializza log collectors
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

            self.services['publisher'] = publisher
            self.services['log_collectors'] = log_collectors
            return True

        except Exception:
            self.logger.exception("Service initialization failed")
            return False

    def start_services(self) -> bool:
        try:
            self.run_event.set()

            #self.thread_manager.run_thread(start_connection_listener, args=(self.run_event,))
            #self.thread_manager.run_thread(start_container_handler, args=(self.run_event,))

            log_collectors = self.services.get('log_collectors', [])
            for name, collector in log_collectors:
                self.thread_manager.run_thread(collector.start)
                self.logger.info(f"{name.capitalize()} LogCollector started")

            self.logger.info("All services started.")
            return True

        except Exception:
            self.logger.exception("Failed to start services")
            return False

    def stop_services(self) -> None:
        self.logger.info("Shutting down services...")
        self.run_event.clear()

        for name, collector in self.services.get('log_collectors', []):
            collector.stop()

        self.thread_manager.wait_all()
        self.logger.info("All services stopped.")
