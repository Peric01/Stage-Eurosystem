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
        level = ask_log_level()
        self.logger = LogManager.get_instance().get_logger()
        self.logger.set_level(level)
        self.run_event = threading.Event()
        self.thread_manager = ThreadManager()
        self.services = {}

    def initialize_services(self):
        try:
            max_retries = 3
            retry_delay = 5
            publisher = None

            for attempt in range(max_retries):
                try:
                    publisher = MqttPublisher("46.62.130.53", "honeypot/logs")
                    break
                except Exception as e:
                    self.logger.warning(f"MQTT connection failed (attempt {attempt + 1}): {e}")
                    time.sleep(retry_delay)

            if not publisher:
                self.logger.error("Could not connect to MQTT broker. Exiting.")
                return False

            # Mappa: sorgente -> (parser_name, log_path)
            sources = {
                'cowrie':   ("cowrie",   "cowrie", True),
                #'apache':   ("apache",   "apache", True),
                #'openldap': ("openldap", "openldap", True),
                #'dionaea':  ("dionaea",  "dionaea", True)
            }

            log_collectors = []

            for name, (parser_name, path_or_container, is_docker) in sources.items():
                try:
                    parser = get_parser(parser_name)
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



def ask_log_level():
    print("Scegli il livello minimo di log:")
    print("1 - DEBUG")
    print("2 - INFO")
    print("3 - WARNING")
    print("Premi INVIO per utilizzare il livello predefinito: DEBUG")
    choice = input("Inserisci la tua scelta [1-3]: ").strip()

    level_map = {
        "1":("DEBUG", 10),
        "2":("INFO", 20),
        "3":("WARNING", 30)
    }

    if choice == "":
        level = "DEBUG", 10
        print("Nessuna scelta effettuata. Verrà utilizzato il livello di log predefinito: DEBUG\n")

    elif choice in level_map:
        level_name, level = level_map[choice]
        print(f"Livello di log impostato su: {level_name}\n")

    else:
        print("Scelta non valida. Verrà utilizzato il livello di log predefinito: DEBUG\n")
        level = "DEBUG", 10
    
    return level