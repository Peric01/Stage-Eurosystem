# service_manager.py

from core.log_collector import LogCollector
from publishers.mqtt_publisher import MqttPublisher
from parsers.cowrie_parser import CowrieParser
from logger.log_manager import LogManager


class ServiceManager:
    """
    Classe responsabile dell'inizializzazione, avvio e arresto
    dei componenti principali del sistema di raccolta e pubblicazione dei log.
    """

    def __init__(self):
        self.logger = LogManager.get_instance().get_logger()
        self.collector = None

    def start_services(self):
        """
        Avvia tutti i servizi necessari: parser, publisher e log collector.
        """
        self.logger.info("Avvio dei servizi...")
        try:
            parser = CowrieParser()
            publisher = MqttPublisher()
            self.collector = LogCollector(parser, publisher)
            self.collector.start()
            self.logger.info("Servizi avviati con successo.")
        except Exception as e:
            self.logger.error(f"Errore durante l'avvio dei servizi: {e}")

    def stop_services(self):
        """
        Interrompe i servizi attivi in modo sicuro.
        """
        self.logger.info("Arresto dei servizi...")
        try:
            if self.collector:
                self.collector.stop()
                self.logger.info("Servizi arrestati correttamente.")
            else:
                self.logger.warning("Nessun servizio da arrestare.")
        except Exception as e:
            self.logger.error(f"Errore durante l'arresto dei servizi: {e}")
