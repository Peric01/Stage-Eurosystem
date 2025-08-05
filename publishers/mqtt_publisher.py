from publishers.base_publisher import InterfaceDataPublisher
import paho.mqtt.client as mqtt
import json
from logger.log_manager import LogManager
import ssl  # Needed for TLS

class MqttPublisher(InterfaceDataPublisher):
    '''
    Publisher che invia log strutturati a un broker MQTT.
    '''

    def __init__(self, broker_address: str, topic: str, port: int = 8883) -> None:
        '''
        Inizializza il publisher MQTT.

        :param broker_address: Indirizzo del broker MQTT.
        :param topic: Topic MQTT su cui pubblicare i messaggi.
        :param port: Porta del broker MQTT (default 8883 con SSL).
        '''

        self.broker_address = broker_address
        self.topic = topic
        self.port = port
        self.client = mqtt.Client()
        self.logger = LogManager.get_instance().get_logger()

        try:
            self.client.tls_set(
                ca_certs="/opt/honeypot/certs/ca.crt",
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLSv1_2
            )

            self.logger.debug(f"Connecting to MQTT broker at {self.broker_address}:{self.port} with TLS on topic '{self.topic}'")
            self.client.connect(self.broker_address, self.port)
            self.logger.debug("MQTT TLS connection established, starting loop")
            self.client.loop_start()
            self.logger.debug("MQTT loop started")
            self.logger.info(f"MQTT (TLS) connected to {self.broker_address}:{self.port} on topic '{self.topic}'")
        except Exception as e:
            self.logger.error(f"Failed to connect to MQTT broker over TLS: {e}")

    def publish(self, log: dict) -> None:
        '''
        Pubblica un dizionario JSON come stringa sul topic MQTT specificato.
        '''
        try:
            payload = json.dumps(log)
            self.client.publish(self.topic, payload)
            self.logger.debug(f"MQTT published log to '{self.topic}': {payload}")
        except Exception as e:
            self.logger.exception(f"Failed to publish log to MQTT: {e}")
