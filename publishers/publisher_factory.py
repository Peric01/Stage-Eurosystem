from .mqtt_publisher import MqttPublisher
from .base_publisher import InterfaceDataPublisher

'''
Factory per la creazione di publisher in base al tipo richiesto.

La factory consente di istanziare il publisher corretto in modo dinamico
senza dover scrivere il codice di una classe specifica nel codice di alto livello.
'''

def get_publisher(name: str, address: str, topic: str) -> InterfaceDataPublisher:
    if name.lower() == "mqtt":
        return MqttPublisher(address, topic)
    else:
        raise ValueError(f"No publisher found for {name}")