import logging
from logger.custom_formatter import CustomFormatter

class LogManager:
    '''
    Singleton per la gestione di un logger centralizzato

    Questa classe crea un'istanza unica di un logger chiaato "LogSystem"
    configurato con livello DEBUG e un handler di tipo StreamHandler che 
    stampa i messaggi in console con un formato personalizzato (CustomFormatter)

    '''
    _instance = None

    def __init__(self):
        self.logger = logging.getLogger("LogSystem")
        self.logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setFormatter(CustomFormatter())
        self.logger.addHandler(ch)

    @classmethod
    def get_instance(cls):
        '''
        Restituisce l'istanza singleton di LogManager

        Se l'istanza non esiste, la crea chiamando il costruttore
        '''
        if cls._instance is None:
            cls._instance = LogManager()
        return cls._instance
    
    def get_logger(self):
        '''
        Restituisce il logger configurato per scrivere i messaggi di log
        '''
        return self.logger