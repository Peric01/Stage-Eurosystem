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
            level_name, level = "DEBUG", 10
            print("Nessuna scelta effettuata. Verrà utilizzato il livello di log predefinito: DEBUG\n")

        elif choice in level_map:
            level_name, level = level_map[choice]
            print(f"Livello di log impostato su: {level_name}\n")

        else:
            print("Scelta non valida. Verrà utilizzato il livello di log predefinito: DEBUG\n")
            level_name, level = "DEBUG", 10
        
        return level