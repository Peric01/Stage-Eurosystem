import logging

class CustomFormatter(logging.Formatter):
    '''Classe utilizzata per effettuare l'override del format base del logger
    tramite colorazioni diverse in base al tipo di log e informazioni aggiuntive rispetto al format base
    '''
    
    #Sequenze ANSI per i colori
    cyan = "\x1b[36;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    blue = "\x1b[34;20m"
    magenta = "\x1b[35;20m"
    bold_cyan = "\x1b[36;1m"
    bold_yellow = "\x1b[33;1m"
    bold_red = "\x1b[31;1m"
    bold_blue = "\x1b[34;1m"
    bold_magenta = "\x1b[35;1m"
    reset = "\x1b[0m"

    #Informazioni dei log da rappresentare
    log_timestamp = "%(asctime)s"
    message_location_log = "%(message)s [%(filename)s:%(lineno)d]"
    dangerous_log_info = "%(exc_info)s"

    #Dizionario dei livelli di log
    FORMATS = {
        logging.DEBUG: cyan + log_timestamp + bold_cyan + " | %(levelname)s | " + reset + cyan + message_location_log + reset,
        logging.INFO: blue + log_timestamp + bold_blue + " | %(levelname)s | " + reset + blue + message_location_log + reset,
        logging.WARNING: yellow + log_timestamp + bold_yellow + " | %(levelname)s | " + reset + yellow + message_location_log + reset,
        logging.ERROR: red + log_timestamp + bold_red + " | %(levelname)s | " + reset + red + message_location_log + "\n" + dangerous_log_info + reset,
        logging.CRITICAL: bold_magenta + log_timestamp + " | %(levelname)s | " + message_location_log + "\n" + magenta + dangerous_log_info + reset,
    }

    def format(self, record):
        '''
        Override del metodo format per applicare il formato personalizzato
        basato sul livello del record di log.

        Se il record contiene un'eccezione, il messaggio viene esteso con
        le informazioni dell'eccezione formattata.
        '''
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        if record.exc_info:
            record.message = f"{record.getMessage()}\n{self.formatException(record.exc_info)}"
        return formatter.format(record)