# connection_listener.py
import threading
import time
from logger.log_manager import LogManager

def start_connection_listener(run_event: threading.Event):
    """
    Listens to incoming connections from open sockets and dummy services.
   
    Args:
        run_event: A threading.Event to control the execution loop
    """
    logger = LogManager.get_instance().get_logger()
    logger.info('Connection listener starting...')
   
    try:
        while run_event.is_set():
            # Main listener logic would go here
            # For now, just log periodically to show it's running
            logger.debug("Connection listener active - checking for connections")
            time.sleep(5)
           
    except Exception as e:
        logger.exception("Connection listener encountered an error")
    finally:
        logger.info("Connection listener shutting down")