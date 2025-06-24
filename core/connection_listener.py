import threading
import socket
import time
from logger.log_manager import LogManager

def handle_connection(client_socket, address, port, logger):
    """
    Gestisce una singola connessione.
    """
    logger.info(f"🔌 Connessione ricevuta da {address} sulla porta {port}")
    try:
        # Messaggio dummy per il client
        client_socket.sendall(b"Welcome to honeypot service.\n")
        time.sleep(1)
    except Exception as e:
        logger.error(f"Errore durante la comunicazione con {address} sulla porta {port}: {e}")
    finally:
        client_socket.close()
        logger.debug(f"Connessione con {address} chiusa.")

def listen_on_port(port, run_event: threading.Event, logger):
    """
    Apre una socket in ascolto sulla porta specificata.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen(5)
        logger.info(f"🟢 Listener attivo sulla porta {port}")

        server_socket.settimeout(1.0)  # Per poter controllare run_event periodicamente

        while run_event.is_set():
            try:
                client_socket, address = server_socket.accept()
                threading.Thread(
                    target=handle_connection,
                    args=(client_socket, address, port, logger),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Errore nella socket su porta {port}: {e}")

        logger.info(f"🔴 Listener sulla porta {port} terminato")

def start_connection_listener(run_event: threading.Event):
    """
    Avvia listener su più porte in thread separati.
    """
    logger = LogManager.get_instance().get_logger()
    logger.info("Avvio del Connection Listener su porte 21 e 2223")

    ports = [21, 2223]
    threads = []

    for port in ports:
        thread = threading.Thread(target=listen_on_port, args=(port, run_event, logger), daemon=True)
        thread.start()
        threads.append(thread)

    try:
        while run_event.is_set():
            time.sleep(1)
    except Exception as e:
        logger.exception("Errore nel Connection Listener")
    finally:
        logger.info("Connection Listener in arresto...")
        for thread in threads:
            thread.join()
