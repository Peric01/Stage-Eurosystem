from logger.log_manager import LogManager
import time
from core.service_manager import ServiceManager
from config.environment_config import ask_log_level
import sys
import threading

def monitor_threads(interval=30):
    """Stampa i thread attivi ogni 'interval' secondi per debug."""
    while True:
        active_threads = threading.enumerate()
        print(f"[Thread Monitor] Active threads ({len(active_threads)}): {[t.name for t in active_threads]}")
        time.sleep(interval)

def main():
    cli_choice = sys.argv[1] if len(sys.argv) > 1 else None

    level = ask_log_level(cli_choice)
    LogManager.get_instance().get_logger().setLevel(level)

    service_manager = ServiceManager()

    if not service_manager.initialize_services():
        return

    # Avvia il thread di monitoraggio dei thread
    threading.Thread(target=monitor_threads, daemon=True, name="ThreadMonitor").start()

    try:
        service_manager.start_services()
        while service_manager.run_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        service_manager.stop_services()

if __name__ == "__main__":
    main()