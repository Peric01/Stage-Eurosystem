from logger.log_manager import LogManager
from core.thread_manager import ThreadManager
from parsers.parser_factory import get_parser
from publishers.mqtt_publisher import MqttPublisher
from core.log_collector import LogCollector
import threading
import time
from core.connection_listener import start_connection_listener
from core.container_handler import start_container_handler

class ServiceManager:
    def __init__(self):
        self.logger = LogManager.get_instance().get_logger()
        self.run_event = threading.Event()
        self.thread_manager = ThreadManager()
        self.services = {}
       
    def initialize_services(self):
        """Initialize all service components with proper error handling"""
        try:
            # Initialize parser
            parser = get_parser("cowrie")
           
            # Initialize MQTT publisher with retry logic
            max_retries = 3
            retry_delay = 5
            publisher = None
           
            for attempt in range(max_retries):
                try:
                    publisher = MqttPublisher("localhost", "honeypot/logs")
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        self.logger.warning(f"MQTT connection attempt {attempt + 1} failed. Retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                    else:
                        self.logger.error("Failed to connect to MQTT broker after multiple attempts. Running in offline mode.")
                        publisher = None  # Or use a NullPublisher implementation
           
            # Create log collector instance
            log_collector = LogCollector(self.logger, parser, publisher) if publisher else None
           
            self.services = {
                'parser': parser,
                'publisher': publisher,
                'log_collector': log_collector
            }
            return True
           
        except Exception as e:
            self.logger.exception("Failed to initialize services")
            return False

    def start_services(self):
        """Start all services with proper error handling"""
        try:
            self.run_event.set()
           
            # Start connection listener and container handler
            self.thread_manager.run_thread(start_connection_listener, args=(self.run_event,))
            self.thread_manager.run_thread(start_container_handler, args=(self.run_event,))
           
            # Start log collector if initialized successfully
            if self.services.get('log_collector'):
                self.thread_manager.run_thread(self.services['log_collector'].start)
            else:
                self.logger.warning("Log collector not started due to initialization issues")
           
            self.logger.info("All available services started. Press Ctrl+C to stop.")
            return True
           
        except Exception as e:
            self.logger.exception("Failed to start services")
            return False

    def stop_services(self):
        """Stop all services gracefully"""
        self.logger.info("Shutting down services...")
        self.run_event.clear()
       
        if self.services.get('log_collector'):
            self.services['log_collector'].stop()
           
        self.thread_manager.wait_all()
        self.logger.info("All services stopped.")

def main():
    service_manager = ServiceManager()
   
    if not service_manager.initialize_services():
        return
   
    try:
        service_manager.start_services()
       
        # Main loop
        while service_manager.run_event.is_set():
            time.sleep(1)
           
    except KeyboardInterrupt:
        pass
    finally:
        service_manager.stop_services()

if __name__ == "__main__":
    main()