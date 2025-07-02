from logger.log_manager import LogManager
from core.thread_manager import ThreadManager
from parsers.parser_factory import get_parser
from publishers.mqtt_publisher import MqttPublisher
from core.log_collector import LogCollector
import threading
import time
from core.service_manager import ServiceManager
from config.environment_config import ask_log_level


def main():
    level = ask_log_level()
    LogManager.get_instance().get_logger().setLevel(level)
    service_manager = ServiceManager()

    if not service_manager.initialize_services():
        return

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
