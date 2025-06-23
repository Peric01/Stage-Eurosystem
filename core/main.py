from core.service_manager import ServiceManager
import time

def main():
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
