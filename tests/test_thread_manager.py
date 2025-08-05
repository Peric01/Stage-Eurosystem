import time
import threading
from core.thread_manager import ThreadManager


def test_run_thread_starts_thread():
    manager = ThreadManager()
    result = []

    def worker():
        result.append("done")

    manager.run_thread(worker)
    manager.wait_all()  # Ensure the thread has completed

    assert result == ["done"]
    assert len(manager.threads) == 1
    assert isinstance(manager.threads[0], threading.Thread)
    assert not manager.threads[0].is_alive()


def test_wait_all_joins_threads():
    manager = ThreadManager()
    started = []

    def slow_worker():
        started.append(True)
        time.sleep(0.2)
        started.append(False)

    manager.run_thread(slow_worker)
    manager.wait_all()

    # After wait_all, both True and False should be present
    assert started == [True, False]
    assert len(manager.threads) == 1
