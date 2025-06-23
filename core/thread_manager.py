import threading

class ThreadManager:
    def __init__(self):
        self.threads = []
    
    def run_thread(self, target, args = ()):
        t = threading.Thread(target=target, args=args)
        t.start()
        self.threads.append(t)

    def wait_all(self):
        for t in self.threads:
            t.join()