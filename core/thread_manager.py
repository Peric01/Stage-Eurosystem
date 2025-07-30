import threading

class ThreadManager:
    '''
    Classe che gestisce i thread per l'esecuzione di operazioni concorrenti.
    '''
    def __init__(self) -> None:
        self.threads = []
    
    def run_thread(self, target, args = ()) -> None:
        t = threading.Thread(target=target, args=args)
        t.start()
        self.threads.append(t)

    def wait_all(self) -> None:
        for t in self.threads:
            t.join()