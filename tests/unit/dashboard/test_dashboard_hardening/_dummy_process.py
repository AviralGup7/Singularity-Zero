class DummyProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.pid = 4242

    def terminate(self) -> None:
        self.terminated = True
