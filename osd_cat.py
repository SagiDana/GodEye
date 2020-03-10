import subprocess
from threading import Lock
from time import sleep

class Osd:
    def __init__(self): 
        self.proc = None
        self.lock = Lock()

    def open(self):
        if self.proc: self.close()

        self.proc = subprocess.Popen([
                        "osd_cat",
                        "--age=1",
                        "--delay=5",
                        "--lines=50",
                        "--align=right",
                        "--indent=400",
                        "--pos=middle",
                        "--color=grey",
                        # "--font=",
                        "-",
                    ],
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE)

    def display(self, text):
        if not self.proc: return

        with self.lock:
            self.proc.stdin.write(text.encode())
            self.proc.stdin.flush()
            sleep(1)

    def close(self):
        if not self.proc: return

        self.proc.communicate()

        self.proce = None

if __name__ == "__main__":
    osd = Osd()
    osd.open()

    for i in range(100):
        osd.display("ashdas\n")

    osd.close()
