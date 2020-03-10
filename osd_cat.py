import subprocess
from time import sleep

class Osd:
    def __init__(self): 
        self.proc = None

    def open(self):
        if self.proc: self.close()

        self.proc = subprocess.Popen([
                        "osd_cat",
                        "--age=1",
                        "--delay=5",
                        "--lines=50",
                        "--align=right",
                        "--indent=40",
                        "--pos=middle",
                        "--color=white",
                        "--font=lucidasans-bold-10",
                        "-",
                    ],
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE)

    def display(self, text):
        if not self.proc: return

        self.proc.stdin.write(text.encode())
        self.proc.stdin.flush()

    def close(self):
        if not self.proc: return

        self.proc.communicate()

        self.proc = None

if __name__ == "__main__":
    osd = Osd()
    osd.open()

    for i in range(100):
        osd.display("test\n")

    osd.close()
