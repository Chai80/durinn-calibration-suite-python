import subprocess

def safe(host: str) -> None:
    # List args, no shell
    subprocess.run(["echo", host], shell=False, check=False)
