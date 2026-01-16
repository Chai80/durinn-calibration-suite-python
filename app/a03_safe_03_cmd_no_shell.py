import subprocess

def safe(host: str) -> None:
    subprocess.run(["ping", "-c", "1", host], check=False)
