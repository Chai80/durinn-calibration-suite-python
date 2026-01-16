import subprocess

def safe(url: str) -> None:
    subprocess.run(["curl", url], shell=False, check=False)
