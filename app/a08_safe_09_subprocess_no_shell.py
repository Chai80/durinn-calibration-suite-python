import subprocess

def safe(cmd: str) -> None:
    subprocess.run(["echo", cmd], shell=False, check=False)
