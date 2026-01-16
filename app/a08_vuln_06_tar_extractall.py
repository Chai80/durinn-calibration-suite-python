# DURINN_GT id=a08_06_tar_extractall track=sast set=core owasp=A08
import tarfile

def vuln(tar_path: str, out_dir: str) -> None:
    with tarfile.open(tar_path) as t:
        t.extractall(out_dir)
