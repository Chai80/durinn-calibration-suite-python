# DURINN_GT id=a08_07_zip_extractall track=sast set=core owasp=A08
import zipfile

def vuln(zip_path: str, out_dir: str) -> None:
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(out_dir)
