import os
import tarfile

def safe(tar_path: str, out_dir: str) -> None:
    out_abs = os.path.abspath(out_dir)
    with tarfile.open(tar_path) as t:
        for m in t.getmembers():
            dest = os.path.abspath(os.path.join(out_dir, m.name))
            if not dest.startswith(out_abs):
                raise ValueError("blocked")
        t.extractall(out_dir)
