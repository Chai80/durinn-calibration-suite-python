# Safe pattern with path check
import os
import zipfile

def safe(zip_path: str, out_dir: str) -> None:
    out_abs = os.path.abspath(out_dir)
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            dest = os.path.abspath(os.path.join(out_dir, name))
            if not dest.startswith(out_abs):
                raise ValueError("blocked")
        z.extractall(out_dir)
