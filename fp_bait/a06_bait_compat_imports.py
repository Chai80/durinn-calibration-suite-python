# Compatibility shim (safe) — some scanners may still complain.
try:
    import urllib2  # noqa: F401
except Exception:
    import urllib.request as urllib2  # type: ignore
