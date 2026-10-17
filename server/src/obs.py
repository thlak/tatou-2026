"""
obs.py — Observability for Tatou (Specialization D: Operational Security).

Two JSON-lines logs, written to a directory bind-mounted to the host so they
survive `docker compose up --build` (the evidence-loss problem from 15 Oct):

  access.log    one line per HTTP request   (observation point O1)
  security.log  one line per security event (O2-O6)

Design notes
------------
- stdlib only; no new dependencies.
- Nothing touches the filesystem at import time, so the module imports cleanly
  under pytest where /app does not exist. Handlers are created lazily on first
  use, and if the log directory is not writable the logger degrades to a no-op
  instead of crashing the request.
- Logging never raises into the request path: monitoring must not become an
  availability risk.
"""
import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler

from flask import g, request

LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")

_loggers = {}


def _get_logger(name: str, filename: str):
    """Create the file logger on first use. Returns None if LOG_DIR is unusable."""
    if name in _loggers:
        return _loggers[name]
    logger = None
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not logger.handlers:
            handler = RotatingFileHandler(
                os.path.join(LOG_DIR, filename),
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
    except Exception:
        logger = None 
    _loggers[name] = logger
    return logger


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "-"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _uid():
    user = getattr(g, "user", None)
    return user.get("id") if isinstance(user, dict) else None


def log_event(kind: str, **fields) -> None:
    """Write one security event at the branch where it happens."""
    try:
        logger = _get_logger("tatou.security", "security.log")
        if logger is None:
            return
        rec = {"ts": _now(), "kind": kind, "ip": _client_ip(),
               "uid": _uid(), "path": request.path}
        rec.update(fields)
        logger.info(json.dumps(rec, default=str))
    except Exception:
        pass


def init_app(app) -> None:
    """Register the per-request access log. Call once inside create_app()."""

    @app.before_request
    def _start_timer():
        g._t0 = time.monotonic()

    @app.after_request
    def _access(response):
        try:
            logger = _get_logger("tatou.access", "access.log")
            if logger is not None:
                dt_ms = round((time.monotonic() - getattr(g, "_t0", time.monotonic())) * 1000, 1)
                rec = {
                    "ts": _now(), "ip": _client_ip(), "uid": _uid(),
                    "method": request.method, "path": request.path,
                    "status": response.status_code, "ms": dt_ms,
                    "len": response.calculate_content_length(),
                }
                logger.info(json.dumps(rec, default=str))
            if response.status_code >= 500:
                log_event("server_error", status=response.status_code, method=request.method)
        except Exception:
            pass
        return response