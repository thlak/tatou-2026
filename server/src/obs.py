"""
obs.py — Observability for Tatou (Specialization D: Operational Security).

Two JSON-lines logs, written to a directory that is bind-mounted to the host so
they survive `docker compose up --build` (the evidence-loss problem from the
15 Oct incident):

  access.log    one line per HTTP request  (observation point O1)
  security.log  one line per security event (O2-O6)

Design notes
------------
- stdlib only; no new dependencies.
- Never raises into the request path: if logging fails, the request still
  succeeds. Monitoring must not become an availability risk (rules forbid DoS,
  and a broken logger must not take the service down).
- The access hook reads g.user, which require_auth sets, so the uid is captured
  for every authenticated request with no per-route code.
"""
import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler

from flask import g, request

LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")


def _make_logger(name: str, filename: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:  # avoid duplicate handlers on reload
        os.makedirs(LOG_DIR, exist_ok=True)
        # rotate so a flood (e.g. a scan) can't fill the disk — availability
        handler = RotatingFileHandler(
            os.path.join(LOG_DIR, filename),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


_access_log = _make_logger("tatou.access", "access.log")
_security_log = _make_logger("tatou.security", "security.log")


def _client_ip() -> str:
    # X-Forwarded-For first value if present (behind gunicorn/proxy), else peer
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
    """Write one security event. Call at the branch where the event happens."""
    try:
        rec = {"ts": _now(), "kind": kind, "ip": _client_ip(),
               "uid": _uid(), "path": request.path}
        rec.update(fields)
        _security_log.info(json.dumps(rec, default=str))
    except Exception:  # logging must never break the request
        pass


def init_app(app) -> None:
    """Register the per-request access log. Call once inside create_app()."""

    @app.before_request
    def _start_timer():
        g._t0 = time.monotonic()

    @app.after_request
    def _access(response):
        try:
            dt_ms = round((time.monotonic() - getattr(g, "_t0", time.monotonic())) * 1000, 1)
            rec = {
                "ts": _now(),
                "ip": _client_ip(),
                "uid": _uid(),
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "ms": dt_ms,
                "len": response.calculate_content_length(),
            }
            _access_log.info(json.dumps(rec, default=str))
            if response.status_code >= 500:  # O6: surface server errors
                log_event("server_error", status=response.status_code,
                          method=request.method)
        except Exception:
            pass
        return response