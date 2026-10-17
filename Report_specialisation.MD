# Specialization D: Operational Security

Threat modeling, logging and monitoring. Author: Athanasios Lakes (atla8167), Group 29.

Artifacts: `threat-model.md`, `server/src/obs.py`, the observability and hardening
commits, and the log samples in `logs/`.

## Why

Two of my three flags were captured during the project, and **neither was
detected by me**. Flag 1 (command injection) I  learned about afterwards; flag 3
(IDOR in `create-watermark`) I found four days later, only because the course
tester's integrity checks failed. When I investigated the IDOR the container logs
were already gone, erased by an earlier `docker compose up --build`, so I
reconstructed the attack from the database. The operational question for this
specialization was therefore: if I  are attacked again, will I  see it, and can
I  recover. At the start the answer was no on both counts.

## What the threat model found

Working through STRIDE against my own fork did not just restate the two known
captures. It surfaced three live issues I  had not found by testing, plus one
exposure:

- **Default `SECRET_KEY`**: `docker-compose.yml` never set it, so the app used the
  public default `dev-secret-change-me`. Anyone could forge a valid token for any
  user, including Mr Important's. This leaves no log trace.
- **Login used as a directory name**: the `login` field was written unvalidated
  into the storage path. The `Users` table showed this had been probed on 7 Oct,
  with uploads landing in `/etc/` and `/app/templates/` inside the container.
- **`load-plugin` deserialization**: an authenticated route ran `pickle.load()`
  on an uploaded file — RCE, and inherited dead code not in the API spec.
- **Exposed data plane**: MariaDB (3306) and phpMyAdmin (8080) published to the
  network.

The lesson: the holes a threat model finds are often the ones monitoring cannot
see. The `SECRET_KEY` issue leaves no log entry at all, and the other two left
none because no logging existed when they were probed. That is the argument for
doing both — a threat model and request-level logging — rather than treating
logging as the whole of operational security.

## What I changed

**Hardening:** `SECRET_KEY` now injected from `.env` (rotating it invalidates any
forged token); `login` restricted to `[A-Za-z0-9_-]`; `load-plugin` disabled;
3306 and 8080 bound to `127.0.0.1`.

**Observation points** (`obs.py`, standard library only, written so a logging
failure can never break a request):

- `access.log` — one JSON line per request (ip, uid, method, path, status,
  latency). One `after_request` hook covers the whole API, including the
  IDOR-sweep pattern of one user touching many document ids.
- `security.log` — labelled events: `auth_failure`, `suspicious_login`,
  `authz_denied` (with the attacker's uid and the requested document id, the exact
  flag-3 signal), and server errors.

Both logs are bind-mounted to the host so they survive a rebuild, which closes
the evidence-loss gap directly.

## Limits

- A successful RCE reads a flag with no application-level log; catching that needs
  host auditing, which I did not set up given time and the solo constraint.
- Forged tokens are invisible by design; the default key was in use for most of
  the project, so earlier forgery cannot be ruled out (disclosed to the
  instructor).
- Detection is after the fact — nothing here blocks an attack in real time.

Incidents are recorded in the operations journal: command injection (§1), the
audit (§2), and the IDOR / flag 3 capture (§8). This section is the
operational-security analysis of that record.