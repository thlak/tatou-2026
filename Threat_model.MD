# Threat Model: Tatou (Group 29)

Specialization D. 
Author: Athanasios Lakes, atla8167.

## Scope and method

I model the Flask API, its MariaDB database, the file storage, and the three
flags, against the realistic attacker in this project: another student group
with a valid account on the isolated network. I use STRIDE, and for each threat
I note whether we saw it, how it is mitigated, and how it would be detected.

**Assets:** flag 1 (`/app/flag`), flag 2 (`tatou/flag`), flag 3 (Mr Important's
PDF), user documents, watermark secrets, and the credentials in `.env`.

## Data flow

```
[other groups] --HTTP/JSON--> [Flask API] --SQL--> [MariaDB]
                                   |
                                   +--files--> [storage volume]
                 [DB :3306 / phpMyAdmin :8080 should not face the network]
```

Trust boundary: everything from the network is untrusted. The VM host and the
instructor are trusted.

## Threats (STRIDE)

| # | STRIDE | Threat | Entry point | Status | Detection |
|---|--------|--------|-------------|--------|-----------|
| 1 | Elevation / Info | **IDOR** — document id not scoped to the caller | `create-watermark` | Exploited; flag 3 captured (journal §8). Fixed: `WHERE id=:id AND ownerid=:uid` | `authz_denied` event |
| 2 | Elevation | Command injection in the shell watermark method | `create-watermark` | Exploited; flag 1 captured (journal §1). Fixed: pure-Python byte ops | 5xx spike |
| 3 | Tampering | Path traversal via login used as a directory name | `create-user` -> `upload` | Probed 7 Oct. Fixed: login allow-list | `suspicious_login` event |
| 4 | Elevation | Unsafe deserialization (pickle) | `load-plugin` | Found in audit. Fixed: route disabled | 5xx / access log |
| 5 | Spoofing | Token forgery via default `SECRET_KEY` | any auth route | Found in audit. Fixed: key set from `.env` | not detectable (forged token looks valid) |
| 6 | Info disclosure | DB / phpMyAdmin exposed to the network | ports 3306, 8080 | Fixed: bound to 127.0.0.1 | port check after deploy |
| 7 | Spoofing | Login brute force | `login` | No rate limiting (accepted) | `auth_failure` burst |
| 8 | Repudiation | Recipient strips watermark and leaks | offline | Inherent risk; attribution script used | hash lookup |
| 9 | Repudiation | Evidence lost when the container is rebuilt | operations | Fixed: logs on a persistent volume | - |

## Observation points added

- **Request log** (`access.log`): one JSON line per request (ip, uid, method,
  path, status, latency). Covers the IDOR-sweep pattern: one user hitting many
  document ids or producing many denials.
- **Security events** (`security.log`): `authz_denied` (threat 1),
  `auth_failure` (7), `suspicious_login` (3), and server errors (2, 4).
- Both logs are bind-mounted to the host so they survive a rebuild (threat 9).

## What this does not cover

- A successful RCE reads a flag with no application-level log (threat 2/4);
  catching that needs host auditing, which I did not set up.
- Forged tokens (threat 5) are invisible by design; the only defence is a strong
  key plus rotation.
- Detection is after the fact - nothing here blocks an attack in real time.