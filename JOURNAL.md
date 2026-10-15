# Tatou : Journal of Events

Phase I /
Group: 29 /
Athanasios Lakes
---

## 0. Context

This is a group project but unfortunately I did not manage to find avaialable groups so I had to do this on my own
Because of that, I spent Phase I entirely on development,
deployment, defense, and the required deliverables. I ran no offensive
operations this phase (see Section 5).

Local access to the running server is done over
an SSH tunnel from my laptop (`ssh -L 5001:localhost:5000 ...`), not from
inside the VM.

The server has been kept up and serving the API (`healthz`, document routes,
and the two RMAP routes) throughout the phase, with downtime only for rebuilds.

---

## 1. Incident: Flag 1 captured (command injection)

**When:** 18th Sept

**What happened:** Flag 1 (`/app/flag`, baked into the container image) was
captured by another group.

**Root cause:** the inherited file `unsafe_bash_bridge_append_eof.py` built
shell commands by string-concatenating user-supplied values into
`subprocess.run(..., shell=True)`. Classic command injection sink. One sink on
the write side (`cat && printf`), one on the read side (`sed`).

**How it was exfiltrated:** the attacker submitted a watermark secret like
`"; cat /app/flag; printf "`. The injected command wrote the flag bytes into
the generated PDF, after the `%%EOF` marker. The flag did **not** come back in
the HTTP response to the write request : stdout there was discarded. It rode
out in the stored output file, fetched afterwards through
`GET /api/get-version/<id>`, which returns raw file bytes. I confirmed this
myself with `curl ... | tail -c 500` and managed to recreate the attack and 
retrieve my own flag.

**Fix:** removed the shell entirely. Both shell commands were replaced with
pure-Python byte operations:
- write side: `data = load_pdf_bytes(pdf); return data + secret.encode("utf-8")`
- read side: recover the trailing bytes after the last `%%EOF` directly.

With no shell, injected metacharacters become inert literal bytes. This kills
the whole vulnerability class rather than trying to sanitize the input.

**Response:** regenerated flags and updated the Server on the 20th of September

Output that doesn't appear in a write response can
still leak through a stored file that a later request serves. After this I
audited every other file-handling route for the same idea (Section 2).

---

## 2. Vulnerabilities found and fixed (proactive audit)

After the flag 1 incident I went through the route surface looking for the same
vulnerability classes. Found and fixed the following.

### 2.1 Information disclosure via exception messages (app-wide)

Nearly every endpoint returned the raw exception string to the client, e.g.
`jsonify({"error": f"database error: {str(e)}"})`. This leaks schema, driver,
and path details to anyone probing the server.

**Fix (class-level):** removed the per-route leaky `except` blocks and added
centralized error handlers in `create_app`:
- `HTTPException`: passed through with its real code (so intentional 4xx still work)
- `OperationalError` / `DBAPIError`: generic 503, detail logged server-side only
- `Exception`: generic 500, full traceback logged server-side only

Kept only the local `except` blocks that do real work (e.g. `IntegrityError`:
409, or file cleanup on failure). New endpoints are covered automatically.

### 2.2 SQL injection : `delete-document`

The document lookup built its query by concatenation:
`"SELECT * FROM Documents WHERE id = " + doc_id`. `text()` gives no protection
here. This allowed injection and also had no owner filter.

**Fix:** parameterized query with a bind param, added `AND ownerid = :uid`,
and cast the id to `int` before use.

### 2.3 `read-watermark`

The version shipped with Tatou had several issues:

- **No ownership check.** The lookup was `SELECT ... FROM Documents WHERE id = :id`
  with no owner filter : the code even carried a `FIXME enforce ownership`. Any
  authenticated user could read the watermark of any document by passing its id.
  This is a broken-authorization (IDOR) vulnerability.
- **Read from the wrong table.** It read the watermark from the source
  `Documents` file. The source document isn't watermarked; the watermarked copies
  live in `Versions`. So it tried to read a watermark from a file that doesn't
  carry one.
- **Document id was required.** An `int()` cast (plus a dead `try/except`) forced
  a document id, but the client UI only sends `key` and `method`. The endpoint
  could not serve its intended use case.
- **Single result only.** It returned exactly one secret. A key can unlock more
  than one version, which a single-result design can't represent.
- **Information disclosure.** Rewritten around what the endpoint is actually for: **given a key and a method,
  find which of my stored versions that key unlocks.**

#### First revision : what I fixed, and what I still got wrong (Commit on the 20th of September)

My first commit already improved on the inherited code, but it wasn't right yet.

**What I fixed in this revision:**

- **Read from `Versions`, not `Documents`.** Switched the lookup to the
  `Versions` table and iterated over all versions of the document, reading the
  watermark from each stored version file.
- **Handled multiple candidates.** Iterated the versions and used the extracted
  secret to select the correct one, instead of assuming a single result.

**What was still wrong:**

- **No ownership check.** The query was `SELECT * FROM Versions WHERE documentid
  = :id AND method = :method` still no owner filter. Any authenticated user
  could read another user's watermark secrets by iterating document ids. The
  `FIXME enforce ownership` was still unaddressed.
- **Positional column access.** Used hardcoded indices (`v[7]` for path, `v[4]`
  for secret) against `SELECT *`. If the schema column order ever changes, these
  silently point at the wrong field. Fragile and unsafe.
- **Document id was still required.** The `int()` cast and the dead `try/except`
  still forced a document id, which the client UI never sends (it only sends
  `key` and `method`).
- **Returned on first match only.** Returned as soon as one version matched. A
  shared key can unlock several versions, so this returns an arbitrary one among
  valid results.
- **Information disclosure.** Still returned the raw exception string:
  `f"database error: {str(e)}"`.

#### Final version

- **Enforce ownership.** The query now joins `Versions`: `Documents` and filters
  `d.ownerid = :uid`, so it can only touch versions of documents I own. Closes
  the IDOR.
- **Named columns.** Replaced `SELECT *` + `v[7]`/`v[4]` with an explicit
  `SELECT v.documentid, v.path, v.secret, v.intended_for` and attribute access
  (`v.path`, `v.secret`), immune to schema reordering.
- **Optional document id.** The query uses `(:id IS NULL OR v.documentid = :id)`,
  so a document id narrows the search when provided and is ignored when absent.
  Matches the UI (key + method only).
- **Return all matches.** Instead of returning on the first match, collects every
  version whose extracted secret matches its stored secret and returns them as
  `{"versions": [...]}`. A shared key unlocks a set; the endpoint returns the set.
- **No information disclosure.** Removed the `str(e)` response; DB errors are
  handled by the global error handler.

**Supporting policy:** Since a key is an unlocker and not an identifier, I thought i made sense that a key can be shared across
versions. On the other hand, each version's `secret` is unique.

### 2.4 Broken authorization + missing auth, `delete-document`

Two problems on a destructive route:
- The route had **no `@require_auth`** at all. It was reachable
  unauthenticated. It happened to crash on `g.user` instead of executing, but
  it was exposed. Found via an `AttributeError: user` traceback in the logs.
- The `DELETE` statement ran on `id` alone; the owner check was only on a
  separate `SELECT`.

**Fix:** added `@require_auth`, and made the `DELETE` self-guarding with
`AND ownerid = :uid` so it cannot touch another user's row regardless of the
earlier check.

### 2.5 Path traversal (write side), `upload-document`

The uploaded filename (`file.filename`) was used unsanitized to build the
storage path. A filename with `../` could escape the user's directory and write
elsewhere. Same class as the flag 1 read-side risk, on the write side.

**Fix:** `secure_filename()` to strip the filename, plus `resolve()` +
`is_relative_to(storage_root)` confinement as a backstop. Sanitize then confine.

### 2.6 Login hardening

- Same `str(e)` info leak as 2.1.
- Timing-based user enumeration: the `not row or not check_password_hash(...)`
  check short-circuits when the email doesn't exist, so nonexistent users get a
  fast response and existing users get a slow one (password hashing runs). An
  attacker can enumerate registered emails by response time. Fixed by running a
  dummy hash comparison on the no-user path so both paths take similar time.
  `DUMMY_HASH` is computed once at startup.

---

## 3. Verified and left unchanged

Checked these and found them already correct. No change needed.

- **`get-document`** : owner filter (`AND ownerid = :uid`) and path confinement
  already present. Used as the reference pattern for the fixes above.
- **`get-version/<link>`** : public by design (recipient download route). Path
  confinement present. The flag 1 file rode out through here, but the hole was
  upstream (the injection writing the file), not this route.
- **`list-documents`, `list-versions`, `list-all-versions`** : all correctly
  scoped to the authenticated user through the join / owner filter. The name
  "list-all-versions" is misleading; it returns all versions belonging to the
  caller, not globally.
- **`static/<path:filename>`** : public catch-all. Tested by hand for
  traversal: `curl --path-as-is` with raw `../`, `%2e%2e%2f` encoded, and
  double-encoded payloads. All returned 404; only legitimate assets returned
  200. Static folder is `/app/src/static` and contains only public assets
  (index.html + client). Confirmed safe.

---

## 4. Known issues, deferred by triage

Found these, decided they were low priority for a solo team this phase.

- **Login has no rate limiting** : brute-force exposure. Deferred; offense was
  not a factor this phase and a correct implementation needs more time than it
  was worth now.
- **`create-user` has no password policy** : a 1-character password is
  accepted.
- **`delete-document` `note` field** still returns some file-deletion error
  detail to the client. Minor leak, owner-only. Deferred.
- **Orphaned version files** : deleting a document cascades to the version rows
  in the DB (FK `ON DELETE CASCADE`) but does not remove the watermarked PDFs
  on disk. Disk-hygiene gap, not a security issue.

---

## 5. Offensive operations

None this phase. Solo team, no time available for offense. The instructor is
aware. Planned for Phase II if time allows.

---

## 6. Deliverables built this phase

### 6.1 RMAP endpoints

Implemented `rmap-initiate` and `rmap-get-link` using the provided RMAP
library.
- `RMAPServer` instantiated at module level; `loadIdentities` called once at
  startup.
- Watermark attribution uses a fixed server-side key (`RMAP_WM_KEY`), not the
  per-handshake link. Using the link as the key would make attribution require
  brute-forcing every stored link.
- Strict ordering before responding: watermark bytes written, DB row inserted,
  committed, only then return `resp2`. A link is never returned unless the
  watermarked version was actually created and recorded.
- On DB insert failure the written file is cleaned up (no file without a row).
- Error messages hardened : this endpoint is adversary-facing in Phase II, so
  it must not leak watermarking internals.
- PGP key handling: server private key exported from the keyring, passphrase
  removed, keys mounted read-only from outside the repo and gitignored.

Endpoints were tested using a toy client.

### 6.2 Watermarking method (individual responsibility)

Invisible-text carrier using PyMuPDF `render_mode=3`. Payload built with
`_build_payload` / HMAC-SHA256, fenced with `<mwm:` / `mwm>` delimiters.
Extraction reads `page.get_text()` and slices between the delimiters. Works
end-to-end through the live API with no changes to the existing
`create-watermark` / `read-watermark` contract. It also allows for direct
one to one mapping to the correct owner in case of a leak and multi page pdfs.

**Phase II note:** invisible text alone is weak against de-watermarking
(re-render, `pdftotext` rebuild, flatten, recompression all strip it). The
instructions allow combining methods. Plan for Phase II is to add carriers that
fail to different attacks so no single transformation removes all of them.

---

## 7. Follow-up changes and findings (26 September–15 October)

### 7.1 Randomized version filenames and download links

Watermarked version filenames now include a random 12-hex-character suffix,
and the public download link is a separate 40-hex-character value generated
with `secrets.token_hex(20)`. This replaces deriving the link from the
watermarked filename, making links unpredictable and avoiding filename-based
link generation. The link remains a bearer capability: anyone who obtains it
can download that version, as intended by the platform specification.

### 7.2 Multi-page watermark extraction

`MyWatermarkingMethod.read_secret` now scans PDF pages until it finds the
watermark markers, rather than assuming they are in the first extracted page
text. It stops at the first page with a complete marker pair and raises
`SecretNotFoundError` if no marker is found. Watermark creation itself still
inserts this method's payload on the first page.

### 7.3 `read-watermark` handles source documents without version rows

The endpoint now has a fallback for a caller-owned original document that has
no corresponding `Versions` rows yet. When the caller supplies its document
id, the route checks ownership, confines the source-file path to the storage
directory, and attempts extraction directly from that PDF. If a matching
owned version row exists, its `intended_for` value is included; otherwise
`intended_for` is `null`.

The response now includes the final match's fields at the top level as well as
the complete `versions` array. A missing match returns a generic 404 message.
The fallback still requires a document id; the id may be omitted when searching
existing version rows, but without an id the route cannot select an original
document with no versions. In that no-version case, omitting the id currently
falls through to `int(None)` and returns a generic 500 instead of a clear 400.

There is also a recipient-attribution edge case: the fallback's `intended_for`
lookup filters by owner, method, and secret, but not by the current document
id. If another document belonging to the same owner reuses that secret and
method, the response can report that other version's recipient.

### 7.4 RMAP input errors and remaining disclosure

Both RMAP endpoints now reject requests unless the JSON body is an object with
a string `payload`. The expected decryption, malformed-message, unknown-
identity, and protocol-state errors are mapped to a generic 400 response rather
than exposing their details.

**Re-check / remaining issue:** the version-insert failure handler in
`rmap-get-link` still returns `str(e)` in its 503 response. This can expose
database or filesystem exception details, so the earlier statement in Section
6.1 that the endpoint's errors do not leak internals is not universally true.
That handler needs to return a generic client message and log the detail
server-side before that claim is accurate.

---

## 8. Incident: IDOR in `POST /api/create-watermark` — flag 3 captured (15 October)

**Detection:** The course tester reported “server lists no version unknown
locally” for its documents (IDs 590, 594, 598, 600). The `Versions` table
contained versions 107–140 with `intended_for` set to
`Ihnkndardav@gmail.com_toy-eof_neo` and method `toy-eof`, attached to documents
owned by IDs 532, 545, 556, 562, 577, 578, 590, 593, and 602. These included
the tester's documents and our `__rmap_source__.pdf`.

**Root cause:** `create-watermark` authenticated the caller but looked up the
document using `WHERE id = :id` without checking ownership. Any logged-in user
could request a watermarked copy of another user's document and receive its
download link. This was an IDOR / broken access control vulnerability (CWE-639).

**Impact:** Version 129 was created on document 606, `flag_3`, owned by user
578. The instructor confirmed flag 3 was captured. Foreign versions also
caused the tester's integrity checks to fail.

**Related activity (blocked):** On 2026-10-07, attacker accounts (owner IDs
590, 593, 602) uploaded files named `../../../../../../../../app/flag` and
`../../../etc/passwd`. The server generated stored paths inside
`/app/storage/files/` (for example,
`.../20261007T105316383008Z__x.pdf`), so path traversal did not succeed and
flag 1 was not exposed by this vector.

**Response:** Preserved a database dump and server logs before making changes.
Fixed `create-watermark` to query with
`WHERE id = :id AND ownerid = :uid` and return 404 when the document is absent
or not owned by the caller, matching `get-document`. Rebuilt and redeployed
the server container and verified the ownership check in the running
container. Deleted the attacker-created rows with
`DELETE FROM Versions WHERE intended_for LIKE 'Ihnkndardav%'`.

**Lesson:** Authentication is not authorization; every object lookup must be
scoped to the requesting user.

---