# Tatou API Documentation

---

# Routes

- [create-user](#create-user) — **POST** `/api/create-user`
- [create-watermark](#create-watermark)
  - **POST** `/api/create-watermark/<int:document_id>`
  - **POST** `/api/create-watermark`
- [delete-document](#delete-document)
  - **DELETE** `/api/delete-document/<document_id>`
  - **DELETE, POST** `/api/delete-document`
- [get-document](#get-document)
  - **GET** `/api/get-document/<int:document_id>`
  - **GET** `/api/get-document`
- [get-version](#get-version) — **GET** `/api/get-version/<link>`
- [get-watermarking-methods](#get-watermarking-methods) — **GET** `/api/get-watermarking-methods`
- [healthz](#healthz) — **GET** `/healthz`
- [list-all-versions](#list-all-versions) — **GET** `/api/list-all-versions`
- [list-documents](#list-documents) — **GET** `/api/list-documents`
- [list-versions](#list-versions)
  - **GET** `/api/list-versions/<int:document_id>`
  - **GET** `/api/list-versions`
- [load-plugin](#load-plugin) — **POST** `/api/load-plugin`
- [login](#login) — **POST** `/api/login`
- [read-watermark](#read-watermark)
  - **POST** `/api/read-watermark/<int:document_id>`
  - **POST** `/api/read-watermark`
- [upload-document](#upload-document) — **POST** `/api/upload-document`
- [rmap-initiate](#rmap-initiate) — **POST** `/api/rmap-initiate`
- [rmap-get-link](#rmap-get-link) — **POST** `/api/rmap-get-link`



## healthz

**Path**
`GET /healthz`

**Description**  
This endpoint checks the health of the server and confirms it is running.

**Parameters**  
_None_

**Return**
```json
{
  "message": <string>,
  "db_connected": <bool>
}
```

**Specification**
 * The healthz endpoint MUST be accessible without authentication.
 * The response MUST always contain a "message" field of type string.

## create-user

**Path**
`POST /api/create-user`

**Description**  
This endpoint creates a new user account in the system.

**Parameters**
```json
{
  "login": <string>,
  "password": <string>,
  "email": <email>
}
```

**Return**
```json
{
  "id": <int>,
  "login": <string>,
  "email": <email>
}
```

**Specification**
 * The create-user endpoint MUST validate that login, password, and email are provided.
 * The login MUST match `[A-Za-z0-9_-]{1,64}`; it is used as a storage directory name, so other characters (including `.` and `/`) are rejected with 400 to prevent path traversal.
 * The response MUST include a unique id along with the created login and email.


## login

**Path**
`POST /api/login`

**Description**  
This endpoint authenticates a user with their credentials and returns a session token.

**Parameters**
```json
{
  "email": <string>,
  "password": <string>
}
```

**Return**
```json
{
  "token": <string>,
  "token_type": "bearer",
  "expires_in": <int>
}
```

**Specification**
 * The login endpoint MUST reject requests missing email or password.
 * The response MUST include a token string and its expiration as an integer Time To Live in seconds.
 * The token is signed with the server `SECRET_KEY`, which MUST be set from the environment; it MUST NOT fall back to a default value in production.


## upload-document

**Path**
`POST /api/upload-document`

**Description**  
This endpoint uploads a PDF document to the server and registers its metadata.

**Parameters**
```json
{
  "file": <pdf file>,
  "name": <string>
}
```

**Return**
```json
{
  "id": <string>,
  "name": <string>,
  "creation": <date ISO 8601>,
  "sha256": <string>,
  "size": <int>
}
```

**Specification**
 * Requires authentication.
 * The upload-document endpoint MUST accept only files in PDF format.
 * The stored path MUST be generated server-side and confined under the user's storage directory; the client-supplied filename MUST NOT be able to escape it.


## list-documents

**Path**
`GET /api/list-documents`

**Description**  
This endpoint lists all uploaded PDF documents of the authenticated user along with their metadata.

**Parameters**  
_None_

**Return**
```json
{
  "documents": [
    {
      "id": <string>,
      "name": <string>,
      "creation": <date ISO 8601>,
      "sha256": <string>,
      "size": <int>
    }
  ]
}
```

**Specification**
 * Requires authentication.
 * The response MUST return only the documents owned by the authenticated user.


## list-versions

**Description**  
This endpoint lists all watermarked versions of a given PDF document owned by the authenticated user.

**Path**
`GET /api/list-versions`

**Parameters**
```json
{
  "documentid": <int>
}
```

**Path**
`GET /api/list-versions/<int:document_id>`

**Parameters**  
_None_

**Return**
```json
{
  "versions": [
    {
      "id": <string>,
      "documentid": <string>,
      "link": <string>,
      "intended_for": <string>,
      "secret": <string>,
      "method": <string>
    }
  ]
}
```

**Specification**
 * Requires authentication.
 * MUST return only versions of documents owned by the authenticated user.


## list-all-versions

**Path**
`GET /api/list-all-versions`

**Description**  
This endpoint lists all versions of all PDF documents owned by the authenticated user.

**Parameters**  
_None_

**Return**
```json
{
  "versions": [
    {
      "id": <string>,
      "documentid": <string>,
      "link": <string>,
      "intended_for": <string>,
      "secret": <string>,
      "method": <string>
    }
  ]
}
```

**Specification**
 * Requires authentication.
 * MUST return only versions of documents owned by the authenticated user.


## delete-document

**Description**  
This endpoint deletes a document owned by the authenticated user and its versions.

**Path**
`DELETE /api/delete-document/<document_id>`

**Path**
`DELETE, POST /api/delete-document`

**Parameters**
```json
{
  "id": <int>
}
```

**Return**
`200` on success.

**Specification**
 * Requires authentication.
 * MUST delete only a document owned by the caller; MUST return 404 when the document does not exist or is not owned by the caller.


## get-document

**Description**  
This endpoint retrieves a PDF document owned by the authenticated user.

**Path**
`GET /api/get-document`

**Parameters**
```json
{
  "id": <int>
}
```

**Path**
`GET /api/get-document/<int:document_id>`

**Return**
Inline PDF file in binary format.

**Specification**
 * Requires authentication.
 * MUST return 404 when the document does not exist or is not owned by the caller.


## get-version

**Path**
`GET /api/get-version/<link>`

**Description**  
This endpoint serves a watermarked version by its unguessable link. Intended for
distribution to a recipient.

**Parameters**  
_None_

**Return**
Inline PDF file in binary format.

**Specification**
 * Public by design (no authentication): the link is the capability.
 * The link MUST be unguessable (a random token, not derived from the filename).
 * The served path MUST be confined under the storage directory.


## get-watermarking-methods

**Description**  
This endpoint lists all available watermarking methods.

**Path**
`GET /api/get-watermarking-methods`

**Parameters**
_None_

**Return**
```json
{
    "count": <int>,
    "methods": [
        {
            "description": <string>,
            "name": <string>
        }
    ]
}
```

**Specification**
 * The endpoint MUST return all methods in `watermarking_utils.METHODS`.

## load-plugin

**Description**  
This endpoint is present in the server implementation but is intentionally disabled. The current server returns a 410 error instead of loading a third-party watermarking plugin.

**Path**
`POST /api/load-plugin`

**Parameters**
```json
{
  "filename": <string>,
  "overwrite": <bool>
}
```

**Return**
```json
{
  "error": "plugin loading is disabled"
}
```

**Status**
* `410 Gone` — the route exists but the feature is disabled in the current build.


## read-watermark

**Description**  
This endpoint reads the secret embedded in a document's watermark with the
provided method and key.

**Path**
`POST /api/read-watermark`

**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>,
    "id": <int>
}
```

**Path**
`POST /api/read-watermark/<int:document_id>`

**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>
}
```

**Return**
```json
{
    "documentid": <int>,
    "secret": <string>,
    "method": <string>,
    "position": <string>,
    "intended_for": <string>,
    "versions": [ ... ]
}
```

**Specification**
 * Requires authentication; operates only on documents owned by the caller.
 * The document id may be supplied in the path or in the body.
 * MUST return the secret read from the document. The top-level fields describe
   the best match; `versions` lists the matching version rows (empty when the
   document has no stored versions, e.g. a freshly uploaded document).
 * MUST return 404 when the document does not exist or is not owned by the caller.


## create-watermark

**Description**  
This endpoint creates a watermarked version of a document owned by the caller,
embedding the given secret with the chosen method, and records it.

**Path**
`POST /api/create-watermark`

**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>,
    "secret": <string>,
    "intended_for": <string>,
    "id": <int>
}
```

**Path**
`POST /api/create-watermark/<int:document_id>`

**Parameters**
```json
{
    "method": <string>,
    "position": <string>,
    "key": <string>,
    "secret": <string>,
    "intended_for": <string>
}
```

**Return**
```json
{
    "id": <int>,
    "documentid": <int>,
    "link": <string>,
    "intended_for": <string>,
    "method": <string>,
    "position": <string>,
    "filename": <string>,
    "size": <int>
}
```

**Specification**
 * Requires authentication.
 * Only the owner of a document may create watermarked versions of it; the
   endpoint MUST return 404 when the document does not exist or is not owned by
   the caller (broken-access-control / IDOR fix).
 * The document id may be supplied in the path or in the body.
 * On success the watermarked version MUST be stored and a corresponding row
   inserted, and the returned `link` MUST resolve via `get-version`.


## rmap-initiate

**Description**  
This endpoint receives a GPG-encrypted message conforming to RMAP message 1.

**Path**
`POST /api/rmap-initiate`

**Parameters**
```json
{
    "payload": <ASCII_armored_base64>
}
```

should decrypt to:

```json
{
    "nonceClient": <u64>,
    "identity": <string>
}
```

**Return**
```json
{
    "payload": <ASCII_armored_base64>
}
```
should decrypt to:

```json
{
    "nonceClient": <u64>,
    "nonceServer": <u64>
}
```

**Specification**
 * The server MUST only respond to known identities (public key present in the course key directory).
 * All submitted group public keys MUST constitute valid identities.
 * The payload is a GPG-encrypted JSON presented as ASCII-armored base64, without the GPG header/footer lines.
 * Malformed, undecryptable, or unknown-identity messages MUST return a generic 400 without leaking the reason.


## rmap-get-link

**Description**  
This endpoint receives a GPG-encrypted message conforming to RMAP message 2.

**Path**
`POST /api/rmap-get-link`

**Parameters**
```json
{
    "payload": <ASCII_armored_base64>
}
```

should decrypt to:

```json
{
    "nonceServer": <u64>
}
```

**Return**
```json
{
    "payload": <ASCII_armored_base64>
}
```
should decrypt to:

```json
{
    "result": "<32-hex nonceClient||nonceServer>"
}
```

**Specification**
 * `get-version/<result>` MUST point to a watermarked version of the assigned PDF, specific to the authenticated client identity.
 * A link MUST NOT be returned unless the watermarked version has been created and recorded.
 * Malformed or undecryptable messages MUST return a generic 400.