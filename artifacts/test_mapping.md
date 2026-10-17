# Test suite — coverage and spec mapping (Group 29)

## Suites

| File | What it tests |
|------|---------------|
| `server/test/test_api.py` | `GET /healthz` returns 200 and JSON. |
| `server/test/test_watermarking_all_methods.py` | Every watermarking method registered in `watermarking_utils.METHODS`, parameterised. |

## Running the unit tests

From the repository root, run the watermarking unit tests from `server/` with
`src` on the module path:

```bash
cd server
PYTHONPATH=src python -m pytest test/test_watermarking_all_methods.py
```

All 9 tests pass when run this way. Running from the repository root instead
leaves the methods registry empty (causing the tests to skip) and makes
`test_api.py` fail to import.

`test/test_api.py` imports the full Flask app, which loads RMAP PGP keys and
connects to a database at startup. It therefore only runs inside a full
deployment and should be excluded from the standalone unit-test run above.

## test_watermarking_all_methods.py — per method

For each registered method (the unsafe shell bridge is excluded):

| Test | Checks | Spec / code item |
|------|--------|------------------|
| `test_is_watermark_applicable` | `is_watermark_applicable()` returns a bool | watermarking method contract |
| `test_add_watermark_and_shape` | output is bytes, not smaller than input, still a valid PDF | `create-watermark` embedding |
| `test_read_secret_roundtrip` | `read_secret(add_watermark(x)) == x` | leak attribution (`read-watermark`) — the security-critical property |

The roundtrip test proves a watermark the server
writes can be read back as the exact secret, which is what leak attribution
depends on.

## Coverage (pytest-cov)

From `server/`, run coverage for the suite with:

```bash
PYTHONPATH=src python -m pytest --cov=src --cov-report=term test/test_watermarking_all_methods.py
```

The reported coverage is scoped to the `src` package:

| Module | Coverage |
|--------|----------|
| `my_watermarking_method.py` | 85% |
| `add_after_eof.py` | 80% |
| `watermarking_method.py` | 78% |
| `watermarking_utils.py` | 31% |

Full HTML report in `coverage/`.

## What is not unit-tested, and why

The HTTP API (routes in `server.py`) is not covered by pytest. `create_app()`
loads RMAP PGP keys and opens a database connection at import, neither of which
exists in the unit-test environment, so `from server import app` cannot run
there. The API is instead validated by the course test bench and by manual
`curl` against the live server (see journal §11). Unit-testing the routes would
require a test fixture that stubs the keys and database — identified as the main
gap in the test approach.