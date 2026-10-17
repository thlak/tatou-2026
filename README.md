# tatou

A web platform for PDF watermarking. This project is intended for pedagogical
use and contains security vulnerabilities. Do not deploy on an open network.

## Clone

```bash
git clone https://github.com/thlak/tatou-2026.git
cd tatou-2026
```

## Run unit tests

```bash
cd server

python3 -m venv .venv
. .venv/bin/activate

# install the package plus test tooling
pip install -e .
pip install pytest pytest-cov

# Run only the watermarking unit tests (all 9 tests pass)
PYTHONPATH=src python -m pytest test/test_watermarking_all_methods.py
```

Run the command from the `server/` directory, with `src` on `PYTHONPATH`, as
shown above. Running pytest from the repository root leaves the watermarking
methods registry empty (causing the tests to skip) and makes `test_api.py` fail
to import.

`test/test_api.py` imports the full Flask app, which loads RMAP PGP keys and
connects to the database at startup. It therefore only runs inside a full
deployment and should be excluded from the standalone unit-test run above.

## Coverage analysis

```bash
cd server
PYTHONPATH=src python -m pytest --cov=src --cov-report=term test/test_watermarking_all_methods.py
```

A saved coverage summary is in `artifacts/atla8167/coverage-summary.txt`.

## Deploy

From the root of the repository:

```bash
# create the environment file
cp sample.env .env

# edit .env: set the DB passwords, FLAG_2, RMAP_WM_KEY, and a strong SECRET_KEY.
# generate a SECRET_KEY with:
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
# the app also expects RMAP_WM_KEY to be set in the environment
# (it is read from server/src/server.py via app.config["RMAP_WM_KEY"]).

# build and start the containers
docker compose up --build -d

# follow logs
docker compose logs -f

# check the API is up
curl -s localhost:5000/healthz; echo
```

Then open `http://127.0.0.1:5000` to check the web client.

Application logs (request log and security events) are written to `./logs/` on
the host via a bind mount, so they survive container rebuilds.