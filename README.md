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

# run the unit tests
python -m pytest
```

The watermarking suite (`test/test_watermarking_all_methods.py`) runs without a
server. `test/test_api.py` imports the Flask app, which builds the RMAP keys and
a DB connection at startup, so it only runs in a full deployment environment; in
development the API is checked with the test bench and with `curl` (below).

## Coverage analysis

```bash
cd server
PYTHONPATH=src python -m pytest \
  --cov=my_watermarking_method --cov=watermarking_utils \
  --cov=watermarking_method --cov=add_after_eof \
  --cov-report=term --cov-report=html test/test_watermarking_all_methods.py
```

`--cov-report=html` writes a browsable report to `htmlcov/`. A saved summary is
in `artifacts/atla8167/coverage-summary.txt`.

## Deploy

From the root of the repository:

```bash
# create the environment file
cp sample.env .env

# edit .env: set the DB passwords, FLAG_2, and a strong SECRET_KEY.
# generate a SECRET_KEY with:
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env

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