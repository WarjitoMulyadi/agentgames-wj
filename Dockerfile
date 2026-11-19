# WJ-ARGUS on Railway — Dockerfile build (replaces nixpacks, whose
# python/node layering failed three builds in a row on 2026-11-19:
# node version conflict, then missing pip in the nix python env).
# Deterministic: official python slim + Node 20 binaries copied in
# (snarkjs prover runs as a node subprocess at runtime).
FROM python:3.11-slim

# Node 20 + npm from the official node image (binary + node_modules copy
# is the standard pattern; npm is a JS program run by node itself).
COPY --from=node:20-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=node:20-slim /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && node --version && npm --version && python --version

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt
RUN npm --prefix agent/prover ci

# Railway injects $PORT; default matches the app's own default.
CMD ["sh", "-c", "cd agent && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8787}"]
