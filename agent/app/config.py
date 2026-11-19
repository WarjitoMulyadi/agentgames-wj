"""Configuration — environment variables + the one-time secret file.

The HMAC secret (platform-generated, shown ONCE in the dashboard at
registration) reaches the agent by one of two paths, in priority order:

  1. SECRET FILE — `data/hmac_secret.txt` (mode 600), written by the
     one-time /setup page (see app/main.py) or dropped in place by hand
     before first boot. This is the primary path: the value never passes
     through chat or shell history.
  2. ENV VAR — HMAC_SECRET (or AGENT_GAMES_HMAC_SECRET). Fallback for
     hosts with proper secret management.

If neither exists, the agent runs with a clearly-marked local
PLACEHOLDER and cannot validate real platform traffic.

KURIER_API_KEY (zkVerify Kurier mainnet, from kurier.xyz) is optional:
without it the agent still answers tasks and returns proofs inline;
only the background on-chain proof submission is skipped.

See agent/.env.example for the full list.
"""

from __future__ import annotations

import os
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent  # ~/workspace/agentgames/agent
PROJECT_DIR = AGENT_DIR.parent  # ~/workspace/agentgames

# --- Server ---------------------------------------------------------------
PORT = int(os.environ.get("PORT", "8787"))

# --- HMAC secret ------------------------------------------------------------
SECRET_FILE = Path(
    os.environ.get("HMAC_SECRET_FILE", str(AGENT_DIR / "data" / "hmac_secret.txt"))
)
PLACEHOLDER_SECRET = "PLACEHOLDER-REPLACE-WITH-DASHBOARD-SECRET"


def _read_secret_file() -> str:
    try:
        value = SECRET_FILE.read_text().strip()
        return value if value else ""
    except OSError:
        return ""


def _resolve_secret() -> tuple[str, str]:
    """Returns (secret, source) with source in {"file", "env", "placeholder"}."""
    from_file = _read_secret_file()
    if from_file:
        return from_file, "file"
    env_value = (
        os.environ.get("HMAC_SECRET") or os.environ.get("AGENT_GAMES_HMAC_SECRET") or ""
    ).strip()
    if env_value:
        return env_value, "env"
    return PLACEHOLDER_SECRET, "placeholder"


HMAC_SECRET, HMAC_SECRET_SOURCE = _resolve_secret()
HMAC_IS_PLACEHOLDER = HMAC_SECRET_SOURCE == "placeholder"

SIGNATURE_HEADER = "x-agent-games-signature"


def install_secret(value: str) -> None:
    """Persist a newly-pasted secret (mode-600 file) and activate it in
    this process immediately. Called by the one-time /setup endpoint."""
    global HMAC_SECRET, HMAC_SECRET_SOURCE, HMAC_IS_PLACEHOLDER
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (value.strip() + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(SECRET_FILE, 0o600)
    HMAC_SECRET, HMAC_SECRET_SOURCE = value.strip(), "file"
    HMAC_IS_PLACEHOLDER = False


# --- Timing (platform hard deadline is 60 s; stay well under it) ---------
RESPONSE_DEADLINE_MS = int(os.environ.get("RESPONSE_DEADLINE_MS", "55000"))
PROOF_TIMEOUT_MS = int(os.environ.get("PROOF_TIMEOUT_MS", "30000"))

# --- Circuits (Proof Gatekeeper only — Steal the VFY entries are closed) ---
CIRCUITS_DIR = Path(os.environ.get("CIRCUITS_DIR", str(PROJECT_DIR / "circuits")))
CIRCUIT_INFO_PATH = Path(
    os.environ.get("CIRCUIT_INFO_PATH", str(PROJECT_DIR / "circuit-info.json"))
)
GATEKEEPER_WASM = CIRCUITS_DIR / "gatekeeper.wasm"
GATEKEEPER_ZKEY = CIRCUITS_DIR / "gatekeeper_final.zkey"

PROVER_DIR = Path(os.environ.get("PROVER_DIR", str(AGENT_DIR / "prover")))
NODE_BIN = os.environ.get("NODE_BIN", "node")

# --- Kurier (zkVerify proof submission, REST) ------------------------------
KURIER_API_KEY = os.environ.get("KURIER_API_KEY", "").strip()
KURIER_API_URL = os.environ.get(
    "KURIER_API_URL", "https://api.kurier.xyz/api/v1"
).rstrip("/")

# --- Persistence --------------------------------------------------------------
STORE_PATH = Path(os.environ.get("STORE_PATH", str(AGENT_DIR / "data" / "store.json")))
