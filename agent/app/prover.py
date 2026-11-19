"""Bridge to the Node/snarkjs prover (agent/prover/prove.js).

All Groth16 work happens in Node: witness generation from the official
Circom WASM and proving with the official .zkey. prove.js also verifies
each proof locally against the official verification key before
returning it — a proof that fails local verification raises here and is
never sent to the platform.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from . import config


class ProverError(RuntimeError):
    pass


def _run_node(script: str, args: list[str], timeout_s: float) -> dict:
    cmd = [config.NODE_BIN, str(config.PROVER_DIR / script), *args]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s
        )
    except subprocess.TimeoutExpired as exc:
        raise ProverError(f"node {script} timed out after {timeout_s:.0f}s") from exc
    except FileNotFoundError as exc:
        raise ProverError(f"node binary not found: {config.NODE_BIN}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip()[:500] or proc.stdout.strip()[:500]
        raise ProverError(f"node {script} failed (exit {proc.returncode}): {detail}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ProverError(f"node {script} returned non-JSON output: {proc.stdout[:200]}") from exc


def generate_proof(wasm: Path, zkey: Path, inputs: dict, timeout_ms: int) -> dict:
    """Run groth16.fullProve + local verify. Returns
    {"proof": {...}, "publicSignals": [str, ...], "selfVerified": True}.
    Raises ProverError on any failure (bad witness, timeout, ...)."""
    if not wasm.exists() or not zkey.exists():
        raise ProverError(f"circuit artifacts missing: {wasm} / {zkey}")
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, dir="/tmp"
    ) as fh:
        json.dump(inputs, fh)
        inputs_path = fh.name
    try:
        return _run_node(
            "prove.js",
            ["prove", str(wasm), str(zkey), inputs_path],
            timeout_s=max(1.0, timeout_ms / 1000.0),
        )
    finally:
        Path(inputs_path).unlink(missing_ok=True)


def export_verification_key(zkey: Path) -> dict:
    if not zkey.exists():
        raise ProverError(f"zkey missing: {zkey}")
    return _run_node("prove.js", ["export-vk", str(zkey)], timeout_s=30.0)


def compute_commitment(params: list[int], salt: str) -> str:
    """Poseidon(params[0..7], salt) as a 0x-prefixed 64-hex string."""
    result = _run_node(
        "commitment.js",
        ["compute", ",".join(str(p) for p in params), str(salt)],
        timeout_s=30.0,
    )
    return result["commitment"]
