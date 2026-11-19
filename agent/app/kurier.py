"""Kurier — zkVerify's REST proof-submission service (recommended path).

Endpoints (from the official /build examples and the zkVerify handbook):
  POST {KURIER_API_URL}/register-vk/{API_KEY}
       body: {proofType: "groth16",
              proofOptions: {library: "snarkjs", curve: "bn128"}, vk}
  POST {KURIER_API_URL}/submit-proof/{API_KEY}
       body: {proofType: "groth16", vkRegistered: true,
              proofOptions: {library: "snarkjs", curve: "bn128"},
              proofData: {proof, publicSignals, vk: <vk hash>}}
  GET  {KURIER_API_URL}/job-status/{API_KEY}/{jobId}
       status flow: Queued -> Valid -> Submitted -> IncludedInBlock
                    -> Finalized (or Failed)

Design rules:
  * The platform response deadline is 60 s, but Kurier finalization
    waits on block inclusion and can take longer — so submission ALWAYS
    happens in the background, after the task response has been sent.
    The platform re-verifies the inline proof itself; the Kurier job is
    the on-chain audit trail (its job id is the proofReference).
  * The verification key must be registered ONCE before the first
    submit with vkRegistered: true, or every job fails immediately.
    Registration runs in the background at startup, per circuit.
  * No KURIER_API_KEY -> everything is skipped (logged once); the agent
    still answers tasks with inline proofs.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import httpx

from . import config, prover

log = logging.getLogger("agentgames.kurier")

_PROOF_OPTIONS = {"library": "snarkjs", "curve": "bn128"}
_registered_circuits: set[str] = set()
_warned_no_key = False


def circuit_vk_hashes() -> dict[str, str]:
    """vk hashes from the saved /api/circuit-info snapshot."""
    try:
        data = json.loads(config.CIRCUIT_INFO_PATH.read_text())
        circuits = data.get("circuits", {})
        return {
            name: info["vkHash"]
            for name, info in circuits.items()
            if isinstance(info, dict) and "vkHash" in info
        }
    except (OSError, json.JSONDecodeError):
        return {}


def _zkey_for(circuit: str) -> Path:
    # Proof Gatekeeper is the only live track (Steal the VFY is closed).
    return config.GATEKEEPER_ZKEY


async def _post(client: httpx.AsyncClient, url: str, body: dict) -> dict:
    resp = await client.post(url, json=body)
    if resp.status_code >= 300:
        raise RuntimeError(f"Kurier {resp.status_code}: {resp.text[:300]}")
    return resp.json()


async def _get(client: httpx.AsyncClient, url: str) -> dict:
    resp = await client.get(url)
    if resp.status_code >= 300:
        raise RuntimeError(f"Kurier {resp.status_code}: {resp.text[:300]}")
    return resp.json()


async def register_vk(circuit: str) -> str | None:
    """Register one circuit's verification key with Kurier (once).
    Returns the vk hash Kurier reports, or None when skipped/failed."""
    global _warned_no_key
    if not config.KURIER_API_KEY:
        if not _warned_no_key:
            log.info("Kurier skipped: KURIER_API_KEY is not set")
            _warned_no_key = True
        return None
    if circuit in _registered_circuits:
        return circuit_vk_hashes().get(circuit)
    vk = prover.export_verification_key(_zkey_for(circuit))
    async with httpx.AsyncClient(timeout=30.0) as client:
        raw = await _post(
            client,
            f"{config.KURIER_API_URL}/register-vk/{config.KURIER_API_KEY}",
            {"proofType": "groth16", "proofOptions": _PROOF_OPTIONS, "vk": vk},
        )
    _registered_circuits.add(circuit)
    vk_hash = raw.get("vkHash") or raw.get("uniq_vk_hash") or circuit_vk_hashes().get(circuit)
    log.info("Kurier VK registered for %s (vkHash=%s)", circuit, vk_hash)
    return vk_hash


async def submit_proof(circuit: str, proof: dict, public_signals: list[str]) -> str:
    """Submit one proof; returns the Kurier jobId."""
    vk_hash = circuit_vk_hashes().get(circuit)
    async with httpx.AsyncClient(timeout=30.0) as client:
        raw = await _post(
            client,
            f"{config.KURIER_API_URL}/submit-proof/{config.KURIER_API_KEY}",
            {
                "proofType": "groth16",
                "vkRegistered": True,
                "proofOptions": _PROOF_OPTIONS,
                "proofData": {
                    "proof": proof,
                    "publicSignals": public_signals,
                    "vk": vk_hash,
                },
            },
        )
    job_id = raw.get("jobId")
    if not job_id:
        raise RuntimeError(f"Kurier submit-proof returned no jobId: {str(raw)[:300]}")
    return job_id


async def poll_job(job_id: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> str:
    """Poll job-status until Finalized/Failed or timeout; returns the
    final status string."""
    waited = 0.0
    status = "unknown"
    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            raw = await _get(
                client,
                f"{config.KURIER_API_URL}/job-status/{config.KURIER_API_KEY}/{job_id}",
            )
            status = str(raw.get("status", ""))
            if status in ("Finalized", "Failed"):
                return status
            if waited >= timeout_s:
                return f"TIMEOUT(last={status or 'unknown'})"
            await asyncio.sleep(interval_s)
            waited += interval_s


async def submit_proof_background(circuit: str, proof: dict, public_signals: list[str]) -> None:
    """Fire-and-forget pipeline: ensure VK registered -> submit -> poll.
    Never raises; failures are logged only. Call with asyncio.create_task
    AFTER the platform response has been sent."""
    if not config.KURIER_API_KEY:
        return
    try:
        await register_vk(circuit)
        job_id = await submit_proof(circuit, proof, public_signals)
        log.info("Kurier %s proof submitted, jobId=%s", circuit, job_id)
        status = await poll_job(job_id)
        log.info("Kurier job %s final status: %s", job_id, status)
    except Exception as exc:  # background path must never crash the agent
        log.warning("Kurier background submission failed (%s): %s", circuit, exc)


async def register_vk_background() -> None:
    """Startup hook: register the Gatekeeper VK (best effort)."""
    if not config.KURIER_API_KEY:
        return
    try:
        await register_vk("gatekeeper")
    except Exception as exc:
        log.warning("Kurier VK registration failed (gatekeeper): %s", exc)
