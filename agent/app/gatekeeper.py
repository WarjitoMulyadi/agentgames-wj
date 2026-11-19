"""Proof Gatekeeper track.

The platform sends a signed task describing a network transaction plus
the condition it claims to satisfy. The agent answers ONE deterministic
decision — APPROVE or REJECT — backed by a Groth16 proof, generated
locally with the official circuit, that the decision followed the rules.

Scoring (official event page): correct decision +12, wrong APPROVE -6,
wrong REJECT -3, timeout -2, invalid proof -2. So: APPROVE only when
EVERY check passes; any doubt at all -> REJECT (fail closed).

Circuit interface (proven against the official gatekeeper.wasm — the
input names/encodings below are the ones the circuit actually takes):
  inputs (13): registeredVkHash, proofVkHash, minimum, publicBalance,
    expiryBlock, currentBlock, recipient, conditionRecipient, amount,
    maxTransfer, taskId, decision, salt   (salt is the only private input)
  public signals (13): [evaluationCommitment, registeredVkHash,
    proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
    recipient, conditionRecipient, amount, maxTransfer, decision, taskId]
  encodings: vk hashes = BigInt(hex) mod P; taskId = trailing UUID of
    task_id as a 128-bit integer, else keccak256(utf8 task_id) mod P;
    decision 0 = REJECT, 1 = APPROVE; salt = 0 (the platform cannot
    check public signal [0] without the private salt, and skips it).

One trap has NO possible proof: PROOF_REUSED. When every on-chain check
passes, the circuit forces decision = 1, so a REJECT proof cannot exist
for a replayed proof. For that case we answer REJECT with honest public
signals and proof = null — the decision is still delivered; a response
with no proof field at all has been rejected by the platform in scored
rounds, so the signals are always attached.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

from Crypto.Hash import keccak

from . import config, prover

log = logging.getLogger("agentgames.gatekeeper")

BN128_FIELD_PRIME = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

TASK_TYPE = "agent-games.proof-gatekeeper.v1"

REASON_CODES = (
    "VALID_CONDITION",
    "VK_SUBSTITUTION",
    "THRESHOLD_MISMATCH",
    "PROOF_REUSED",
    "EXPIRED_CONDITION",
    "RECIPIENT_MISMATCH",
    "AMOUNT_OVERFLOW",
    "INVALID_TASK",
)


# --------------------------------------------------------------------------
# Field encodings
# --------------------------------------------------------------------------
def _keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def vk_hash_to_field(vk_hex: str) -> str:
    return str(int(vk_hex, 16) % BN128_FIELD_PRIME)


_UUID_TAIL = re.compile(
    r"[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", re.I
)


def task_id_to_field(task_id: str) -> str:
    m = _UUID_TAIL.search(task_id)
    if m:  # R03-style ids: trailing UUID as a 128-bit integer
        return str(int(m.group(0).replace("-", ""), 16))
    digest = _keccak256(task_id.encode("utf-8"))
    return str(int.from_bytes(digest, "big") % BN128_FIELD_PRIME)


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value.strip())
    return None


def _parse_ts_ms(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        return v * 1000.0 if v < 1e12 else v
    if isinstance(value, str) and value.strip():
        s = value.strip()
        if re.fullmatch(r"\d+", s):
            v = float(s)
            return v * 1000.0 if v < 1e12 else v
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp() * 1000.0
    return None


# --------------------------------------------------------------------------
# Task parsing + decision
# --------------------------------------------------------------------------
def parse_task(body: Any) -> tuple[dict | None, str | None]:
    """Validate the envelope structure. Returns (task, None) or
    (None, error) — anything untrustworthy fails closed."""
    if not isinstance(body, dict):
        return None, "body is not a JSON object"
    if body.get("type") != TASK_TYPE:
        return None, f"unknown type: {body.get('type')!r}"
    task_id = body.get("task_id")
    if not isinstance(task_id, str) or not task_id.strip():
        return None, "missing task_id"
    inp = body.get("input")
    if not isinstance(inp, dict):
        return None, "missing input object"
    for name in ("registered_vk", "proof_vk", "recipient", "condition_recipient", "proof_tx"):
        value = inp.get(name)
        if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
            return None, f"input.{name} is not a 0x hex string"
    numbers: dict[str, int] = {}
    for name in ("minimum", "public_balance", "amount", "max_transfer", "expiry_block", "current_block"):
        value = _to_int(inp.get(name))
        if value is None or value < 0:
            return None, f"input.{name} is not a non-negative integer"
        numbers[name] = value
    task = {
        "task_id": task_id.strip(),
        "mode": body.get("mode"),
        "issued_at": body.get("issued_at"),
        "deadline_at": body.get("deadline_at"),
        "input": {
            "registered_vk": inp["registered_vk"].lower(),
            "proof_vk": inp["proof_vk"].lower(),
            "recipient": inp["recipient"].lower(),
            "condition_recipient": inp["condition_recipient"].lower(),
            "proof_tx": inp["proof_tx"].lower(),
            **numbers,
        },
    }
    return task, None


def decide(task: dict, is_proof_seen, now_ms: float | None = None) -> tuple[str, str, str]:
    """Deterministic decision. Returns (decision, reason_code, detail).
    APPROVE only if every check passes."""
    now = now_ms if now_ms is not None else time.time() * 1000.0
    inp = task["input"]

    # Timestamps first: the task must be currently valid before any work.
    if task.get("issued_at") is not None:
        issued = _parse_ts_ms(task["issued_at"])
        if issued is None:
            return "REJECT", "INVALID_TASK", "issued_at unparseable"
        if issued > now + 5 * 60 * 1000:
            return "REJECT", "INVALID_TASK", "issued_at in the future"
    deadline_raw = task.get("deadline_at")
    if deadline_raw is None:
        return "REJECT", "INVALID_TASK", "deadline_at missing"
    deadline = _parse_ts_ms(deadline_raw)
    if deadline is None:
        return "REJECT", "INVALID_TASK", "deadline_at unparseable"
    if now > deadline:
        return "REJECT", "INVALID_TASK", "deadline passed"

    if inp["proof_vk"] != inp["registered_vk"]:
        return "REJECT", "VK_SUBSTITUTION", "proof_vk != registered_vk"
    if inp["public_balance"] < inp["minimum"]:
        return "REJECT", "THRESHOLD_MISMATCH", "public_balance < minimum"
    if inp["recipient"] != inp["condition_recipient"]:
        return "REJECT", "RECIPIENT_MISMATCH", "recipient != condition_recipient"
    if inp["amount"] > inp["max_transfer"]:
        return "REJECT", "AMOUNT_OVERFLOW", "amount > max_transfer"
    if inp["current_block"] >= inp["expiry_block"]:
        return "REJECT", "EXPIRED_CONDITION", "current_block >= expiry_block"
    if is_proof_seen(inp["proof_tx"]):
        return "REJECT", "PROOF_REUSED", "proof_tx already accepted in a previous task"
    return "APPROVE", "VALID_CONDITION", "all checks passed"


# --------------------------------------------------------------------------
# Circuit inputs / public signals
# --------------------------------------------------------------------------
def build_circuit_inputs(task: dict, decision: str) -> dict[str, str]:
    inp = task["input"]
    return {
        "registeredVkHash": vk_hash_to_field(inp["registered_vk"]),
        "proofVkHash": vk_hash_to_field(inp["proof_vk"]),
        "minimum": str(inp["minimum"]),
        "publicBalance": str(inp["public_balance"]),
        "expiryBlock": str(inp["expiry_block"]),
        "currentBlock": str(inp["current_block"]),
        "recipient": str(int(inp["recipient"], 16)),
        "conditionRecipient": str(int(inp["condition_recipient"], 16)),
        "amount": str(inp["amount"]),
        "maxTransfer": str(inp["max_transfer"]),
        "taskId": task_id_to_field(task["task_id"]),
        "decision": "1" if decision == "APPROVE" else "0",
        "salt": "0",
    }


def build_public_signals(task: dict, decision: str) -> list[str]:
    """Honest public signals WITHOUT a proof — the fallback for cases
    where no proof can exist (PROOF_REUSED) or proving failed.
    Index 0 (evaluationCommitment) is a circuit-computed hash over the
    private salt; the platform skips it, so it is an explicit "0"."""
    w = build_circuit_inputs(task, decision)
    return [
        "0",  # [0] evaluationCommitment — not computable without a proof
        w["registeredVkHash"],
        w["proofVkHash"],
        w["minimum"],
        w["publicBalance"],
        w["expiryBlock"],
        w["currentBlock"],
        w["recipient"],
        w["conditionRecipient"],
        w["amount"],
        w["maxTransfer"],
        w["decision"],
        w["taskId"],
    ]


# --------------------------------------------------------------------------
# Task handler
# --------------------------------------------------------------------------
def handle_task(body: dict, store) -> tuple[dict, dict | None]:
    """Answer one Gatekeeper task. Returns (response_body, kurier_job)
    where kurier_job is {"proof":..., "publicSignals":[...]} when a real
    proof was produced (for background Kurier submission), else None."""
    task, error = parse_task(body)
    if task is None:
        # No trustworthy task_id -> answer fail-closed, do not persist.
        # (error is logged by the caller; the wire shape stays minimal)
        return {
            "decision": "REJECT",
            "reason_code": "INVALID_TASK",
            "proof_tx": "0x",
        }, None

    cached = store.get_response(f"gk:{task['task_id']}")
    if cached is not None:
        return cached, None  # redelivery: exact same answer, no re-proving

    decision, reason_code, detail = decide(task, store.is_proof_seen)
    response: dict[str, Any] = {
        "decision": decision,
        "reason_code": reason_code,
        "proof_tx": task["input"]["proof_tx"],
    }

    kurier_job = None
    if reason_code == "PROOF_REUSED":
        # The circuit forces decision=1 when all on-chain checks pass, so
        # a REJECT proof for a replay is impossible. Honest signals only.
        response["proof"] = None
        response["public_signals"] = build_public_signals(task, decision)
    else:
        try:
            result = prover.generate_proof(
                config.GATEKEEPER_WASM,
                config.GATEKEEPER_ZKEY,
                build_circuit_inputs(task, decision),
                timeout_ms=config.PROOF_TIMEOUT_MS,
            )
            response["proof"] = result["proof"]
            response["public_signals"] = result["publicSignals"]
            kurier_job = {
                "proof": result["proof"],
                "publicSignals": result["publicSignals"],
            }
        except prover.ProverError as exc:
            # Proving failed (witness assert, timeout, missing artifacts):
            # still deliver the decision with honest signals + proof null
            # rather than timing out (a timeout scores the same -2 and
            # loses the decision entirely).
            log.warning(
                "proof generation failed for task %s (%s): %s",
                task["task_id"], reason_code, exc,
            )
            response["proof"] = None
            response["public_signals"] = build_public_signals(task, decision)

    store.save_response(f"gk:{task['task_id']}", response)
    if decision == "APPROVE":
        store.mark_proof_seen(task["input"]["proof_tx"])
    return response, kurier_job
