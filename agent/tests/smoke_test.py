#!/usr/bin/env python3
"""End-to-end smoke test against a locally running WJ-ARGUS agent.

The server must be started WITHOUT a configured secret (placeholder
mode), with throwaway store/secret paths, e.g.:

  cd ~/workspace/agentgames/agent
  rm -f /tmp/ag-secret.txt /tmp/ag-store.json
  HMAC_SECRET_FILE=/tmp/ag-secret.txt STORE_PATH=/tmp/ag-store.json \
  PROOF_TIMEOUT_MS=1200000 \
    .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8787

(PROOF_TIMEOUT_MS is huge only because this dev VM throttles sustained
CPU; on a normal host a proof takes ~2 s and 30000 is right.)

The test then:
  1. checks /health and the one-time /setup flow (page open -> paste ->
     secret file mode 600 -> setup locked -> second paste refused),
  2. checks the HMAC gate (bad/missing signature -> 401),
  3. runs a valid Gatekeeper task -> APPROVE with a real Groth16 proof
     that verifies locally against the official VK,
  4. checks idempotent redelivery,
  5. runs a VK-substitution task -> REJECT with a real proof,
  6. checks the preflight handshake.

Run:  .venv/bin/python tests/smoke_test.py
Exits non-zero on the first failed check.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import stat
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = "http://127.0.0.1:8787"
SECRET = "local-smoke-test-secret"
SECRET_FILE = Path("/tmp/ag-secret.txt")
AGENT_DIR = Path(__file__).resolve().parent.parent
CIRCUITS = AGENT_DIR.parent / "circuits"

GATEKEEPER_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
OTHER_VK = "0x7d3a00000000000000000000000000000000000000000000000000000000f291"

PASS = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if not cond:
        print(f"FAIL: {name} {detail}", flush=True)
        sys.exit(1)
    PASS += 1
    print(f"  ok: {name}", flush=True)


def sign(secret: str, raw: bytes) -> str:
    return hmac_mod.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def request(method: str, path: str, raw: bytes | None = None,
            headers: dict | None = None, timeout: float = 1500):
    req = urllib.request.Request(BASE + path, data=raw, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def post_task(body: dict, secret: str | None):
    raw = json.dumps(body).encode()
    headers = {"content-type": "application/json"}
    if secret is not None:
        headers["x-agent-games-signature"] = sign(secret, raw)
    return request("POST", "/agent", raw, headers)


def verify_response_signature(headers, raw: bytes) -> bool:
    sig = headers.get("x-agent-games-signature")
    return sig is not None and hmac_mod.compare_digest(sig, sign(SECRET, raw))


def verify_proof_locally(zkey: Path, proof: dict, signals: list[str]) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as pf:
        json.dump(proof, pf)
        proof_path = pf.name
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as sf:
        json.dump(signals, sf)
        signals_path = sf.name
    try:
        out = subprocess.run(
            ["node", str(AGENT_DIR / "prover" / "prove.js"), "verify",
             str(zkey), proof_path, signals_path],
            capture_output=True, text=True, timeout=1400,
        )
        return out.returncode == 0 and json.loads(out.stdout).get("valid") is True
    finally:
        Path(proof_path).unlink(missing_ok=True)
        Path(signals_path).unlink(missing_ok=True)


def gatekeeper_task(task_id: str, **input_overrides) -> dict:
    now = datetime.now(timezone.utc)
    inp = {
        "registered_vk": GATEKEEPER_VK,
        "proof_vk": GATEKEEPER_VK,
        "minimum": "1000",
        "public_balance": "1460",
        "expiry_block": 19842201,
        "current_block": 19832000,
        "recipient": "0xde4200000000000000000000000000000000009f01",
        "condition_recipient": "0xde4200000000000000000000000000000000009f01",
        "amount": "500",
        "max_transfer": "1000",
        "proof_tx": "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
    }
    inp.update(input_overrides)
    return {
        "type": "agent-games.proof-gatekeeper.v1",
        "task_id": task_id,
        "mode": "competition",
        "issued_at": (now - timedelta(seconds=60)).isoformat(),
        "deadline_at": (now + timedelta(seconds=50)).isoformat(),
        "input": inp,
    }


def main() -> None:
    print("== health (placeholder mode) ==", flush=True)
    status, _, raw = request("GET", "/health")
    health = json.loads(raw)
    check("health ok", status == 200 and health["ok"] is True)
    check("gatekeeper artifacts present",
          health["circuits"]["gatekeeper"]["wasmPresent"] and health["circuits"]["gatekeeper"]["zkeyPresent"])
    check("no secret configured yet", health["hmacConfigured"] is False
          and health["hmacSource"] == "placeholder" and health["setupLocked"] is False)

    print("== one-time /setup flow ==", flush=True)
    status, _, raw = request("GET", "/setup")
    check("setup page is open before setup", status == 200 and b"<form" in raw)
    task = gatekeeper_task("task_R03_16e835e2-9c68-4307-30da-4b8a25ebd319")
    status, _, _ = post_task(task, secret=SECRET)
    check("task rejected before secret is installed (401)", status == 401, f"(got {status})")

    payload = json.dumps({"secret": SECRET}).encode()
    status, headers, raw = request(
        "POST", "/setup", payload, {"content-type": "application/json"})
    check("setup paste accepted", status == 200 and json.loads(raw).get("ok") is True,
          f"(got {status}: {raw[:200]})")
    check("setup response is signed with the new secret",
          verify_response_signature(headers, raw))
    check("secret file exists", SECRET_FILE.exists())
    mode = stat.S_IMODE(os.stat(SECRET_FILE).st_mode)
    check("secret file is mode 600", mode == 0o600, f"(got {oct(mode)})")

    status, _, _ = request("POST", "/setup", payload, {"content-type": "application/json"})
    check("second setup paste refused (403, locked)", status == 403, f"(got {status})")
    status, _, raw = request("GET", "/setup")
    check("setup page shows locked state", status == 200 and b"locked" in raw.lower())
    status, _, raw = request("GET", "/health")
    health = json.loads(raw)
    check("health now reports file-backed secret",
          health["hmacConfigured"] is True and health["hmacSource"] == "file"
          and health["setupLocked"] is True)

    print("== signature gate ==", flush=True)
    status, _, _ = post_task(task, secret="the-wrong-secret")
    check("bad HMAC rejected with 401", status == 401, f"(got {status})")
    status, _, _ = post_task(task, secret=None)
    check("missing signature rejected with 401", status == 401, f"(got {status})")

    print("== gatekeeper: valid condition -> APPROVE with real proof ==", flush=True)
    status, headers, raw = post_task(task, secret=SECRET)
    check("status 200", status == 200, f"(got {status}: {raw[:200]})")
    check("response is signed", verify_response_signature(headers, raw))
    body = json.loads(raw)
    check("decision APPROVE", body["decision"] == "APPROVE", f"(got {body.get('decision')})")
    check("reason VALID_CONDITION", body["reason_code"] == "VALID_CONDITION")
    check("proof present", isinstance(body.get("proof"), dict))
    signals = body["public_signals"]
    check("13 public signals", len(signals) == 13, f"(got {len(signals)})")
    check("signal[11] is decision=1", signals[11] == "1", f"(got {signals[11]})")
    expected_task_field = str(int("16e835e29c68430730da4b8a25ebd319", 16))
    check("signal[12] is UUID-tail taskId", signals[12] == expected_task_field,
          f"(got {signals[12]}, want {expected_task_field})")
    check("proof verifies against official gatekeeper VK",
          verify_proof_locally(CIRCUITS / "gatekeeper_final.zkey", body["proof"], signals))

    print("== gatekeeper: redelivery is idempotent ==", flush=True)
    status2, _, raw2 = post_task(task, secret=SECRET)
    check("redelivery returns the identical body", status2 == 200 and raw2 == raw)

    print("== gatekeeper: VK substitution -> REJECT with proof ==", flush=True)
    task2 = gatekeeper_task(
        "task_R03_26e835e2-9c68-4307-30da-4b8a25ebd319",
        proof_vk=OTHER_VK,
        proof_tx="0xb4c1000000000000000000000000000000000000000000000000000000008ff2",
    )
    status, headers, raw = post_task(task2, secret=SECRET)
    body = json.loads(raw)
    check("status 200 + signed", status == 200 and verify_response_signature(headers, raw))
    check("decision REJECT", body["decision"] == "REJECT")
    check("reason VK_SUBSTITUTION", body["reason_code"] == "VK_SUBSTITUTION")
    check("proof present with decision signal 0",
          isinstance(body.get("proof"), dict) and body["public_signals"][11] == "0")
    check("reject proof verifies locally",
          verify_proof_locally(CIRCUITS / "gatekeeper_final.zkey", body["proof"], body["public_signals"]))

    print("== preflight ==", flush=True)
    status, headers, raw = post_task(
        {"type": "agent-games.preflight.v1", "agent_id": "smoke", "nonce": "n1"},
        secret=SECRET,
    )
    body = json.loads(raw)
    check("preflight ok", status == 200 and body.get("ok") is True
          and body.get("protocolVersion") == "v1" and verify_response_signature(headers, raw))

    print(f"\nALL {PASS} SMOKE CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()
