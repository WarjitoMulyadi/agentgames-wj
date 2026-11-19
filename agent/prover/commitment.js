#!/usr/bin/env node
/**
 * commitment.js — Steal the VFY strategy commitment tool.
 *
 *   commitment = Poseidon(strategyParams[0..7], salt)   (params first, salt last)
 *
 * computed with circomlibjs Poseidon over the BN128 field — the same
 * construction the vfy-policy circuit enforces.
 *
 * Usage:
 *   node commitment.js compute <paramsCsv> <salt>
 *       paramsCsv: 8 comma-separated integers, e.g. "10,0,0,1,0,0,0,0"
 *       salt:      decimal string or 0x-prefixed hex, must be < BN128 modulus
 *       -> stdout: {"commitment": "0x<64 hex>", "commitmentDecimal": "..."}
 *   node commitment.js generate <paramsCsv>
 *       Generates a fresh random 31-byte salt, prints {salt, commitment}.
 *       The salt is a SECRET: store it in the agent env (STRATEGY_SALT),
 *       register only the commitment hash in the dashboard.
 *   node commitment.js golden
 *       Regression check against the publicly documented golden vector:
 *       params [10,0,0,0,0,0,0,0] + salt 123456789 ->
 *       0x0bdd4ea66acf04d7ef79f45af72b709020c9269b8452dd6cab33355d866126cd
 */
"use strict";

const crypto = require("crypto");
const { buildPoseidon } = require("circomlibjs");

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

function parseSalt(raw) {
  const s = String(raw).trim();
  const v = BigInt(s); // BigInt() accepts decimal and 0x-prefixed hex
  if (v < 0n || v >= FIELD_MODULUS) {
    throw new Error("salt must be a BN128 field element (0 <= salt < modulus)");
  }
  return v;
}

function parseParams(csv) {
  const parts = String(csv).split(",").map((x) => x.trim());
  if (parts.length !== 8) throw new Error(`need exactly 8 params, got ${parts.length}`);
  const params = parts.map((x) => {
    if (!/^\d+$/.test(x)) throw new Error(`param is not a non-negative integer: ${x}`);
    return BigInt(x);
  });
  if (params[0] < 1n || params[0] > 10n) {
    throw new Error("params[0] (EXTRACT amount) must be in 1..10 or the circuit assert fails");
  }
  if (params[3] !== 0n && params[3] !== 1n) throw new Error("params[3] must be 0 or 1");
  for (let i = 4; i < 8; i++) {
    if (params[i] !== 0n) throw new Error(`params[${i}] must be exactly 0`);
  }
  return params;
}

async function computeCommitment(params, salt) {
  const poseidon = await getPoseidon();
  const digest = BigInt(poseidon.F.toString(poseidon([...params, salt])));
  return "0x" + digest.toString(16).padStart(64, "0");
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  try {
    if (cmd === "compute") {
      const params = parseParams(args[0]);
      const salt = parseSalt(args[1]);
      const commitment = await computeCommitment(params, salt);
      process.stdout.write(
        JSON.stringify({ commitment, commitmentDecimal: BigInt(commitment).toString() })
      );
    } else if (cmd === "generate") {
      const params = parseParams(args[0]);
      // 31 random bytes -> always < 2^248 < field modulus.
      const salt = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
      const commitment = await computeCommitment(params, salt);
      process.stdout.write(
        JSON.stringify({
          salt: salt.toString(),
          saltHex: "0x" + salt.toString(16),
          commitment,
        })
      );
    } else if (cmd === "golden") {
      const params = parseParams("10,0,0,0,0,0,0,0");
      const commitment = await computeCommitment(params, 123456789n);
      const expected =
        "0x0bdd4ea66acf04d7ef79f45af72b709020c9269b8452dd6cab33355d866126cd";
      process.stdout.write(
        JSON.stringify({ commitment, expected, match: commitment === expected })
      );
      if (commitment !== expected) process.exit(3);
    } else {
      throw new Error(`unknown command: ${cmd}`);
    }
  } catch (err) {
    process.stderr.write(JSON.stringify({ error: String((err && err.message) || err) }) + "\n");
    process.exit(1);
  }
}

main();
