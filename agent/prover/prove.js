#!/usr/bin/env node
/**
 * prove.js — Node bridge between the Python agent and snarkjs.
 *
 * The FastAPI app shells out to this script for everything Groth16:
 * witness generation + proving are far better supported in Node
 * (snarkjs) than in Python, and the official circuit artifacts
 * (Circom 2.x WASM + .zkey) are consumed directly.
 *
 * Usage:
 *   node prove.js prove     <wasmPath> <zkeyPath> <inputsJsonPath>
 *       -> stdout: {"proof": {...}, "publicSignals": ["..."], "selfVerified": true}
 *       Runs groth16.fullProve, then verifies the proof locally against
 *       the verification key exported from the .zkey. A proof that fails
 *       local verification is NEVER returned as valid (exit code 3) —
 *       the platform would reject it anyway.
 *   node prove.js export-vk <zkeyPath>
 *       -> stdout: the verification key JSON (for Kurier register-vk).
 *   node prove.js verify    <zkeyPath> <proofJsonPath> <signalsJsonPath>
 *       -> stdout: {"valid": true|false}
 *
 * Errors are printed to stderr as JSON and the exit code is non-zero.
 */
"use strict";

const fs = require("fs");
const snarkjs = require("snarkjs");

function fail(code, message) {
  process.stderr.write(JSON.stringify({ error: message }) + "\n");
  process.exit(code);
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  try {
    if (cmd === "prove") {
      const [wasmPath, zkeyPath, inputsPath] = args;
      const inputs = JSON.parse(fs.readFileSync(inputsPath, "utf8"));
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        inputs,
        wasmPath,
        zkeyPath
      );
      const signals = publicSignals.map(String);
      const vk = await snarkjs.zKey.exportVerificationKey(zkeyPath);
      const ok = await snarkjs.groth16.verify(vk, signals, proof);
      if (!ok) {
        fail(3, "proof failed local groth16.verify against the official VK");
      }
      process.stdout.write(
        JSON.stringify({ proof, publicSignals: signals, selfVerified: true })
      );
    } else if (cmd === "export-vk") {
      const [zkeyPath] = args;
      const vk = await snarkjs.zKey.exportVerificationKey(zkeyPath);
      process.stdout.write(JSON.stringify(vk));
    } else if (cmd === "verify") {
      const [zkeyPath, proofPath, signalsPath] = args;
      const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
      const signals = JSON.parse(fs.readFileSync(signalsPath, "utf8")).map(String);
      const vk = await snarkjs.zKey.exportVerificationKey(zkeyPath);
      const ok = await snarkjs.groth16.verify(vk, signals, proof);
      process.stdout.write(JSON.stringify({ valid: ok }));
    } else {
      fail(2, `unknown command: ${cmd}`);
    }
  } catch (err) {
    fail(1, String((err && err.message) || err));
  }
}

main();
