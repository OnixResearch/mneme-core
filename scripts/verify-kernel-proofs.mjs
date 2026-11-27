#!/usr/bin/env node
// Kernel proof gate & signed Proof-Carrying Code receipt emitter.
//
// 1. Translate crates/mneme-kernel with Charon and Aeneas and require the
//    result to be byte-identical to the checked-in proofs/kernel/MnemeKernel.lean,
//    so the theorems are about the Rust source that is actually compiled.
// 2. Refuse escape hatches in the proof sources.
// 3. Build the proofs with the pinned Lean toolchain and Aeneas library.
// 4. Require every inventoried theorem to exist, every public theorem to be
//    inventoried with exactly the statement that is in the source, every public
//    kernel function to be the subject of a theorem, and every theorem to
//    depend only on Lean's three standard axioms.
// 5. Replay all compiled MnemeKernel / MnemeKernelProofs .olean constants
//    directly through the minimal-TCB Lean C++ kernel (`Lean.Kernel.Environment.replay`)
//    bypassing the elaborator, export a compressed canonical proof artifact,
//    bind the receipt to the BLAKE3 Merkle root of the kernel sources, and
//    sign the canonical Preserves binary payload with Ed25519
//    (`mneme-kernel-proof-receipt/v2`).
//
// Standalone verification mode:
//   node scripts/verify-kernel-proofs.mjs --verify-receipt <file|-> [--skip-source-tree] [--root <dir>]
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync, gzipSync } from 'node:zlib';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const proofRoot = path.join(root, 'proofs', 'kernel');
const kernelRoot = path.join(root, 'crates', 'mneme-kernel');
const translation = 'MnemeKernel.lean';
const allowedAxioms = new Set(['propext', 'Classical.choice', 'Quot.sound']);
const forbidden = /(?<![.\w'])(sorry|admit|axiom|native_decide|unsafe|opaque|implemented_by|extern)(?![\w'])/;
const expectedLean = '4.35.0';

export const KERNEL_PROOF_RECEIPT_V2_FORMAT = 'mneme-kernel-proof-receipt/v2';

// PKCS#8 DER prefix for a 32-byte raw Ed25519 seed (RFC 8410).
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
// SPKI DER prefix for a 32-byte raw Ed25519 public key (RFC 8410).
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export class GateError extends Error {}

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

// ---------------------------------------------------------------------------
// Pure-JS BLAKE3 (official reference specification, 32-byte output)
// ---------------------------------------------------------------------------

const BLAKE3_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
const BLAKE3_MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const BLAKE3_CHUNK_START = 1;
const BLAKE3_CHUNK_END = 2;
const BLAKE3_PARENT = 4;
const BLAKE3_ROOT = 8;
const BLAKE3_BLOCK_LEN = 64;
const BLAKE3_CHUNK_LEN = 1024;

function rotr32(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function blake3G(s, a, b, c, d, mx, my) {
  s[a] = (s[a] + s[b] + mx) | 0;
  s[d] = rotr32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) | 0;
  s[b] = rotr32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b] + my) | 0;
  s[d] = rotr32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) | 0;
  s[b] = rotr32(s[b] ^ s[c], 7);
}

function blake3Round(s, m) {
  blake3G(s, 0, 4, 8, 12, m[0], m[1]);
  blake3G(s, 1, 5, 9, 13, m[2], m[3]);
  blake3G(s, 2, 6, 10, 14, m[4], m[5]);
  blake3G(s, 3, 7, 11, 15, m[6], m[7]);
  blake3G(s, 0, 5, 10, 15, m[8], m[9]);
  blake3G(s, 1, 6, 11, 12, m[10], m[11]);
  blake3G(s, 2, 7, 8, 13, m[12], m[13]);
  blake3G(s, 3, 4, 9, 14, m[14], m[15]);
}

function blake3Compress(cv, blockWords, counter, blockLen, flags) {
  const s = new Uint32Array(16);
  s.set(cv, 0);
  s[8] = BLAKE3_IV[0];
  s[9] = BLAKE3_IV[1];
  s[10] = BLAKE3_IV[2];
  s[11] = BLAKE3_IV[3];
  s[12] = Number(counter & 0xffffffffn);
  s[13] = Number((counter >> 32n) & 0xffffffffn);
  s[14] = blockLen >>> 0;
  s[15] = flags >>> 0;

  let m = Uint32Array.from(blockWords);
  for (let round = 0; round < 7; round += 1) {
    blake3Round(s, m);
    if (round < 6) {
      const next = new Uint32Array(16);
      for (let i = 0; i < 16; i += 1) next[i] = m[BLAKE3_MSG_PERM[i]];
      m = next;
    }
  }
  for (let i = 0; i < 8; i += 1) {
    s[i] ^= s[i + 8];
    s[i + 8] ^= cv[i];
  }
  return s;
}

function bytesToWords16(bytes) {
  const words = new Uint32Array(16);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < 16; i += 1) {
    words[i] = view.getUint32(i * 4, true);
  }
  return words;
}

function words8ToBytes(words) {
  const out = Buffer.allocUnsafe(32);
  for (let i = 0; i < 8; i += 1) {
    out.writeUInt32LE(words[i] >>> 0, i * 4);
  }
  return out;
}

function blake3Output(cv, blockWords, counter, blockLen, flags) {
  return {
    chainingValue() {
      return blake3Compress(cv, blockWords, counter, blockLen, flags).subarray(0, 8);
    },
    rootBytes() {
      return words8ToBytes(blake3Compress(cv, blockWords, 0n, blockLen, flags | BLAKE3_ROOT));
    },
  };
}

function blake3ParentOutput(leftCv, rightCv) {
  const blockWords = new Uint32Array(16);
  blockWords.set(leftCv, 0);
  blockWords.set(rightCv, 8);
  return blake3Output(BLAKE3_IV, blockWords, 0n, BLAKE3_BLOCK_LEN, BLAKE3_PARENT);
}

/** Compute the 32-byte BLAKE3 digest of `input` (Buffer or Uint8Array). */
export function blake3(input) {
  const data = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const cvStack = [];
  let chunkCv = Uint32Array.from(BLAKE3_IV);
  let chunkCounter = 0n;
  let block = Buffer.alloc(BLAKE3_BLOCK_LEN);
  let blockLen = 0;
  let blocksCompressed = 0;

  const chunkOutput = () => {
    const padded = Buffer.alloc(BLAKE3_BLOCK_LEN);
    block.copy(padded, 0, 0, blockLen);
    let flags = BLAKE3_CHUNK_END;
    if (blocksCompressed === 0) flags |= BLAKE3_CHUNK_START;
    return blake3Output(chunkCv, bytesToWords16(padded), chunkCounter, blockLen, flags);
  };

  let offset = 0;
  while (offset < data.length) {
    if (blocksCompressed * BLAKE3_BLOCK_LEN + blockLen === BLAKE3_CHUNK_LEN) {
      let finishedCv = chunkOutput().chainingValue();
      let totalChunks = chunkCounter + 1n;
      while ((totalChunks & 1n) === 0n) {
        finishedCv = blake3ParentOutput(cvStack.pop(), finishedCv).chainingValue();
        totalChunks >>= 1n;
      }
      cvStack.push(finishedCv);
      chunkCv = Uint32Array.from(BLAKE3_IV);
      chunkCounter += 1n;
      block = Buffer.alloc(BLAKE3_BLOCK_LEN);
      blockLen = 0;
      blocksCompressed = 0;
    }

    if (blockLen === BLAKE3_BLOCK_LEN) {
      const flags = blocksCompressed === 0 ? BLAKE3_CHUNK_START : 0;
      chunkCv = blake3Compress(chunkCv, bytesToWords16(block), chunkCounter, BLAKE3_BLOCK_LEN, flags).subarray(0, 8);
      blocksCompressed += 1;
      block = Buffer.alloc(BLAKE3_BLOCK_LEN);
      blockLen = 0;
    }

    const want = Math.min(BLAKE3_BLOCK_LEN - blockLen, data.length - offset);
    data.copy(block, blockLen, offset, offset + want);
    blockLen += want;
    offset += want;
  }

  let output = chunkOutput();
  while (cvStack.length > 0) {
    output = blake3ParentOutput(cvStack.pop(), output.chainingValue());
  }
  return output.rootBytes();
}

export function blake3Hex(input) {
  return blake3(input).toString('hex');
}

/**
 * Compute the deterministic RFC 6962 / Crosby-Wallach BLAKE3 Merkle root over
 * sorted `(relative_path, file_bytes)` pairs, matching
 * `mneme_core::compute_source_tree_merkle_root` byte-for-byte.
 */
export function computeSourceTreeMerkleRoot(entries) {
  if (entries.length === 0) return blake3(Buffer.alloc(0));
  const sorted = [...entries].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const peaks = [];
  for (const [relPath, bytes] of sorted) {
    const pathBuf = Buffer.from(relPath, 'utf8');
    const contentBuf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    const leafInput = Buffer.concat([Buffer.from([0x00]), pathBuf, Buffer.from([0x00]), contentBuf]);
    let cur = blake3(leafInput);
    let size = 1n;
    while (peaks.length > 0 && peaks[peaks.length - 1].size === size) {
      const left = peaks.pop().digest;
      cur = blake3(Buffer.concat([Buffer.from([0x01]), left, cur]));
      size *= 2n;
    }
    peaks.push({ size, digest: cur });
  }
  let acc = peaks.pop().digest;
  while (peaks.length > 0) {
    const left = peaks.pop().digest;
    acc = blake3(Buffer.concat([Buffer.from([0x01]), left, acc]));
  }
  return acc;
}

/**
 * Compute the BLAKE3 Merkle root over `crates/mneme-kernel/src/*.rs`,
 * `proofs/kernel/MnemeKernel.lean`, and `proofs/kernel/inventory.json`.
 */
export async function computeKernelSourceTreeBlake3(repoRoot = root) {
  const kernelSrc = path.join(repoRoot, 'crates', 'mneme-kernel', 'src');
  const rsFiles = (await readdir(kernelSrc)).filter((name) => name.endsWith('.rs')).sort();
  const entries = [];
  for (const file of rsFiles) {
    const rel = `crates/mneme-kernel/src/${file}`;
    entries.push([rel, await readFile(path.join(kernelSrc, file))]);
  }
  for (const rel of ['proofs/kernel/MnemeKernel.lean', 'proofs/kernel/inventory.json']) {
    entries.push([rel, await readFile(path.join(repoRoot, rel))]);
  }
  return computeSourceTreeMerkleRoot(entries).toString('hex');
}

// ---------------------------------------------------------------------------
// Canonical Preserves Binary Encoder (matching `mneme_core::binary::encode`)
// ---------------------------------------------------------------------------

const TAG_FALSE = 0x80;
const TAG_TRUE = 0x81;
const TAG_END = 0x84;
const TAG_INTEGER = 0xb0;
const TAG_STRING = 0xb1;
const TAG_BYTESTRING = 0xb2;
const TAG_SYMBOL = 0xb3;
const TAG_RECORD = 0xb4;
const TAG_SEQUENCE = 0xb5;
const TAG_DICTIONARY = 0xb7;

function encodeVarint(value) {
  let v = BigInt(value);
  const out = [];
  while (true) {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    out.push(byte);
    if (v === 0n) break;
  }
  return Buffer.from(out);
}

function encodeSignedIntBytes(value) {
  let v = BigInt(value);
  if (v === 0n) return Buffer.alloc(0);
  const bytes = [];
  if (v > 0n) {
    while (v > 0n) {
      bytes.push(Number(v & 0xffn));
      v >>= 8n;
    }
    if ((bytes[bytes.length - 1] & 0x80) !== 0) bytes.push(0x00);
  } else {
    while (v < -1n) {
      bytes.push(Number(v & 0xffn));
      v >>= 8n;
    }
    bytes.push(Number(v & 0xffn));
    if ((bytes[bytes.length - 1] & 0x80) === 0) bytes.push(0xff);
  }
  bytes.reverse();
  return Buffer.from(bytes);
}

const pSym = (text) => ({ kind: 'symbol', value: text });
const pStr = (text) => ({ kind: 'string', value: text });
const pInt = (num) => ({ kind: 'integer', value: num });
const pSeq = (items) => ({ kind: 'sequence', value: items });
const pDict = (entries) => ({ kind: 'dictionary', value: entries });
const pRec = (label, fields) => ({ kind: 'record', label, fields });

export function encodePreserves(val) {
  switch (val.kind) {
    case 'bool':
      return Buffer.from([val.value ? TAG_TRUE : TAG_FALSE]);
    case 'integer': {
      const payload = encodeSignedIntBytes(val.value);
      return Buffer.concat([Buffer.from([TAG_INTEGER]), encodeVarint(payload.length), payload]);
    }
    case 'string': {
      const payload = Buffer.from(val.value, 'utf8');
      return Buffer.concat([Buffer.from([TAG_STRING]), encodeVarint(payload.length), payload]);
    }
    case 'bytes': {
      const payload = Buffer.isBuffer(val.value) ? val.value : Buffer.from(val.value);
      return Buffer.concat([Buffer.from([TAG_BYTESTRING]), encodeVarint(payload.length), payload]);
    }
    case 'symbol': {
      const payload = Buffer.from(val.value, 'utf8');
      return Buffer.concat([Buffer.from([TAG_SYMBOL]), encodeVarint(payload.length), payload]);
    }
    case 'sequence': {
      const parts = [Buffer.from([TAG_SEQUENCE]), ...val.value.map(encodePreserves), Buffer.from([TAG_END])];
      return Buffer.concat(parts);
    }
    case 'record': {
      const parts = [
        Buffer.from([TAG_RECORD]),
        encodePreserves(val.label),
        ...val.fields.map(encodePreserves),
        Buffer.from([TAG_END]),
      ];
      return Buffer.concat(parts);
    }
    case 'dictionary': {
      const encoded = val.value.map(([k, v]) => [encodePreserves(k), encodePreserves(v)]);
      encoded.sort((a, b) => Buffer.compare(a[0], b[0]));
      const parts = [Buffer.from([TAG_DICTIONARY])];
      for (const [kb, vb] of encoded) {
        parts.push(kb, vb);
      }
      parts.push(Buffer.from([TAG_END]));
      return Buffer.concat(parts);
    }
    default:
      throw new GateError(`unsupported Preserves kind: ${val.kind}`);
  }
}

/**
 * Encode the canonical Preserves binary payload signed by Ed25519 for
 * `mneme-kernel-proof-receipt/v2`.
 */
export function encodeKernelProofReceiptV2Preserves(receipt) {
  const artifact = receipt.proofArtifact ?? {};
  const axioms = [...(receipt.axioms ?? [])].sort();
  return encodePreserves(
    pRec(pSym('mneme-kernel-proof-receipt-v2'), [
      pDict([
        [pSym('artifact-digest-blake3'), pStr(String(artifact.artifactDigestBlake3 ?? ''))],
        [pSym('axioms'), pSeq(axioms.map(pStr))],
        [pSym('checker'), pStr(String(artifact.checker ?? ''))],
        [pSym('format'), pStr(String(receipt.format ?? ''))],
        [pSym('kernel-functions'), pInt(receipt.kernelFunctions ?? 0)],
        [pSym('lean'), pStr(String(receipt.lean ?? ''))],
        [pSym('replayed-constants'), pInt(artifact.constants ?? 0)],
        [pSym('replayed-theorems'), pInt(artifact.replayedTheorems ?? 0)],
        [pSym('source-tree-blake3'), pStr(String(receipt.sourceTreeBlake3 ?? ''))],
        [pSym('theorems'), pInt(receipt.theorems ?? 0)],
        [pSym('translation-sha256'), pStr(String(receipt.translationSha256 ?? ''))],
        [pSym('verdict'), pSym(String(receipt.verdict ?? ''))],
        [pSym('version'), pInt(receipt.version ?? 0)],
      ]),
    ]),
  );
}

// ---------------------------------------------------------------------------
// Ed25519 signing and verification (RFC 8032 / RFC 8410)
// ---------------------------------------------------------------------------

async function loadSigningKey() {
  let seedHex = process.env.MNEME_PROOF_SIGNING_KEY_HEX?.trim();
  let keySource = 'env-hex';
  if (!seedHex && process.env.MNEME_PROOF_SIGNING_KEY_FILE) {
    keySource = 'env-file';
    const raw = await readFile(process.env.MNEME_PROOF_SIGNING_KEY_FILE);
    if (raw.length === 32) {
      seedHex = raw.toString('hex');
    } else {
      const text = raw.toString('utf8').trim();
      if (text.startsWith('-----BEGIN')) {
        const privateKey = createPrivateKey(text);
        const publicKey = createPublicKey(privateKey);
        const pubRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
        return { privateKey, publicKeyHex: pubRaw.toString('hex'), keySource };
      }
      seedHex = text;
    }
  }
  if (seedHex) {
    if (!/^[0-9a-f]{64}$/i.test(seedHex)) {
      throw new GateError('MNEME_PROOF_SIGNING_KEY must be 64 hex characters (32-byte Ed25519 seed)');
    }
    const seed = Buffer.from(seedHex, 'hex');
    const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
    const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    const publicKey = createPublicKey(privateKey);
    const pubRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    return { privateKey, publicKeyHex: pubRaw.toString('hex'), keySource };
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey, publicKeyHex: pubRaw.toString('hex'), keySource: 'ephemeral' };
}

export function verifyEd25519Signature(payload, publicKeyHex, signatureHex) {
  if (!/^[0-9a-f]{64}$/i.test(publicKeyHex) || !/^[0-9a-f]{128}$/i.test(signatureHex)) {
    return false;
  }
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, 'hex')]);
  const publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return cryptoVerify(null, payload, publicKey, Buffer.from(signatureHex, 'hex'));
}

// ---------------------------------------------------------------------------
// Standalone receipt verification (< 2s fail-closed check)
// ---------------------------------------------------------------------------

/**
 * Verify a `mneme-kernel-proof-receipt/v2` JSON object:
 * - format/version/verdict checks
 * - canonical Preserves binary reconstruction & byte-equality check
 * - Ed25519 signature verification over canonical Preserves bytes
 * - gzip proof export decompression, BLAKE3 digest binding, and structural check
 * - optional live BLAKE3 source-tree Merkle root check against `repoRoot`
 */
export async function verifyKernelProofReceipt(receipt, options = {}) {
  const { checkSourceTree = true, repoRoot = root, expectedPublicKeyHex = null } = options;
  if (!receipt || typeof receipt !== 'object') {
    throw new GateError('receipt must be a JSON object');
  }
  if (receipt.format !== KERNEL_PROOF_RECEIPT_V2_FORMAT || receipt.version !== 2) {
    throw new GateError(
      `unsupported receipt format/version: ${receipt.format ?? 'missing'} v${receipt.version ?? '?'}`,
    );
  }
  if (receipt.verdict !== 'passed') {
    throw new GateError(`receipt verdict is not passed: ${receipt.verdict ?? 'missing'}`);
  }
  const sig = receipt.signature;
  if (!sig || sig.algorithm !== 'ed25519' || typeof sig.publicKeyHex !== 'string' || typeof sig.signatureHex !== 'string') {
    throw new GateError('receipt is missing a valid ed25519 signature block');
  }
  if (expectedPublicKeyHex && sig.publicKeyHex.toLowerCase() !== expectedPublicKeyHex.toLowerCase()) {
    throw new GateError(`receipt signer ${sig.publicKeyHex} does not match expected key ${expectedPublicKeyHex}`);
  }
  if (typeof receipt.canonicalPayloadBase64 !== 'string' || receipt.canonicalPayloadBase64.length === 0) {
    throw new GateError('receipt missing canonicalPayloadBase64');
  }
  const declaredPayload = Buffer.from(receipt.canonicalPayloadBase64, 'base64');
  const expectedPayload = encodeKernelProofReceiptV2Preserves(receipt);
  if (!declaredPayload.equals(expectedPayload)) {
    throw new GateError('receipt canonical Preserves payload does not match receipt fields');
  }
  if (!verifyEd25519Signature(declaredPayload, sig.publicKeyHex, sig.signatureHex)) {
    throw new GateError('receipt Ed25519 signature verification failed');
  }
  const artifact = receipt.proofArtifact;
  if (!artifact || typeof artifact !== 'object') {
    throw new GateError('receipt missing proofArtifact');
  }
  if (typeof artifact.compressedExportBase64 !== 'string' || typeof artifact.artifactDigestBlake3 !== 'string') {
    throw new GateError('receipt proofArtifact missing compressedExportBase64 or artifactDigestBlake3');
  }
  let uncompressed;
  try {
    uncompressed = gunzipSync(Buffer.from(artifact.compressedExportBase64, 'base64'));
  } catch (error) {
    throw new GateError(`proofArtifact decompression failed (possible corruption/tamper): ${error.message}`);
  }
  const actualDigest = blake3Hex(uncompressed);
  if (actualDigest !== artifact.artifactDigestBlake3) {
    throw new GateError(
      `proofArtifact BLAKE3 digest mismatch: expected ${artifact.artifactDigestBlake3}, got ${actualDigest}`,
    );
  }
  const exportLines = uncompressed.toString('utf8').split('\n').filter(Boolean);
  const theoremLines = exportLines.filter((line) => line.startsWith('THEOREM '));
  if (theoremLines.length !== receipt.theorems || theoremLines.length !== artifact.replayedTheorems) {
    throw new GateError(
      `proofArtifact theorem count mismatch: export has ${theoremLines.length}, receipt claims ${receipt.theorems}`,
    );
  }
  const constantsLine = exportLines.find((line) => line.startsWith('CONSTANTS '));
  if (!constantsLine || Number(constantsLine.slice('CONSTANTS '.length)) !== artifact.constants) {
    throw new GateError('proofArtifact constant count mismatch');
  }
  if (checkSourceTree) {
    const actualSourceRoot = await computeKernelSourceTreeBlake3(repoRoot);
    if (actualSourceRoot !== receipt.sourceTreeBlake3) {
      throw new GateError(
        `sourceTreeBlake3 mismatch: receipt binds ${receipt.sourceTreeBlake3}, tree is ${actualSourceRoot}`,
      );
    }
  }
  return {
    theorems: receipt.theorems,
    kernelFunctions: receipt.kernelFunctions,
    constants: artifact.constants,
    sourceTreeBlake3: receipt.sourceTreeBlake3,
    publicKeyHex: sig.publicKeyHex,
  };
}

// ---------------------------------------------------------------------------
// Lean / Charon / Aeneas pipeline helpers
// ---------------------------------------------------------------------------

function tool(name, variable) {
  return process.env[variable] || name;
}

function run(label, argv, options = {}) {
  const result = spawnSync(argv[0], argv.slice(1), {
    cwd: options.cwd ?? root,
    env: options.env ?? process.env,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  if (result.error) {
    throw new GateError(`${label}: cannot run ${argv[0]}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const tail = `${result.stdout}\n${result.stderr}`.trim().split('\n').slice(-40).join('\n');
    throw new GateError(`${label}: exit ${result.status}\n${tail}`);
  }
  return `${result.stdout}${result.stderr}`;
}

/** Strip Lean comments and string literals so the escape-hatch scan sees code only. */
export function stripLean(text) {
  let out = '';
  let index = 0;
  let depth = 0;
  while (index < text.length) {
    const two = text.slice(index, index + 2);
    if (depth > 0) {
      if (two === '/-') { depth += 1; index += 2; }
      else if (two === '-/') { depth -= 1; index += 2; }
      else { if (text[index] === '\n') out += '\n'; index += 1; }
    } else if (two === '/-') { depth = 1; index += 2; }
    else if (two === '--') {
      while (index < text.length && text[index] !== '\n') index += 1;
    } else if (text[index] === '"') {
      index += 1;
      while (index < text.length && text[index] !== '"') {
        index += text[index] === '\\' ? 2 : 1;
      }
      index += 1;
      out += '""';
    } else { out += text[index]; index += 1; }
  }
  return out;
}

/** Public theorem names declared in one proof file, qualified by its namespaces. */
export function declaredTheorems(text) {
  return [...theoremStatements(text).keys()];
}

/**
 * Public theorems declared in one proof file: qualified name to statement.
 * The statement is the text between the theorem name and the `:=` that starts
 * its proof, with whitespace collapsed, so the inventory pins what is claimed.
 */
export function theoremStatements(text) {
  const statements = new Map();
  const namespaces = [];
  const lines = stripLean(text).split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const opened = /^namespace\s+(\S+)/.exec(line);
    if (opened) { namespaces.push(opened[1]); continue; }
    const closed = /^end\s+(\S+)/.exec(line);
    if (closed && namespaces.at(-1) === closed[1]) { namespaces.pop(); continue; }
    const declared = /^(?:@\[[^\]]*\]\s*)*(private\s+|protected\s+)?(?:theorem|lemma)\s+([^\s:({\[]+)/.exec(line);
    if (!declared || declared[1]) continue;
    let body = line.slice(declared.index + declared[0].length);
    let cursor = index;
    while (!/:=/.test(body) && cursor + 1 < lines.length) {
      cursor += 1;
      body += `\n${lines[cursor]}`;
    }
    const proofStart = body.search(/:=\s*(by\b|$)/m);
    const statement = (proofStart >= 0 ? body.slice(0, proofStart) : body.split(':=')[0]).replace(/\s+/g, ' ').trim();
    statements.set([...namespaces, declared[2]].join('.'), statement);
  }
  return statements;
}

/** Public functions of the kernel crate as `module::function`. */
export async function kernelFunctions() {
  const source = path.join(kernelRoot, 'src');
  const functions = [];
  for (const file of (await readdir(source)).sort()) {
    if (!file.endsWith('.rs') || file === 'lib.rs') continue;
    const text = await readFile(path.join(source, file), 'utf8');
    for (const match of text.matchAll(/^pub fn ([a-z0-9_]+)/gm)) {
      functions.push(`${file.slice(0, -3)}::${match[1]}`);
    }
  }
  return functions;
}

export function parseAxiomReport(output) {
  const report = new Map();
  const pattern = /'([^']+)' (?:depends on axioms: \[([^\]]*)\]|does not depend on any axioms)/g;
  for (const match of output.replace(/\s+/g, ' ').matchAll(pattern)) {
    report.set(match[1], match[2] ? match[2].split(',').map((name) => name.trim()).filter(Boolean) : []);
  }
  return report;
}

async function proofFiles() {
  const directory = path.join(proofRoot, 'MnemeKernelProofs');
  const files = (await readdir(directory)).filter((name) => name.endsWith('.lean')).sort();
  return files.map((name) => path.join('MnemeKernelProofs', name));
}

async function extract(out) {
  const charon = tool('charon', 'MNEME_CHARON');
  const aeneas = tool('aeneas', 'MNEME_AENEAS');
  const env = { ...process.env, CARGO_TARGET_DIR: path.join(out, 'target') };
  delete env.RUSTC_WRAPPER;
  delete env.RUSTFLAGS;
  if (process.env.MNEME_EXTRACTION_TOOLCHAIN_BIN) {
    env.PATH = `${process.env.MNEME_EXTRACTION_TOOLCHAIN_BIN}${path.delimiter}${env.PATH}`;
  }
  const llbc = path.join(out, 'mneme_kernel.llbc');
  run('charon', [
    charon, 'cargo', '--preset=aeneas', '--error-on-warnings', '--dest-file', llbc, '--',
    '--manifest-path', 'crates/mneme-kernel/Cargo.toml', '--lib', '--no-default-features', '--locked', '--offline',
  ], { env });
  const lean = path.join(out, 'lean');
  run('aeneas', [
    aeneas, '-backend', 'lean', '-abort-on-error', '-warnings-as-errors', '-no-progress-bar', '-dest', lean, llbc,
  ], { env });
  return path.join(lean, translation);
}

/**
 * Minimal-TCB Lean kernel replay (`Lean.Kernel.Environment.replay`) over the
 * compiled `.olean` files of `MnemeKernel` and `MnemeKernelProofs`.
 * Returns the replayed constant count and canonical gzipped proof export.
 */
async function runMinimalTcbKernelReplay(lake, leanEnv, inventoried, translationSha256) {
  const replayPath = path.join(proofRoot, '.lake', 'mneme-kernel-replay.lean');
  const namesListPath = path.join(proofRoot, '.lake', 'mneme-inventoried-names.txt');
  const exportOutPath = path.join(proofRoot, '.lake', 'mneme-kernel-export.txt');
  await mkdir(path.dirname(replayPath), { recursive: true });
  await writeFile(namesListPath, `${[...inventoried].sort().join('\n')}\n`);
  const replayScript = `import Lean
open Lean

def main (args : List String) : IO Unit := do
  let [namesPath, outPath, transSha] := args | throw (IO.userError "expected <namesPath> <outPath> <transSha>")
  initSearchPath (← findSysroot)
  let targetMods : Array Name := #[\`MnemeKernel, \`MnemeKernelProofs]
  let mut newConstants : Std.HashMap Name ConstantInfo := {}
  let mut baseImports : Array Import := #[]
  let mut seenBase : NameHashSet := {}
  let mut queue : List Name := targetMods.toList
  let mut visited : NameHashSet := {}
  while !queue.isEmpty do
    match queue with
    | [] => break
    | m :: rest =>
      queue := rest
      if visited.contains m then continue
      visited := visited.insert m
      let oleanPath ← findOLean m
      let (modData, _) ← readModuleData oleanPath
      for imp in modData.imports do
        let impName := imp.module
        let isLocal := impName == \`MnemeKernel || impName == \`MnemeKernelProofs || (\`MnemeKernelProofs).isPrefixOf impName
        if isLocal then
          if !visited.contains impName then
            queue := impName :: queue
        else
          if !seenBase.contains impName then
            seenBase := seenBase.insert impName
            baseImports := baseImports.push { module := impName }
      for name in modData.constNames, cinfo in modData.constants do
        newConstants := newConstants.insert name cinfo
  let baseEnv ← importModules baseImports {}
  let replayed ← baseEnv.toKernelEnv.replay newConstants
  let rawNames ← IO.FS.readFile namesPath
  let wanted : List String := (rawNames.splitOn "\\n").filter (fun (s : String) => s != "")
  let mut lines : Array String := #[
    "MNEME-KERNEL-REPLAY-EXPORT/v1",
    s!"TRANSLATION_SHA256 {transSha}",
    s!"CONSTANTS {newConstants.size}",
    s!"THEOREMS {wanted.length}"
  ]
  for nameStr in wanted do
    let name := String.toName nameStr
    match replayed.find? name with
    | none => throw (IO.userError s!"theorem missing from replayed kernel environment: {nameStr}")
    | some cinfo =>
      let kind := match cinfo with
        | .thmInfo _ => "thm"
        | .defnInfo _ => "defn"
        | _ => "other"
      lines := lines.push s!"THEOREM {nameStr} {kind} {cinfo.levelParams.length} {cinfo.type.hash}"
  IO.FS.writeFile outPath (String.intercalate "\\n" lines.toList ++ "\\n")
  IO.println s!"REPLAY_OK constants={newConstants.size} theorems={wanted.length}"
`;
  await writeFile(replayPath, replayScript);
  const output = run(
    'minimal-TCB kernel replay',
    [lake, 'env', 'lean', '--run', replayPath, namesListPath, exportOutPath, translationSha256],
    { cwd: proofRoot, env: leanEnv },
  );
  const match = /REPLAY_OK constants=(\d+) theorems=(\d+)/.exec(output);
  if (!match) {
    throw new GateError(`minimal-TCB kernel replay produced unexpected output: ${output.trim()}`);
  }
  const exportBytes = await readFile(exportOutPath);
  const artifactDigestBlake3 = blake3Hex(exportBytes);
  const compressedExportBase64 = gzipSync(exportBytes, { level: 9 }).toString('base64');
  return {
    checker: 'lean-kernel-replay',
    constants: Number(match[1]),
    replayedTheorems: Number(match[2]),
    artifactDigestBlake3,
    compressedExportBase64,
  };
}

async function readInputPath(targetPath) {
  if (targetPath === '-') {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
  }
  return readFile(targetPath, 'utf8');
}

async function main(argv) {
  const verifyIndex = argv.indexOf('--verify-receipt');
  if (verifyIndex >= 0) {
    const receiptArg = argv[verifyIndex + 1];
    if (!receiptArg) throw new GateError('--verify-receipt requires a file path or `-`');
    const skipSourceTree = argv.includes('--skip-source-tree');
    const rootIndex = argv.indexOf('--root');
    const targetRoot = rootIndex >= 0 && argv[rootIndex + 1] ? path.resolve(argv[rootIndex + 1]) : root;
    const keyIndex = argv.indexOf('--expected-public-key');
    const expectedPublicKeyHex = keyIndex >= 0 ? argv[keyIndex + 1] : null;
    const raw = await readInputPath(receiptArg);
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new GateError(`receipt is not valid JSON: ${error.message}`);
    }
    const summary = await verifyKernelProofReceipt(parsed, {
      checkSourceTree: !skipSourceTree,
      repoRoot: targetRoot,
      expectedPublicKeyHex,
    });
    console.log(
      `RECEIPT-VERIFIED: ${summary.theorems} theorems over ${summary.kernelFunctions} kernel functions ` +
      `(replayed ${summary.constants} constants, source=${summary.sourceTreeBlake3.slice(0, 16)}...)`,
    );
    return;
  }

  const update = argv.includes('--update');
  const keep = argv.includes('--keep');
  const out = await mkdtemp(path.join(os.tmpdir(), 'mneme-kernel-proofs-'));
  const lake = tool('lake', 'MNEME_LAKE');
  const leanEnv = { ...process.env };
  try {
    const leanVersion = run('lean version', [tool('lean', 'MNEME_LEAN'), '--version']);
    if (!leanVersion.includes(`version ${expectedLean}`)) {
      throw new GateError(`lean ${expectedLean} is required; found: ${leanVersion.trim()}`);
    }

    const generatedPath = await extract(out);
    const generated = await readFile(generatedPath);
    const checkedInPath = path.join(proofRoot, translation);
    if (update) {
      await writeFile(checkedInPath, generated);
    } else {
      const checkedIn = await readFile(checkedInPath);
      if (!generated.equals(checkedIn)) {
        throw new GateError(
          `${path.relative(root, checkedInPath)} differs from a fresh translation of crates/mneme-kernel ` +
          `(fresh sha256 ${sha256(generated)}, checked-in ${sha256(checkedIn)}); ` +
          'rerun with --update, then re-check every proof',
        );
      }
    }
    if (forbidden.test(stripLean(generated.toString('utf8')))) {
      throw new GateError('the generated translation contains an axiom or escape hatch');
    }

    const files = await proofFiles();
    const statements = new Map();
    for (const file of [...files, 'MnemeKernelProofs.lean']) {
      const text = await readFile(path.join(proofRoot, file), 'utf8');
      const hit = forbidden.exec(stripLean(text));
      if (hit) throw new GateError(`${file}: forbidden construct \`${hit[1]}\``);
      for (const [name, statement] of theoremStatements(text)) statements.set(name, statement);
    }
    const declared = [...statements.keys()];

    const inventory = JSON.parse(await readFile(path.join(proofRoot, 'inventory.json'), 'utf8'));
    if (inventory.format !== 'mneme-kernel-proof-inventory' || inventory.version !== 1) {
      throw new GateError('proofs/kernel/inventory.json has an unknown format');
    }
    const inventoried = inventory.theorems.map((entry) => entry.name);
    const duplicate = inventoried.find((name, index) => inventoried.indexOf(name) !== index);
    if (duplicate) throw new GateError(`inventory lists ${duplicate} twice`);
    const missing = inventoried.filter((name) => !declared.includes(name));
    if (missing.length > 0) throw new GateError(`inventoried theorems are not declared: ${missing.join(', ')}`);
    const unlisted = declared.filter((name) => !inventoried.includes(name));
    if (unlisted.length > 0) throw new GateError(`public theorems are not inventoried: ${unlisted.join(', ')}`);
    const restated = inventory.theorems.filter((entry) => entry.statement !== statements.get(entry.name));
    if (restated.length > 0) {
      throw new GateError(
        `theorem statements differ from the inventory: ${restated.map((entry) => entry.name).join(', ')}`,
      );
    }
    const functions = await kernelFunctions();
    const subjects = new Set(inventory.theorems.flatMap((entry) => entry.subjects ?? []));
    const unknownSubjects = [...subjects].filter((subject) => !functions.includes(subject));
    if (unknownSubjects.length > 0) {
      throw new GateError(`inventory names subjects that are not public kernel functions: ${unknownSubjects.join(', ')}`);
    }
    const uncovered = functions.filter((name) => !subjects.has(name));
    if (uncovered.length > 0) {
      throw new GateError(`public kernel functions without a theorem: ${uncovered.join(', ')}`);
    }

    const build = run('lake build', [lake, 'build'], { cwd: proofRoot, env: leanEnv });
    const warning = build.split('\n').find((line) => /^warning: .*MnemeKernelProofs/.test(line));
    if (warning) throw new GateError(`proof sources build with a warning: ${warning}`);

    const auditPath = path.join(proofRoot, '.lake', 'mneme-axiom-audit.lean');
    await mkdir(path.dirname(auditPath), { recursive: true });
    await writeFile(
      auditPath,
      `import MnemeKernelProofs\n${inventoried.map((name) => `#print axioms ${name}`).join('\n')}\n`,
    );
    const audit = parseAxiomReport(run('axiom audit', [lake, 'env', 'lean', auditPath], { cwd: proofRoot, env: leanEnv }));
    for (const name of inventoried) {
      const axioms = audit.get(name);
      if (!axioms) throw new GateError(`no axiom report for ${name}`);
      const extra = axioms.filter((axiom) => !allowedAxioms.has(axiom));
      if (extra.length > 0) throw new GateError(`${name} depends on ${extra.join(', ')}`);
    }

    const translationSha256 = sha256(generated);
    const proofArtifact = await runMinimalTcbKernelReplay(lake, leanEnv, inventoried, translationSha256);
    const sourceTreeBlake3 = await computeKernelSourceTreeBlake3(root);
    const { privateKey, publicKeyHex, keySource } = await loadSigningKey();

    const receipt = {
      format: KERNEL_PROOF_RECEIPT_V2_FORMAT,
      version: 2,
      verdict: 'passed',
      lean: leanVersion.trim(),
      translationSha256,
      sourceTreeBlake3,
      theorems: inventoried.length,
      kernelFunctions: functions.length,
      axioms: [...allowedAxioms].sort(),
      proofArtifact,
    };
    const canonicalPayload = encodeKernelProofReceiptV2Preserves(receipt);
    const signatureBytes = cryptoSign(null, canonicalPayload, privateKey);
    receipt.canonicalPayloadBase64 = canonicalPayload.toString('base64');
    receipt.signature = {
      algorithm: 'ed25519',
      publicKeyHex,
      signatureHex: signatureBytes.toString('hex'),
      keySource,
    };

    // Self-check before emitting so a broken receipt is never printed.
    await verifyKernelProofReceipt(receipt, { checkSourceTree: true, repoRoot: root });

    console.log(JSON.stringify(receipt, null, 2));
    console.error(
      `KERNEL-PROOFS: ${inventoried.length} theorems over ${functions.length} kernel functions; ` +
      `translation identical; standard axioms only; kernel-replayed ${proofArtifact.constants} constants`,
    );
  } finally {
    if (!keep) await rm(out, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof GateError ? `kernel proof gate failed: ${error.message}` : error);
    process.exit(1);
  });
}
