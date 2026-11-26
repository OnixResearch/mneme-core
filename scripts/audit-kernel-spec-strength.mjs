#!/usr/bin/env node
// Kernel formal-spec mutation auditor.
//
// Injects first-order single-operator Rust mutants into crates/mneme-kernel/src/*.rs,
// re-extracts each mutant with Charon + Aeneas, and checks whether the pinned Lean
// theorem suite in proofs/kernel/MnemeKernelProofs catches the mutation.
//
// Any non-equivalent mutant that survives both Charon/Aeneas extraction and a full
// `lake build MnemeKernelProofs` exposes an under-specified kernel branch and exits
// non-zero.
import { createHash } from 'node:crypto';
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const kernelSrcDir = path.join(root, 'crates', 'mneme-kernel', 'src');
const proofRoot = path.join(root, 'proofs', 'kernel');
const translationFile = 'MnemeKernel.lean';

// Known mathematically equivalent mutants whose mutated Rust expression computes
// an identical function on all inputs (keyed by stable `<file>:<fn>:<kind>:<orig>-><repl>`
// or full mutant id).
// Keep minimal and mathematically proven.
export const EQUIVALENT_MUTANTS = new Map([
  [
    'verdict.rs:merge:comparison_op:>=->>',
    'severity is injective on Status (0,1,2,3), so severity(left) == severity(right) implies left == right; >= and > compute the exact same function on all inputs.',
  ],
]);

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

function tool(name, envVar) {
  return process.env[envVar] || name;
}

/**
 * Replace Rust comments, string literals, raw strings, and char/byte literals
 * with spaces while preserving byte offsets and newlines so regex/token scans
 * never mutate comments or literals.
 */
export function stripRust(source) {
  const chars = [...source];
  const out = new Array(chars.length);
  let i = 0;
  const blank = (from, to) => {
    for (let k = from; k < to; k += 1) {
      out[k] = chars[k] === '\n' ? '\n' : ' ';
    }
  };
  while (i < chars.length) {
    const ch = chars[i];
    const next = chars[i + 1];
    // Line comment
    if (ch === '/' && next === '/') {
      const start = i;
      while (i < chars.length && chars[i] !== '\n') i += 1;
      blank(start, i);
      continue;
    }
    // Nested block comment
    if (ch === '/' && next === '*') {
      const start = i;
      let depth = 1;
      i += 2;
      while (i < chars.length && depth > 0) {
        if (chars[i] === '/' && chars[i + 1] === '*') {
          depth += 1;
          i += 2;
        } else if (chars[i] === '*' && chars[i + 1] === '/') {
          depth -= 1;
          i += 2;
        } else {
          i += 1;
        }
      }
      blank(start, i);
      continue;
    }
    // Byte literal b'x' or b'\x..'
    if (ch === 'b' && next === "'") {
      const start = i;
      i += 2;
      while (i < chars.length && chars[i] !== "'") {
        i += chars[i] === '\\' ? 2 : 1;
      }
      if (i < chars.length) i += 1;
      blank(start, i);
      continue;
    }
    // String literal "..." (including b"...")
    if (ch === '"' || (ch === 'b' && next === '"')) {
      const start = i;
      i += ch === 'b' ? 2 : 1;
      while (i < chars.length && chars[i] !== '"') {
        i += chars[i] === '\\' ? 2 : 1;
      }
      if (i < chars.length) i += 1;
      blank(start, i);
      continue;
    }
    // Char literal 'x' (distinguished from lifetime 'a by closing ')
    if (ch === "'") {
      if (chars[i + 1] === '\\') {
        const start = i;
        i += 2;
        while (i < chars.length && chars[i] !== "'" && chars[i] !== '\n') i += 1;
        if (chars[i] === "'") {
          i += 1;
          blank(start, i);
          continue;
        }
        // Not a char literal; restore position
        out[start] = chars[start];
        i = start + 1;
        continue;
      }
      if (i + 2 < chars.length && chars[i + 2] === "'") {
        blank(i, i + 3);
        i += 3;
        continue;
      }
    }
    out[i] = ch;
    i += 1;
  }
  return out.join('');
}

/**
 * Parse unit-variant enums declared in a kernel module:
 * `pub enum Name { V1, V2, ... }` -> Map<string, string[]>.
 */
export function parseEnums(masked) {
  const enums = new Map();
  const enumPattern = /\b(?:pub\s+)?enum\s+([A-Z][A-Za-z0-9_]*)\s*\{/g;
  for (const match of masked.matchAll(enumPattern)) {
    const name = match[1];
    let pos = match.index + match[0].length;
    let depth = 1;
    const bodyStart = pos;
    while (pos < masked.length && depth > 0) {
      if (masked[pos] === '{') depth += 1;
      else if (masked[pos] === '}') depth -= 1;
      pos += 1;
    }
    const body = masked.slice(bodyStart, pos - 1);
    const variants = [];
    for (const rawPart of body.split(',')) {
      const cleaned = rawPart.replace(/#\[[^\]]*\]/g, '').trim();
      if (!cleaned) continue;
      const ident = /^([A-Z][A-Za-z0-9_]*)$/.exec(cleaned);
      if (ident) {
        variants.push(ident[1]);
      } else {
        // Non-unit variant enum; skip swapping variants on this enum.
        variants.length = 0;
        break;
      }
    }
    if (variants.length >= 2) {
      enums.set(name, variants);
    }
  }
  return enums;
}

/**
 * Locate `{ start, end, name }` byte ranges of every function body in masked Rust source.
 */
export function findFunctionBodies(masked) {
  const bodies = [];
  const fnPattern = /\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g;
  for (const match of masked.matchAll(fnPattern)) {
    const name = match[1];
    // Find matching closing paren of parameter list
    let pos = match.index + match[0].length;
    let parenDepth = 1;
    while (pos < masked.length && parenDepth > 0) {
      if (masked[pos] === '(') parenDepth += 1;
      else if (masked[pos] === ')') parenDepth -= 1;
      pos += 1;
    }
    // Advance to opening brace of function body (skipping return type / where clause)
    while (pos < masked.length && masked[pos] !== '{' && masked[pos] !== ';') {
      pos += 1;
    }
    if (masked[pos] !== '{') continue;
    const bodyStart = pos;
    let braceDepth = 1;
    pos += 1;
    while (pos < masked.length && braceDepth > 0) {
      if (masked[pos] === '{') braceDepth += 1;
      else if (masked[pos] === '}') braceDepth -= 1;
      pos += 1;
    }
    bodies.push({ name, start: bodyStart, end: pos });
  }
  return bodies;
}

function lineNumberAt(text, offset) {
  let line = 1;
  for (let i = 0; i < offset; i += 1) {
    if (text[i] === '\n') line += 1;
  }
  return line;
}

/**
 * Determine whether `offset` inside a function body sits on the pattern side
 * (LHS of `=>`) of a `match` arm, excluding `matches!(...)` macro calls.
 */
function isInMatchArmPattern(masked, bodyStart, offset) {
  // Walk backwards to the start of the current statement/arm (up to `{`, `,`, or `;` at same nesting)
  let paren = 0;
  let bracket = 0;
  let i = offset - 1;
  while (i >= bodyStart) {
    const ch = masked[i];
    if (ch === ')') paren += 1;
    else if (ch === '(') {
      if (paren === 0) {
        // Check if this `(` belongs to `matches!(`
        const prefix = masked.slice(Math.max(bodyStart, i - 12), i).trimEnd();
        if (prefix.endsWith('matches!')) return false;
      } else {
        paren -= 1;
      }
    } else if (ch === ']') bracket += 1;
    else if (ch === '[') {
      if (bracket > 0) bracket -= 1;
    } else if (paren === 0 && bracket === 0) {
      if (ch === '{' || ch === ';' || ch === ',') break;
      if (ch === '>' && masked[i - 1] === '=') {
        // We already passed `=>` going left, so we are on the RHS expression!
        return false;
      }
    }
    i -= 1;
  }

  // Walk forward from `offset` at current paren/bracket depth to see if `=>` appears
  // before `,`, `;`, `}`, or `{`.
  let fParen = 0;
  let fBracket = 0;
  let j = offset;
  while (j < masked.length) {
    const ch = masked[j];
    if (ch === '(') fParen += 1;
    else if (ch === ')') {
      if (fParen === 0) {
        // Inside an outer `(` — check if outer `(` is `matches!(`
        // (already returned false above if immediate, check up chain)
        fParen -= 1;
      } else {
        fParen -= 1;
      }
    } else if (ch === '[') fBracket += 1;
    else if (ch === ']') fBracket -= 1;
    else if (fParen <= 0 && fBracket <= 0) {
      if (ch === '=' && masked[j + 1] === '>') return true;
      if (ch === ';' || ch === '{' || ch === '}') return false;
    }
    j += 1;
  }
  return false;
}

/**
 * If `offset` is inside a `matches!(expr, Pattern)` call, return the text of
 * that `matches!(...)` invocation so we avoid replacing a variant with one
 * already listed in the same `matches!` pattern.
 */
function enclosingMatchesCall(masked, bodyStart, offset) {
  let depth = 0;
  for (let i = offset - 1; i >= bodyStart; i -= 1) {
    if (masked[i] === ')') depth += 1;
    else if (masked[i] === '(') {
      if (depth === 0) {
        const before = masked.slice(Math.max(bodyStart, i - 12), i).trimEnd();
        if (before.endsWith('matches!')) {
          let end = i + 1;
          let d = 1;
          while (end < masked.length && d > 0) {
            if (masked[end] === '(') d += 1;
            else if (masked[end] === ')') d -= 1;
            end += 1;
          }
          return masked.slice(i, end);
        }
        // Keep climbing outer parens (e.g., tuple inside matches!)
      } else {
        depth -= 1;
      }
    }
  }
  return null;
}

/**
 * Enumerate all first-order single-operator Rust mutants for one kernel source file.
 */
export function enumerateMutantsForSource(file, source) {
  const masked = stripRust(source);
  const enums = parseEnums(masked);
  const bodies = findFunctionBodies(masked);
  const mutants = [];
  const seen = new Set();

  const addMutant = ({ fnName, kind, start, end, original, replacement }) => {
    const line = lineNumberAt(source, start);
    const key = `${start}:${end}:${replacement}`;
    if (seen.has(key)) return;
    seen.add(key);
    const id = `${file}:${fnName}:L${line}:${kind}:${original}->${replacement}@${start}`;
    mutants.push({
      id,
      file,
      fnName,
      line,
      kind,
      start,
      end,
      original,
      replacement,
    });
  };

  for (const body of bodies) {
    const slice = masked.slice(body.start, body.end);

    // 1. Boolean literals: true <-> false
    for (const match of slice.matchAll(/\b(true|false)\b/g)) {
      const start = body.start + match.index;
      const original = match[1];
      const replacement = original === 'true' ? 'false' : 'true';
      addMutant({
        fnName: body.name,
        kind: 'bool_literal',
        start,
        end: start + original.length,
        original,
        replacement,
      });
    }

    // 2. Logical binary operators: && <-> ||
    for (const match of slice.matchAll(/&&|\|\|/g)) {
      const start = body.start + match.index;
      const original = match[0];
      const replacement = original === '&&' ? '||' : '&&';
      addMutant({
        fnName: body.name,
        kind: 'logical_op',
        start,
        end: start + original.length,
        original,
        replacement,
      });
    }

    // 3. Unary logical negation: !expr -> expr (skipping != and macro!)
    for (const match of slice.matchAll(/(?<![A-Za-z0-9_!])!(?!=)/g)) {
      const start = body.start + match.index;
      const afterSlice = masked.slice(start + 1).trimStart();
      if (!afterSlice || !/[A-Za-z_(]/.test(afterSlice[0])) continue;
      addMutant({
        fnName: body.name,
        kind: 'logical_not',
        start,
        end: start + 1,
        original: '!',
        replacement: '',
      });
    }

    // 4. Relational / boundary comparison operators:
    //    <= <-> <, >= <-> >, == <-> !=
    //    Require surrounding whitespace so generics (`Option<T>`) and arrows (`=>`, `->`) are skipped.
    const cmpMap = new Map([
      ['<=', '<'],
      ['<', '<='],
      ['>=', '>'],
      ['>', '>='],
      ['==', '!='],
      ['!=', '=='],
    ]);
    for (const match of slice.matchAll(/ (<=|<|>=|>|==|!=) /g)) {
      const start = body.start + match.index + 1;
      const original = match[1];
      const replacement = cmpMap.get(original);
      addMutant({
        fnName: body.name,
        kind: 'comparison_op',
        start,
        end: start + original.length,
        original,
        replacement,
      });
    }

    // 5. Enum variant swaps in expressions and `matches!(...)` patterns
    for (const match of slice.matchAll(/\b([A-Z][A-Za-z0-9_]*)::([A-Z][A-Za-z0-9_]*)\b/g)) {
      const enumName = match[1];
      const variant = match[2];
      const variants = enums.get(enumName);
      if (!variants) continue;
      const idx = variants.indexOf(variant);
      if (idx < 0) continue;

      const start = body.start + match.index;
      const end = start + match[0].length;
      if (isInMatchArmPattern(masked, body.start, start)) continue;

      const matchesText = enclosingMatchesCall(masked, body.start, start);
      let nextVariant = null;
      if (matchesText) {
        // For simple alternation `matches!(x, E::A | E::B)`, avoid duplicating an
        // existing variant; for tuple patterns like `kind_eq`, cycling is always valid.
        const isTuplePattern = /\(\s*[A-Z][A-Za-z0-9_]*::/.test(matchesText);
        for (let step = 1; step < variants.length; step += 1) {
          const candidate = variants[(idx + step) % variants.length];
          if (isTuplePattern || !matchesText.includes(`${enumName}::${candidate}`)) {
            nextVariant = candidate;
            break;
          }
        }
      } else {
        nextVariant = variants[(idx + 1) % variants.length];
      }
      if (!nextVariant) continue;

      addMutant({
        fnName: body.name,
        kind: 'enum_variant',
        start,
        end,
        original: `${enumName}::${variant}`,
        replacement: `${enumName}::${nextVariant}`,
      });
    }

    // 6. Option return collapse: `Some(<simple>)` -> `None` when returning Option
    //    (only for functions whose signature returns `Option<...>`).
    const sigPrefix = masked.slice(Math.max(0, body.start - 160), body.start);
    if (/->\s*Option\s*</.test(sigPrefix)) {
      for (const match of slice.matchAll(/\bSome\s*\(/g)) {
        const start = body.start + match.index;
        if (isInMatchArmPattern(masked, body.start, start)) continue;
        // Skip if this `Some(` is in a `match` arm pattern or `if let`
        const lineStart = masked.lastIndexOf('\n', start) + 1;
        const linePrefix = masked.slice(lineStart, start);
        if (/\b(?:if|while)\s+let\b/.test(linePrefix)) continue;

        let pos = start + match[0].length;
        let depth = 1;
        while (pos < body.end && depth > 0) {
          if (masked[pos] === '(') depth += 1;
          else if (masked[pos] === ')') depth -= 1;
          pos += 1;
        }
        if (depth !== 0) continue;
        const original = source.slice(start, pos);
        // Keep mutation concise for single-line Some(...) expressions
        if (original.includes('\n')) continue;
        addMutant({
          fnName: body.name,
          kind: 'option_none',
          start,
          end: pos,
          original,
          replacement: 'None',
        });
      }
    }
  }

  return mutants;
}

export function applyMutant(source, mutant) {
  return source.slice(0, mutant.start) + mutant.replacement + source.slice(mutant.end);
}

/**
 * Enumerate mutants across all crates/mneme-kernel/src/*.rs files (excluding lib.rs).
 */
export async function enumerateMutants(srcDir = kernelSrcDir, filters = []) {
  const files = (await readdir(srcDir))
    .filter((name) => name.endsWith('.rs') && name !== 'lib.rs')
    .sort();
  const matchedFiles =
    filters.length === 0
      ? files
      : files.filter((file) =>
          filters.some((f) => file.includes(f) || file.slice(0, -3) === f),
        );

  const all = [];
  for (const file of matchedFiles) {
    const source = await readFile(path.join(srcDir, file), 'utf8');
    all.push(...enumerateMutantsForSource(file, source));
  }
  return all;
}

/**
 * Deterministically select `sampleSize` mutants stratified across files so every
 * kernel module is covered.
 */
export function selectSample(mutants, sampleSize) {
  if (!sampleSize || sampleSize >= mutants.length) return mutants;
  const byFile = new Map();
  for (const m of mutants) {
    if (!byFile.has(m.file)) byFile.set(m.file, []);
    byFile.get(m.file).push(m);
  }
  const buckets = [...byFile.values()];
  const picked = [];
  let round = 0;
  while (picked.length < sampleSize) {
    let progressed = false;
    for (const bucket of buckets) {
      if (picked.length >= sampleSize) break;
      if (round < bucket.length) {
        picked.push(bucket[round]);
        progressed = true;
      }
    }
    if (!progressed) break;
    round += 1;
  }
  return picked;
}

export function parseArgs(argv) {
  const opts = {
    list: false,
    json: false,
    keep: false,
    sample: null,
    jobs: Math.max(1, Math.min(4, Math.floor(os.cpus().length / 2) || 1)),
    filters: [],
    timeoutSeconds: 120,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--list') {
      opts.list = true;
    } else if (arg === '--json') {
      opts.json = true;
    } else if (arg === '--keep') {
      opts.keep = true;
    } else if (arg === '--sample') {
      const value = Number.parseInt(argv[++i], 10);
      if (!Number.isInteger(value) || value <= 0) {
        throw new Error('--sample requires a positive integer');
      }
      opts.sample = value;
    } else if (arg.startsWith('--sample=')) {
      const value = Number.parseInt(arg.slice('--sample='.length), 10);
      if (!Number.isInteger(value) || value <= 0) {
        throw new Error('--sample requires a positive integer');
      }
      opts.sample = value;
    } else if (arg === '--jobs' || arg === '-j') {
      const value = Number.parseInt(argv[++i], 10);
      if (!Number.isInteger(value) || value <= 0) {
        throw new Error('--jobs requires a positive integer');
      }
      opts.jobs = value;
    } else if (arg.startsWith('--jobs=')) {
      const value = Number.parseInt(arg.slice('--jobs='.length), 10);
      if (!Number.isInteger(value) || value <= 0) {
        throw new Error('--jobs requires a positive integer');
      }
      opts.jobs = value;
    } else if (arg === '--filter') {
      const value = argv[++i];
      if (!value) throw new Error('--filter requires a value');
      opts.filters.push(...value.split(',').filter(Boolean));
    } else if (arg.startsWith('--filter=')) {
      const value = arg.slice('--filter='.length);
      if (!value) throw new Error('--filter requires a value');
      opts.filters.push(...value.split(',').filter(Boolean));
    } else if (arg === '--timeout') {
      const value = Number.parseInt(argv[++i], 10);
      if (!Number.isInteger(value) || value <= 0) {
        throw new Error('--timeout requires a positive integer');
      }
      opts.timeoutSeconds = value;
    } else if (arg === '--help' || arg === '-h') {
      opts.help = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

function printHelp() {
  console.log(`Usage: node scripts/audit-kernel-spec-strength.mjs [options]

Options:
  --list               Enumerate mutants without running Charon/Aeneas/Lean
  --sample N           Run a deterministic stratified sample of N mutants
  --jobs N, -j N       Parallel worker count (default: min(4, cpus/2))
  --filter <file>      Filter mutants by source file name (repeatable or comma-separated)
  --timeout <seconds>  Per-step timeout in seconds (default: 120)
  --json               Emit machine-readable JSON output
  --keep               Keep temp workspace for surviving mutants
  -h, --help           Show this help message
`);
}

function runAsync(argv, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), {
      cwd: options.cwd ?? root,
      env: options.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          child.kill('SIGKILL');
        }, options.timeoutMs)
      : null;

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', (error) => {
      if (timer) clearTimeout(timer);
      resolve({ status: -1, timedOut, error: error.message, stdout, stderr });
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolve({ status: code ?? -1, timedOut, error: null, stdout, stderr });
    });
  });
}

function tailLines(text, maxLines = 12) {
  return text.trim().split('\n').slice(-maxLines).join('\n');
}

function proofModuleForFile(file) {
  const stem = file.slice(0, -3);
  return stem.charAt(0).toUpperCase() + stem.slice(1);
}

const STANDALONE_KERNEL_CARGO_TOML = `[package]
name = "mneme-kernel"
version = "0.1.0"
edition = "2024"
rust-version = "1.99"

[features]
default = ["debug"]
debug = []

[lints.rust]
unsafe_code = "forbid"
`;

async function pathExists(p) {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Ensure `proofs/kernel/.lake/packages` is populated before parallel workers share it.
 */
async function ensureLakeCacheWarm(timeoutMs) {
  const packagesDir = path.join(proofRoot, '.lake', 'packages');
  if (await pathExists(packagesDir)) return;
  const lake = tool('lake', 'MNEME_LAKE');
  const res = await runAsync([lake, 'build'], { cwd: proofRoot, timeoutMs: Math.max(timeoutMs, 600_000) });
  if (res.status !== 0) {
    throw new Error(
      `baseline lake build failed while warming .lake cache:\n${tailLines(`${res.stdout}\n${res.stderr}`, 30)}`,
    );
  }
}

async function prepareMutantWorkspace(runDir, index, mutant, sourcesByFile) {
  const mDir = path.join(runDir, `m-${String(index).padStart(4, '0')}`);
  const crateDir = path.join(mDir, 'crates', 'mneme-kernel');
  const srcDir = path.join(crateDir, 'src');
  const proofsDir = path.join(mDir, 'proofs');
  const lakeDir = path.join(proofsDir, '.lake');

  await mkdir(srcDir, { recursive: true });
  await mkdir(path.join(lakeDir, 'build'), { recursive: true });

  await writeFile(path.join(crateDir, 'Cargo.toml'), STANDALONE_KERNEL_CARGO_TOML);
  for (const [file, text] of sourcesByFile.entries()) {
    const content = file === mutant.file ? applyMutant(text, mutant) : text;
    await writeFile(path.join(srcDir, file), content);
  }

  for (const entry of [
    'lakefile.toml',
    'lake-manifest.json',
    'lean-toolchain',
    'MnemeKernelProofs.lean',
    'MnemeKernelProofs',
  ]) {
    await symlink(path.join(proofRoot, entry), path.join(proofsDir, entry));
  }

  await symlink(path.join(proofRoot, '.lake', 'packages'), path.join(lakeDir, 'packages'));
  const configSrc = path.join(proofRoot, '.lake', 'config');
  if (await pathExists(configSrc)) {
    await cp(configSrc, path.join(lakeDir, 'config'), { recursive: true });
  }

  return { mDir, crateDir, proofsDir };
}

async function evaluateMutant({
  runDir,
  index,
  mutant,
  sourcesByFile,
  baselineSha,
  proofModuleFiles,
  timeoutMs,
  keep,
}) {
  const started = Date.now();
  const equivalentKey = `${mutant.file}:${mutant.fnName}:${mutant.kind}:${mutant.original}->${mutant.replacement}`;
  if (EQUIVALENT_MUTANTS.has(mutant.id) || EQUIVALENT_MUTANTS.has(equivalentKey)) {
    return {
      ...mutant,
      outcome: 'equivalent',
      stage: 'allowlist',
      durationMs: 0,
      detail: EQUIVALENT_MUTANTS.get(mutant.id) ?? EQUIVALENT_MUTANTS.get(equivalentKey),
    };
  }

  const { mDir, crateDir, proofsDir } = await prepareMutantWorkspace(
    runDir,
    index,
    mutant,
    sourcesByFile,
  );
  let outcome = 'survived';
  let stage = 'lean';
  let detail = '';

  try {
    const charon = tool('charon', 'MNEME_CHARON');
    const aeneas = tool('aeneas', 'MNEME_AENEAS');
    const lake = tool('lake', 'MNEME_LAKE');

    const extractEnv = { ...process.env, CARGO_TARGET_DIR: path.join(mDir, 'target') };
    delete extractEnv.RUSTC_WRAPPER;
    delete extractEnv.RUSTFLAGS;
    if (process.env.MNEME_EXTRACTION_TOOLCHAIN_BIN) {
      extractEnv.PATH = `${process.env.MNEME_EXTRACTION_TOOLCHAIN_BIN}${path.delimiter}${extractEnv.PATH}`;
    }

    const llbcPath = path.join(mDir, 'mneme_kernel.llbc');
    const charonRes = await runAsync(
      [
        charon,
        'cargo',
        '--preset=aeneas',
        '--dest-file',
        llbcPath,
        '--',
        '--manifest-path',
        path.join(crateDir, 'Cargo.toml'),
        '--lib',
        '--no-default-features',
        '--offline',
      ],
      { cwd: mDir, env: extractEnv, timeoutMs },
    );
    if (charonRes.status !== 0) {
      outcome = charonRes.timedOut ? 'timeout' : 'unviable';
      stage = 'charon';
      detail = tailLines(`${charonRes.stdout}\n${charonRes.stderr}`);
      return {
        ...mutant,
        outcome,
        stage,
        durationMs: Date.now() - started,
        detail,
      };
    }

    const aeneasRes = await runAsync(
      [
        aeneas,
        '-backend',
        'lean',
        '-abort-on-error',
        '-no-progress-bar',
        '-dest',
        proofsDir,
        llbcPath,
      ],
      { cwd: mDir, env: extractEnv, timeoutMs },
    );
    if (aeneasRes.status !== 0) {
      outcome = aeneasRes.timedOut ? 'timeout' : 'killed_by_aeneas';
      stage = 'aeneas';
      detail = tailLines(`${aeneasRes.stdout}\n${aeneasRes.stderr}`);
      return {
        ...mutant,
        outcome,
        stage,
        durationMs: Date.now() - started,
        detail,
      };
    }

    const generatedBytes = await readFile(path.join(proofsDir, translationFile));
    if (sha256(generatedBytes) === baselineSha) {
      outcome = 'equivalent';
      stage = 'translation';
      detail = 'Aeneas translation is byte-identical to baseline MnemeKernel.lean';
      return {
        ...mutant,
        outcome,
        stage,
        durationMs: Date.now() - started,
        detail,
      };
    }

    // Fast path: check owning proof module first.
    const moduleName = proofModuleForFile(mutant.file);
    if (proofModuleFiles.has(`${moduleName}.lean`)) {
      const fastRes = await runAsync(
        [lake, 'build', `MnemeKernelProofs.${moduleName}`],
        { cwd: proofsDir, env: process.env, timeoutMs },
      );
      if (fastRes.status !== 0) {
        outcome = fastRes.timedOut ? 'killed_by_lean' : 'killed_by_lean';
        stage = `lean:${moduleName}`;
        detail = fastRes.timedOut
          ? 'Lean proof build timed out (killed)'
          : tailLines(`${fastRes.stdout}\n${fastRes.stderr}`);
        return {
          ...mutant,
          outcome,
          stage,
          durationMs: Date.now() - started,
          detail,
        };
      }
    }

    // Owning module passed — run full proof suite to check cross-module theorems.
    const fullRes = await runAsync([lake, 'build', 'MnemeKernelProofs'], {
      cwd: proofsDir,
      env: process.env,
      timeoutMs,
    });
    if (fullRes.status !== 0) {
      outcome = 'killed_by_lean';
      stage = 'lean:all';
      detail = fullRes.timedOut
        ? 'Full Lean proof build timed out (killed)'
        : tailLines(`${fullRes.stdout}\n${fullRes.stderr}`);
    } else {
      outcome = 'survived';
      stage = 'lean:all';
      detail = keep ? `SURVIVED (workspace kept at ${mDir})` : 'SURVIVED all Lean proofs';
    }

    return {
      ...mutant,
      outcome,
      stage,
      durationMs: Date.now() - started,
      detail,
    };
  } finally {
    if (!(keep && outcome === 'survived')) {
      await rm(mDir, { recursive: true, force: true });
    }
  }
}

export function summarizeResults(results, totalDurationMs) {
  const counts = {
    total: results.length,
    killed_by_lean: 0,
    killed_by_aeneas: 0,
    equivalent: 0,
    unviable: 0,
    timeout: 0,
    survived: 0,
  };
  for (const r of results) {
    counts[r.outcome] = (counts[r.outcome] ?? 0) + 1;
  }
  const killed = counts.killed_by_lean + counts.killed_by_aeneas;
  const nonEquivalent = killed + counts.survived;
  const killRate = nonEquivalent === 0 ? 1.0 : killed / nonEquivalent;
  return {
    format: 'mneme-kernel-spec-mutation-audit',
    version: 1,
    durationMs: totalDurationMs,
    counts,
    killed,
    nonEquivalent,
    killRate,
    survivors: results
      .filter((r) => r.outcome === 'survived')
      .map(({ id, file, fnName, line, kind, original, replacement, detail }) => ({
        id,
        file,
        fnName,
        line,
        kind,
        original,
        replacement,
        detail,
      })),
    unviable: results
      .filter((r) => r.outcome === 'unviable' || r.outcome === 'timeout')
      .map(({ id, file, fnName, line, kind, original, replacement, outcome, detail }) => ({
        id,
        file,
        fnName,
        line,
        kind,
        original,
        replacement,
        outcome,
        detail,
      })),
  };
}

async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help) {
    printHelp();
    return;
  }

  let mutants = await enumerateMutants(kernelSrcDir, opts.filters);
  if (opts.sample !== null) {
    mutants = selectSample(mutants, opts.sample);
  }

  if (opts.list) {
    if (opts.json) {
      console.log(JSON.stringify({ count: mutants.length, mutants }, null, 2));
    } else {
      for (const m of mutants) {
        console.log(`${m.file}:${m.line} [${m.fnName}] (${m.kind}) ${m.original} -> ${m.replacement}`);
      }
      console.log(`\nTotal enumerated mutants: ${mutants.length}`);
    }
    return;
  }

  if (mutants.length === 0) {
    throw new Error('no mutants matched the selected filter');
  }

  const started = Date.now();
  const timeoutMs = opts.timeoutSeconds * 1000;
  await ensureLakeCacheWarm(timeoutMs);

  const baselineBytes = await readFile(path.join(proofRoot, translationFile));
  const baselineSha = sha256(baselineBytes);

  const allSrcFiles = (await readdir(kernelSrcDir)).filter((name) => name.endsWith('.rs')).sort();
  const sourcesByFile = new Map();
  for (const file of allSrcFiles) {
    sourcesByFile.set(file, await readFile(path.join(kernelSrcDir, file), 'utf8'));
  }

  const proofModuleFiles = new Set(
    (await readdir(path.join(proofRoot, 'MnemeKernelProofs'))).filter((n) => n.endsWith('.lean')),
  );

  const runDir = await mkdtemp(path.join(os.tmpdir(), 'mneme-kernel-mutants-'));
  const results = new Array(mutants.length);
  let cursor = 0;

  if (!opts.json) {
    console.error(
      `Auditing ${mutants.length} kernel mutants with ${opts.jobs} parallel worker(s) in ${runDir}...`,
    );
  }

  try {
    const worker = async () => {
      while (true) {
        const index = cursor;
        cursor += 1;
        if (index >= mutants.length) return;
        const mutant = mutants[index];
        const result = await evaluateMutant({
          runDir,
          index,
          mutant,
          sourcesByFile,
          baselineSha,
          proofModuleFiles,
          timeoutMs,
          keep: opts.keep,
        });
        results[index] = result;
        if (!opts.json) {
          const tag = result.outcome.toUpperCase();
          console.error(
            `[${index + 1}/${mutants.length}] ${tag} (${result.stage}, ${(result.durationMs / 1000).toFixed(1)}s) ${mutant.file}:${mutant.line} [${mutant.fnName}] ${mutant.original} -> ${mutant.replacement}`,
          );
        }
      }
    };

    const workerCount = Math.min(opts.jobs, mutants.length);
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
  } finally {
    const hasKeptSurvivors = opts.keep && results.some((r) => r && r.outcome === 'survived');
    if (!hasKeptSurvivors) {
      await rm(runDir, { recursive: true, force: true });
    }
  }

  const summary = summarizeResults(results, Date.now() - started);
  if (opts.json) {
    console.log(JSON.stringify({ ...summary, results }, null, 2));
  } else {
    const pct = (summary.killRate * 100).toFixed(2);
    console.log(
      `\nKERNEL-MUTATION-AUDIT: ${summary.killed}/${summary.nonEquivalent} killed (${pct}%) ` +
        `[lean=${summary.counts.killed_by_lean}, aeneas=${summary.counts.killed_by_aeneas}, ` +
        `survived=${summary.counts.survived}, equiv=${summary.counts.equivalent}, ` +
        `unviable=${summary.counts.unviable}, timeout=${summary.counts.timeout}] ` +
        `in ${(summary.durationMs / 1000).toFixed(1)}s`,
    );
    if (summary.survivors.length > 0) {
      console.log('\nSurviving non-equivalent mutants:');
      for (const s of summary.survivors) {
        console.log(
          `  - ${s.file}:${s.line} [${s.fnName}] (${s.kind}) ${s.original} -> ${s.replacement}`,
        );
      }
    }
    if (summary.unviable.length > 0) {
      console.log('\nUnviable / timed-out mutants:');
      for (const u of summary.unviable) {
        console.log(
          `  - ${u.file}:${u.line} [${u.fnName}] (${u.kind}, ${u.outcome}) ${u.original} -> ${u.replacement}`,
        );
      }
    }
  }

  if (summary.counts.survived > 0) {
    process.exit(1);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`kernel spec mutation audit error: ${error.message}`);
    process.exit(2);
  });
}
