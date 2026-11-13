#!/usr/bin/env node
// Kernel proof gate.
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
//
// Passing this gate shows that the stated theorems hold for the translation.
// It does not show that the Charon/Aeneas translation, the Lean kernel, or the
// shells that call the decision functions are correct.
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const proofRoot = path.join(root, 'proofs', 'kernel');
const kernelRoot = path.join(root, 'crates', 'mneme-kernel');
const translation = 'MnemeKernel.lean';
const allowedAxioms = new Set(['propext', 'Classical.choice', 'Quot.sound']);
const forbidden = /(?<![.\w'])(sorry|admit|axiom|native_decide|unsafe|opaque|implemented_by|extern)(?![\w'])/;
const expectedLean = '4.35.0';

export class GateError extends Error {}

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

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

async function main(argv) {
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

    const receipt = {
      format: 'mneme-kernel-proof-receipt',
      version: 1,
      lean: leanVersion.trim(),
      translationSha256: sha256(generated),
      theorems: inventoried.length,
      kernelFunctions: functions.length,
      axioms: [...allowedAxioms],
    };
    console.log(JSON.stringify(receipt, null, 2));
    console.log(
      `KERNEL-PROOFS: ${inventoried.length} theorems over ${functions.length} kernel functions; ` +
      'translation identical; standard axioms only',
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
