import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EQUIVALENT_MUTANTS,
  applyMutant,
  enumerateMutants,
  enumerateMutantsForSource,
  findFunctionBodies,
  parseArgs,
  parseEnums,
  stripRust,
  selectSample,
  summarizeResults,
} from './audit-kernel-spec-strength.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const kernelSrcDir = path.join(root, 'crates', 'mneme-kernel', 'src');

test('stripRust blanks comments and literals while preserving offsets and newlines', () => {
  const src = [
    '// true && false',
    '/* <= >= */',
    'pub fn f(b: u8) -> bool {',
    '    b == b\'a\' && true',
    '}',
  ].join('\n');
  const masked = stripRust(src);
  assert.equal(masked.length, src.length);
  assert.equal(masked.split('\n').length, src.split('\n').length);
  assert.ok(!masked.includes('false'));
  assert.ok(!masked.includes('<='));
  assert.ok(masked.includes('&& true'));
});

test('parseEnums extracts unit enums and skips data-carrying enums', () => {
  const src = `
    pub enum Decision { Allow, Deny, Defer }
    pub enum Carrying { A(u64), B }
  `;
  const enums = parseEnums(stripRust(src));
  assert.deepEqual(enums.get('Decision'), ['Allow', 'Deny', 'Defer']);
  assert.equal(enums.has('Carrying'), false);
});

test('enumerateMutantsForSource skips match arm patterns and mutates expressions cleanly', () => {
  const src = `
pub enum Mode { A, B, C }

pub fn decide(m: Mode, x: u64, limit: u64) -> Mode {
    match m {
        Mode::A => {
            if ! (x <= limit) && true {
                Mode::B
            } else {
                Mode::C
            }
        }
        Mode::B | Mode::C => Mode::A,
    }
}
`;
  const mutants = enumerateMutantsForSource('sample.rs', src);
  const summaries = mutants.map((m) => `${m.kind}:${m.original}->${m.replacement}`);
  assert.ok(summaries.includes('comparison_op:<=->' + '<'));
  assert.ok(summaries.includes('logical_op:&&->||'));
  assert.ok(summaries.includes('logical_not:!->'));
  assert.ok(summaries.includes('bool_literal:true->false'));
  assert.ok(summaries.includes('enum_variant:Mode::B->Mode::C'));
  assert.ok(summaries.includes('enum_variant:Mode::C->Mode::A'));
  assert.ok(summaries.includes('enum_variant:Mode::A->Mode::B'));
  // Ensure every applied mutant preserves line count and changes source
  for (const m of mutants) {
    const mutated = applyMutant(src, m);
    assert.notEqual(mutated, src);
    // Pattern side `Mode::A =>` must remain untouched
    assert.ok(mutated.includes('Mode::A =>'), `pattern arm was mutated by ${m.id}`);
    assert.ok(mutated.includes('Mode::B | Mode::C =>'), `pattern arm was mutated by ${m.id}`);
  }
});

test('enumerateMutants covers every kernel source module with stratified sampling', async () => {
  const all = await enumerateMutants(kernelSrcDir);
  assert.ok(all.length >= 100, `expected >= 100 mutants, got ${all.length}`);
  const files = new Set(all.map((m) => m.file));
  assert.ok(files.has('budget.rs'));
  assert.ok(files.has('extent.rs'));
  assert.ok(files.has('claim.rs'));
  assert.ok(files.has('isolation.rs'));
  assert.ok(files.has('admission.rs'));

  const sample = selectSample(all, files.size);
  assert.equal(sample.length, files.size);
  assert.equal(new Set(sample.map((m) => m.file)).size, files.size);
});

test('parseArgs handles --list, --sample, --jobs, --filter, and --json', () => {
  const opts = parseArgs(['--list', '--sample', '12', '--jobs=2', '--filter', 'budget.rs,extent', '--json']);
  assert.equal(opts.list, true);
  assert.equal(opts.sample, 12);
  assert.equal(opts.jobs, 2);
  assert.deepEqual(opts.filters, ['budget.rs', 'extent']);
  assert.equal(opts.json, true);
});

test('summarizeResults computes kill rate over non-equivalent mutants only', () => {
  const summary = summarizeResults(
    [
      { id: '1', file: 'a.rs', fnName: 'f', line: 1, kind: 'bool_literal', original: 'true', replacement: 'false', outcome: 'killed_by_lean', detail: '' },
      { id: '2', file: 'a.rs', fnName: 'f', line: 2, kind: 'comparison_op', original: '<', replacement: '<=', outcome: 'killed_by_aeneas', detail: '' },
      { id: '3', file: 'a.rs', fnName: 'f', line: 3, kind: 'comparison_op', original: '>=', replacement: '>', outcome: 'equivalent', detail: '' },
      { id: '4', file: 'a.rs', fnName: 'f', line: 4, kind: 'logical_op', original: '&&', replacement: '||', outcome: 'survived', detail: '' },
    ],
    1234,
  );
  assert.equal(summary.killed, 2);
  assert.equal(summary.nonEquivalent, 3);
  assert.ok(Math.abs(summary.killRate - 2 / 3) < 1e-9);
  assert.equal(summary.survivors.length, 1);
  assert.equal(summary.survivors[0].id, '4');
});

test('findFunctionBodies locates all functions in budget.rs', async () => {
  const src = `pub fn charge(used: u64, cost: u64, limit: u64) -> Option<u64> { None }`;
  const bodies = findFunctionBodies(stripRust(src));
  assert.equal(bodies.length, 1);
  assert.equal(bodies[0].name, 'charge');
});

test('EQUIVALENT_MUTANTS matches verdict.rs merge >= -> > key', async () => {
  const verdictMutants = await enumerateMutants(kernelSrcDir, ['verdict.rs']);
  const mergeMutant = verdictMutants.find(
    (m) => m.fnName === 'merge' && m.original === '>=' && m.replacement === '>',
  );
  assert.ok(mergeMutant, 'expected verdict.rs::merge >= -> > mutant');
  const key = `${mergeMutant.file}:${mergeMutant.fnName}:${mergeMutant.kind}:${mergeMutant.original}->${mergeMutant.replacement}`;
  assert.ok(EQUIVALENT_MUTANTS.has(key), `missing equivalent mutant key ${key}`);
});
