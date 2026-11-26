#!/usr/bin/env node
// 3-tier sharded Octet baseline runner and monotonic ratchet checker for mneme-core.
//
// Tier 1 (`dylint.toml`, `just octet`): zero-baseline deny safety lints.
// Tier 2 (`dylint-all.toml`, `just octet-all`): per-crate sharded ratchet in
//   `octet-baseline/<crate>.json` with CI monotonic check `new <= base`.
// Tier 3 (`dylint-advisory.toml`, `just octet-advisory`): opt-in advisory report
//   for noisy heuristic lints (`assertion_density`, `ambiguous_params`, `numeric_units`).
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const baselineDir = path.join(root, 'octet-baseline');
const TIER3_ADVISORY_LINTS = new Set([
  'assertion_density',
  'ambiguous_params',
  'numeric_units',
]);

function workspaceCrates() {
  const manifest = readFileSync(path.join(root, 'Cargo.toml'), 'utf8');
  const membersMatch = /\[workspace\][\s\S]*?members\s*=\s*\[([\s\S]*?)\]/m.exec(manifest);
  if (!membersMatch) {
    throw new Error('Could not parse [workspace].members from Cargo.toml');
  }
  const crates = [...membersMatch[1].matchAll(/"crates\/([^"]+)"/g)].map((m) => m[1]);
  if (crates.length === 0) {
    throw new Error('No crates found in [workspace].members');
  }
  return crates;
}

function runCargoOctet(args) {
  const result = spawnSync('cargo-octet', args, {
    cwd: root,
    stdio: 'inherit',
  });
  if (result.error) {
    throw new Error(`Failed to execute cargo-octet: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const error = new Error(`cargo-octet exited with status ${result.status ?? 1}`);
    error.exitCode = result.status ?? 1;
    throw error;
  }
}

function withTemporaryDylintConfig(configFile, fn) {
  const target = path.join(root, 'dylint.toml');
  const source = path.join(root, configFile);
  const original = readFileSync(target, 'utf8');
  const replacement = readFileSync(source, 'utf8');
  let restored = false;
  const restore = () => {
    if (!restored) {
      writeFileSync(target, original, 'utf8');
      restored = true;
    }
  };
  const onSignal = (signal) => {
    restore();
    process.exit(signal === 'SIGINT' ? 130 : 143);
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  try {
    writeFileSync(target, replacement, 'utf8');
    return fn();
  } finally {
    restore();
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
  }
}

function validateShardLayout(crates) {
  if (!existsSync(baselineDir)) {
    throw new Error('Missing octet-baseline/ directory');
  }
  const expected = new Set(crates.map((crate) => `${crate}.json`));
  const actual = new Set(readdirSync(baselineDir).filter((name) => name.endsWith('.json')));
  const missing = [...expected].filter((name) => !actual.has(name));
  const extra = [...actual].filter((name) => !expected.has(name));
  if (missing.length > 0) {
    throw new Error(`Missing per-crate Octet baseline shard(s): ${missing.join(', ')}`);
  }
  if (extra.length > 0) {
    throw new Error(`Unexpected Octet baseline shard(s) outside workspace: ${extra.join(', ')}`);
  }
}

function readFindingsCount(filePath) {
  const data = JSON.parse(readFileSync(filePath, 'utf8'));
  if (!Array.isArray(data.findings)) {
    throw new Error(`${filePath}: missing findings array`);
  }
  return data.findings.length;
}

function gitShowJson(ref, relPath) {
  const result = spawnSync('git', ['show', `${ref}:${relPath}`], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) return null;
  return JSON.parse(result.stdout);
}

function checkSharded(args) {
  const offline = args.includes('--offline');
  const useAllConfig = args.includes('--use-all-config');
  const crates = workspaceCrates();
  validateShardLayout(crates);
  const cargoArgs = ['--all-targets', '--all-features', '--ignore-rust-version'];
  if (offline) cargoArgs.push('--offline');

  const exec = () => {
    let totalAccepted = 0;
    for (const crate of crates) {
      const shardRel = `octet-baseline/${crate}.json`;
      const count = readFindingsCount(path.join(root, shardRel));
      totalAccepted += count;
      console.log(`==> Checking Tier 2 Octet shard for ${crate} (baseline: ${count} findings)`);
      runCargoOctet(['check', '-p', crate, '--baseline', shardRel, '--', ...cargoArgs]);
    }
    console.log(
      `All ${crates.length} per-crate Tier 2 Octet shards passed (${totalAccepted} total accepted findings).`,
    );
  };

  if (useAllConfig) {
    withTemporaryDylintConfig('dylint-all.toml', exec);
  } else {
    exec();
  }
}

function writeBaselines() {
  const crates = workspaceCrates();
  mkdirSync(baselineDir, { recursive: true });
  const cargoArgs = ['--all-targets', '--all-features', '--ignore-rust-version'];
  withTemporaryDylintConfig('dylint-all.toml', () => {
    let total = 0;
    for (const crate of crates) {
      const shardRel = `octet-baseline/${crate}.json`;
      console.log(`==> Writing Tier 2 Octet shard ${shardRel}`);
      runCargoOctet(['check', '-p', crate, '--write-baseline', shardRel, '--', ...cargoArgs]);
      const count = readFindingsCount(path.join(root, shardRel));
      total += count;
      console.log(`    ${crate}: ${count} findings`);
    }
    console.log(`Wrote ${crates.length} per-crate baseline shards (${total} total findings).`);
  });
}

function runAdvisory() {
  const cargoArgs = ['--all-targets', '--all-features', '--ignore-rust-version'];
  console.log('==> Running Tier 3 advisory heuristic lints (assertion_density, ambiguous_params, numeric_units)');
  withTemporaryDylintConfig('dylint-advisory.toml', () => {
    runCargoOctet(['check', '--workspace', '--', ...cargoArgs]);
  });
}

function checkMonotonic(args) {
  const crates = workspaceCrates();
  validateShardLayout(crates);

  const baseIdx = args.indexOf('--base');
  const baseRef = baseIdx >= 0 ? args[baseIdx + 1] : null;
  if (!baseRef) {
    let total = 0;
    for (const crate of crates) {
      const count = readFindingsCount(path.join(baselineDir, `${crate}.json`));
      total += count;
      console.log(`  ${crate}: ${count}`);
    }
    console.log(`Validated ${crates.length} per-crate Octet shards (${total} total findings; no --base ref specified).`);
    return;
  }

  // Initial migration: `baseRef` still has monolithic `octet-baseline.json` and
  // no `octet-baseline/<crate>.json` shards yet. Validate total reduction and
  // shard completeness; strict per-crate `new <= base` applies once shards exist.
  const anyBaseShard = crates.some((crate) => gitShowJson(baseRef, `octet-baseline/${crate}.json`) !== null);
  if (!anyBaseShard) {
    const legacyMonolith = gitShowJson(baseRef, 'octet-baseline.json');
    const baseTotal = Array.isArray(legacyMonolith?.findings) ? legacyMonolith.findings.length : null;
    let newTotal = 0;
    for (const crate of crates) {
      const count = readFindingsCount(path.join(baselineDir, `${crate}.json`));
      newTotal += count;
      console.log(`  [INIT] ${crate}: ${count}`);
    }
    if (baseTotal !== null && newTotal > baseTotal) {
      console.error(`ERROR: sharded total ${newTotal} exceeds legacy monolithic baseline ${baseTotal}`);
      process.exit(1);
    }
    console.log(
      `Initial sharded baseline migration vs ${baseRef}: ${newTotal} findings` +
        (baseTotal !== null ? ` (down from ${baseTotal} monolithic findings).` : '.'),
    );
    return;
  }

  let failed = false;
  let totalBase = 0;
  let totalNew = 0;
  for (const crate of crates) {
    const newCount = readFindingsCount(path.join(baselineDir, `${crate}.json`));
    const baseShard = gitShowJson(baseRef, `octet-baseline/${crate}.json`);
    const baseCount = Array.isArray(baseShard?.findings) ? baseShard.findings.length : 0;
    const sourceLabel = baseShard ? 'shard' : 'new-crate';
    totalBase += baseCount;
    totalNew += newCount;
    const delta = newCount - baseCount;
    const sign = delta > 0 ? `+${delta}` : `${delta}`;
    const status = newCount <= baseCount ? 'OK' : 'FAIL';
    console.log(`  [${status}] ${crate}: ${newCount} <= ${baseCount} (${sign}, base=${sourceLabel})`);
    if (newCount > baseCount) {
      console.error(
        `ERROR: ${crate} Tier 2 Octet baseline grew from ${baseCount} to ${newCount} (+${delta}); silent baseline expansion is forbidden.`,
      );
      failed = true;
    }
  }
  console.log(`Monotonic summary vs ${baseRef}: ${totalNew} <= ${totalBase} (${totalNew - totalBase})`);
  if (failed) process.exit(1);
}

const [command, ...rest] = process.argv.slice(2);
try {
  switch (command) {
    case 'check':
      checkSharded(rest);
      break;
    case 'write-baselines':
      writeBaselines();
      break;
    case 'advisory':
      runAdvisory();
      break;
    case 'check-monotonic':
      checkMonotonic(rest);
      break;
    default:
      console.error(
        'Usage: node scripts/octet-sharded.mjs <check [--offline] [--use-all-config] | write-baselines | advisory | check-monotonic [--base <ref>]>',
      );
      process.exit(2);
  }
} catch (error) {
  console.error(error.message);
  process.exit(typeof error.exitCode === 'number' ? error.exitCode : 1);
}
