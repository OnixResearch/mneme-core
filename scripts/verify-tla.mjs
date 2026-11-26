#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const tlaDir = path.join(repoRoot, 'specs', 'tla');

function parseArgs(argv) {
  const opts = { traceNdjson: null, skipNegatives: false };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--trace-ndjson' && i + 1 < argv.length) {
      opts.traceNdjson = path.resolve(argv[i + 1]);
      i += 1;
    } else if (argv[i] === '--skip-negatives') {
      opts.skipNegatives = true;
    }
  }
  return opts;
}

function findTlcCommand() {
  if (process.env.MNEME_TLC_BIN) {
    return { cmd: process.env.MNEME_TLC_BIN, prefixArgs: [] };
  }
  const direct = spawnSync('which', ['tlc'], { encoding: 'utf8' });
  if (direct.status === 0 && direct.stdout.trim()) {
    return { cmd: direct.stdout.trim(), prefixArgs: [] };
  }
  const nixCheck = spawnSync('which', ['nix'], { encoding: 'utf8' });
  if (nixCheck.status === 0 && nixCheck.stdout.trim()) {
    return {
      cmd: 'nix',
      prefixArgs: ['shell', '--option', 'builders', '', 'nixpkgs#tlaplus', 'nixpkgs#jdk', '-c', 'tlc'],
    };
  }
  throw new Error('TLC not found on PATH and nix is unavailable. Set MNEME_TLC_BIN or install tlaplus.');
}

function runTlc(tlc, workDir, specFile, cfgFile, metaDir) {
  const args = [
    ...tlc.prefixArgs,
    '-workers', 'auto',
    '-deadlock',
    '-metadir', metaDir,
    '-config', cfgFile,
    specFile,
  ];
  const res = spawnSync(tlc.cmd, args, {
    cwd: workDir,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  return {
    status: res.status ?? 1,
    output: `${res.stdout ?? ''}\n${res.stderr ?? ''}`,
  };
}

function tlaString(value) {
  const escaped = String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${escaped}"`;
}

function tlaValue(value) {
  if (typeof value === 'boolean') return value ? 'TRUE' : 'FALSE';
  if (typeof value === 'number') return String(Math.trunc(value));
  if (typeof value === 'string') return tlaString(value);
  if (Array.isArray(value)) {
    return `{${value.map(tlaValue).join(', ')}}`;
  }
  throw new Error(`Unsupported trace field value: ${JSON.stringify(value)}`);
}

function ndjsonToTraceDataTla(ndjsonText) {
  const lines = ndjsonText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const records = lines.map((line, index) => {
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (err) {
      throw new Error(`Invalid NDJSON at line ${index + 1}: ${err.message}`);
    }
    const entries = Object.entries(parsed).map(([k, v]) => `${k} |-> ${tlaValue(v)}`);
    return `    [${entries.join(', ')}]`;
  });
  return [
    '----------------------------- MODULE TraceData -----------------------------',
    'EXTENDS Sequences',
    '',
    'Trace == <<',
    records.join(',\n'),
    '>>',
    '',
    '=============================================================================',
    '',
  ].join('\n');
}

function extractSummary(output) {
  const match = output.match(/(\d+)\s+states generated,\s+(\d+)\s+distinct states found/);
  if (!match) return 'checked';
  return `${match[1]} states generated, ${match[2]} distinct states`;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const tlc = findTlcCommand();
  const baseTemp = process.env.CARGO_TARGET_DIR
    ? path.join(process.env.CARGO_TARGET_DIR, 'tla-verify-tmp')
    : path.join(os.tmpdir(), 'mneme-tla-verify');
  fs.mkdirSync(baseTemp, { recursive: true });
  const runDir = fs.mkdtempSync(path.join(baseTemp, 'run-'));

  try {
    // Copy specs into isolated work directory so TLC metadata & generated files never dirty the repo.
    const workSpecs = path.join(runDir, 'specs');
    fs.mkdirSync(workSpecs, { recursive: true });
    for (const file of fs.readdirSync(tlaDir)) {
      if (file.endsWith('.tla') || file.endsWith('.cfg')) {
        fs.copyFileSync(path.join(tlaDir, file), path.join(workSpecs, file));
      }
    }

    const positiveSpecs = [
      { name: 'WorkspaceLifecycle', spec: 'WorkspaceLifecycle.tla', cfg: 'WorkspaceLifecycle.cfg' },
      { name: 'RestoreBarrier', spec: 'RestoreBarrier.tla', cfg: 'RestoreBarrier.cfg' },
      { name: 'SyncConvergence', spec: 'SyncConvergence.tla', cfg: 'SyncConvergence.cfg' },
      { name: 'TraceSpec (reference)', spec: 'TraceSpec.tla', cfg: 'TraceSpec.cfg' },
    ];

    for (const item of positiveSpecs) {
      const meta = path.join(runDir, `meta-${item.name.replace(/[^a-zA-Z0-9]/g, '_')}`);
      fs.mkdirSync(meta, { recursive: true });
      const res = runTlc(tlc, workSpecs, item.spec, item.cfg, meta);
      if (res.status !== 0) {
        console.error(`[FAIL] TLC ${item.name}:\n${res.output}`);
        process.exit(1);
      }
      console.log(`[PASS] TLC ${item.name}: ${extractSummary(res.output)}`);
    }

    if (opts.traceNdjson) {
      const ndjsonText = fs.readFileSync(opts.traceNdjson, 'utf8');
      fs.writeFileSync(path.join(workSpecs, 'TraceData.tla'), ndjsonToTraceDataTla(ndjsonText));
      const meta = path.join(runDir, 'meta-live-trace');
      fs.mkdirSync(meta, { recursive: true });
      const res = runTlc(tlc, workSpecs, 'TraceSpec.tla', 'TraceSpec.cfg', meta);
      if (res.status !== 0) {
        console.error(`[FAIL] TLC TraceSpec (${opts.traceNdjson}):\n${res.output}`);
        process.exit(1);
      }
      console.log(`[PASS] TLC TraceSpec (${path.basename(opts.traceNdjson)}): ${extractSummary(res.output)}`);
    }

    if (!opts.skipNegatives) {
      const negatives = [
        {
          name: 'WorkspaceLifecycle S1 regression (EnableChunkGC = FALSE)',
          spec: 'WorkspaceLifecycle.tla',
          baseCfg: 'WorkspaceLifecycle.cfg',
          mutate: (cfg) => cfg.replace('EnableChunkGC = TRUE', 'EnableChunkGC = FALSE'),
          expectSubstring: 'Invariant NoLeakedUnreferencedChunks is violated',
        },
        {
          name: 'WorkspaceLifecycle dropped generation pinning (EnableGenPin = FALSE)',
          spec: 'WorkspaceLifecycle.tla',
          baseCfg: 'WorkspaceLifecycle.cfg',
          mutate: (cfg) => cfg.replace('EnableGenPin = TRUE', 'EnableGenPin = FALSE'),
          expectSubstring: 'Invariant GenerationPinnedCommit is violated',
        },
        {
          name: 'SyncConvergence stale-seq rollback (EnablePushMonotonic = FALSE)',
          spec: 'SyncConvergence.tla',
          baseCfg: 'SyncConvergence.cfg',
          mutate: (cfg) => cfg.replace('EnablePushMonotonic = TRUE', 'EnablePushMonotonic = FALSE'),
          expectSubstring: 'Invariant PushHeadMonotonic is violated',
        },
        {
          name: 'SyncConvergence dropped RevocationSet merge (EnableRevocationMerge = FALSE)',
          spec: 'SyncConvergence.tla',
          baseCfg: 'SyncConvergence.cfg',
          mutate: (cfg) => cfg.replace('EnableRevocationMerge = TRUE', 'EnableRevocationMerge = FALSE'),
          expectSubstring: 'Invariant RevokedAndExpiredRejected is violated',
        },
      ];

      for (const neg of negatives) {
        const cfgPath = path.join(workSpecs, `neg-${neg.baseCfg}`);
        const baseContent = fs.readFileSync(path.join(workSpecs, neg.baseCfg), 'utf8');
        fs.writeFileSync(cfgPath, neg.mutate(baseContent));
        const meta = path.join(runDir, `meta-neg-${Math.random().toString(16).slice(2, 8)}`);
        fs.mkdirSync(meta, { recursive: true });
        const res = runTlc(tlc, workSpecs, neg.spec, path.basename(cfgPath), meta);
        if (res.status === 0 || !res.output.includes(neg.expectSubstring)) {
          console.error(`[FAIL] Negative check did not catch bug: ${neg.name}\n${res.output}`);
          process.exit(1);
        }
        console.log(`[PASS] Negative check caught expected violation: ${neg.name}`);
      }

      // TraceSpec negative regression: S1 unpurged chunk in NDJSON trace.
      const badTrace = [
        JSON.stringify({ domain: 'workspace', action: 'CommitWritten', seq: 1, gen: 0, pinnedGen: 0, blob: 'b1', chunks: ['c1'], isRetention: false }),
        JSON.stringify({ domain: 'workspace', action: 'CommitWritten', seq: 2, gen: 1, pinnedGen: 0, blob: 'b1', chunks: [], isRetention: true }),
        JSON.stringify({ domain: 'workspace', action: 'PurgeBlob', blob: 'b1', outcome: 'purged', leakedChunks: 1, cacheInvalidated: true }),
      ].join('\n');
      fs.writeFileSync(path.join(workSpecs, 'TraceData.tla'), ndjsonToTraceDataTla(badTrace));
      const metaBad = path.join(runDir, 'meta-neg-trace-s1');
      fs.mkdirSync(metaBad, { recursive: true });
      const resBad = runTlc(tlc, workSpecs, 'TraceSpec.tla', 'TraceSpec.cfg', metaBad);
      if (resBad.status === 0 || !resBad.output.includes('Invariant TraceValid is violated')) {
        console.error(`[FAIL] TraceSpec negative S1 check did not fail!\n${resBad.output}`);
        process.exit(1);
      }
      console.log('[PASS] Negative check caught expected violation: TraceSpec S1 unpurged FastCDC chunk');
    }
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
  }
}

main();
