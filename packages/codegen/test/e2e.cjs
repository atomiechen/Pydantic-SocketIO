const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const packageRoot = path.resolve(__dirname, '..');
const repository = path.resolve(packageRoot, '..', '..');
const generated = path.join(__dirname, 'generated');
const cli = path.join(packageRoot, 'bin', 'generate.cjs');
const tsc = path.join(packageRoot, 'node_modules', '.bin', 'tsc');

function run(command, args, cwd = packageRoot) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  if (result.error) throw result.error;
  return result;
}

function success(command, args, cwd) {
  const result = run(command, args, cwd);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result;
}

fs.mkdirSync(generated, { recursive: true });
success('uv', ['run', '--locked', '--no-sync', 'python',
  'packages/codegen/test/export_contract.py'], repository);
for (const role of ['server', 'client']) {
  success(process.execPath, [cli, path.join(generated, `${role}.json`),
    '-o', path.join(generated, `${role}.ts`)]);
  const first = fs.readFileSync(path.join(generated, `${role}.ts`), 'utf8');
  success(process.execPath, [cli, path.join(generated, `${role}.json`),
    '-o', path.join(generated, `${role}.ts`)]);
  assert.equal(fs.readFileSync(path.join(generated, `${role}.ts`), 'utf8'), first);
}
success(tsc, ['-p', path.join(packageRoot, 'tsconfig.json')]);

const original = fs.readFileSync(path.join(__dirname, 'consumer-server.ts'), 'utf8');
const negative = path.join(__dirname, 'consumer-negative.ts');
try {
  fs.writeFileSync(negative, original.replaceAll('@ts-expect-error', 'negative assertion'));
  const result = run(tsc, ['--strict', '--noEmit', '--skipLibCheck',
    '--target', 'ES2020', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', negative]);
  assert.notEqual(result.status, 0, 'Removing negative assertions should fail');
  assert.equal((result.stdout.match(/error TS/g) || []).length, 7, result.stdout);
} finally {
  fs.rmSync(negative, { force: true });
}

const invalid = path.join(generated, 'invalid.json');
const invalidOutput = path.join(generated, 'invalid.ts');
const document = JSON.parse(fs.readFileSync(path.join(generated, 'server.json'), 'utf8'));
document['x-pydantic-socketio'].formatVersion = 2;
fs.writeFileSync(invalid, JSON.stringify(document));
fs.rmSync(invalidOutput, { force: true });
const rejected = run(process.execPath, [cli, invalid, '-o', invalidOutput]);
assert.notEqual(rejected.status, 0);
assert.match(rejected.stderr, /formatVersion 1/);
assert.equal(fs.existsSync(invalidOutput), false);

console.log('Python → AsyncAPI JSON → CLI → Socket.IO TypeScript: passed');
console.log('Negative compile assertions: 7 verified errors; invalid contract rejected');
