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
  for (const model of ['Request', 'Nested', 'Answer']) {
    assert.match(first, new RegExp(`export interface ${model} \\{`));
    assert.equal((first.match(new RegExp(`export interface ${model} \\{`, 'g')) || []).length, 1);
  }
  assert.doesNotMatch(first, /Model\d+|Value\d+|PydanticSocketIOModels/);
  if (role === 'server') {
    assert.match(first, /export interface Notice \{/);
    assert.match(first, /first: Request, second: number/);
    assert.match(first, /payload: Request/);
    assert.match(first, /export interface ChatNumericStatus \{\s+value: number;/);
    assert.match(first, /export interface ChatTextStatus \{\s+value: string;/);
    assert.match(first, /export interface ChatNumericContainerItem \{\s+value: number;/);
    assert.match(first, /export interface ChatTextContainerItem \{\s+value: string;/);
  }
}
success(tsc, ['-p', path.join(packageRoot, 'tsconfig.json')]);

const negative = path.join(__dirname, 'consumer-negative.ts');
for (const [file, expected] of [['consumer-server.ts', 7], ['consumer-client.ts', 2], ['consumer-ts-server.ts', 3]]) {
  const original = fs.readFileSync(path.join(__dirname, file), 'utf8');
  try {
    fs.writeFileSync(negative, original.replaceAll('@ts-expect-error', 'negative assertion'));
    const result = run(tsc, ['--strict', '--noEmit', '--skipLibCheck',
      '--target', 'ES2020', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', negative]);
    assert.notEqual(result.status, 0, `Removing negative assertions from ${file} should fail`);
    assert.equal((result.stdout.match(/error TS/g) || []).length, expected, result.stdout);
  } finally {
    fs.rmSync(negative, { force: true });
  }
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

// Documents emitted before argument names were added remain valid version 1 inputs.
const legacy = JSON.parse(fs.readFileSync(path.join(generated, 'server.json'), 'utf8'));
for (const message of Object.values(legacy.components.messages)) {
  if (message["x-pydantic-socketio"]) delete message["x-pydantic-socketio"].arguments;
}
const legacyInput = path.join(generated, 'legacy.json');
const legacyOutput = path.join(generated, 'legacy.ts');
fs.writeFileSync(legacyInput, JSON.stringify(legacy));
success(process.execPath, [cli, legacyInput, '-o', legacyOutput]);
assert.match(fs.readFileSync(legacyOutput, 'utf8'), /"many": \(\.\.\.args: \[\.\.\.\[Request, number\]/);

const reordered = JSON.parse(fs.readFileSync(path.join(generated, 'server.json'), 'utf8'));
reordered.operations = Object.fromEntries(Object.entries(reordered.operations).reverse());
reordered.components.schemas = Object.fromEntries(Object.entries(reordered.components.schemas).reverse());
const reorderedInput = path.join(generated, 'reordered.json');
const reorderedOutput = path.join(generated, 'reordered.ts');
fs.writeFileSync(reorderedInput, JSON.stringify(reordered));
success(process.execPath, [cli, reorderedInput, '-o', reorderedOutput]);
assert.equal(fs.readFileSync(reorderedOutput, 'utf8'), fs.readFileSync(path.join(generated, 'server.ts'), 'utf8'));

console.log('Python → AsyncAPI JSON → CLI → Socket.IO TypeScript: passed');
console.log('Negative compile assertions: 12 verified errors; invalid contract rejected');
