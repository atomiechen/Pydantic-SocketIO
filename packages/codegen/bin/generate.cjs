#!/usr/bin/env node
const fs = require('node:fs/promises');
const path = require('node:path');
const { generate } = require('../src/generate.cjs');

async function main(args) {
  if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) {
    process.stdout.write('Usage: pydantic-socketio-codegen <asyncapi.json> -o <output.ts>\n');
    return;
  }
  if (args.length !== 3 || !['-o', '--output'].includes(args[1])) {
    throw new Error('Expected <asyncapi.json> -o <output.ts>. Use --help for usage.');
  }
  const input = path.resolve(args[0]);
  const output = path.resolve(args[2]);
  if (input === output) throw new Error('Input and output paths must differ');
  let document;
  try {
    document = JSON.parse(await fs.readFile(input, 'utf8'));
  } catch (error) {
    throw new Error(`Cannot read AsyncAPI JSON from ${input}: ${error.message}`);
  }
  const source = await generate(document);
  await fs.writeFile(output, source);
}

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`pydantic-socketio-codegen: ${error.message}\n`);
  process.exitCode = 1;
});
