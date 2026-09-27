const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const http = require('node:http');
const { Server } = require('socket.io');
const { io } = require('socket.io-client');

const repository = path.resolve(__dirname, '..', '..', '..');
const python = path.join(repository, '.venv', 'bin', 'python');

async function port() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const value = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return value;
}

function pythonProcess(mode, number) {
  const child = spawn(python, [path.join(__dirname, 'live_python.py'), mode, String(number)], {
    cwd: repository, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  let errors = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { errors += chunk; });
  return { child, output: () => output, errors: () => errors };
}

async function pythonServerToTsClient() {
  const number = await port();
  const process = pythonProcess('server', number);
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Python server startup timed out: ' + process.errors())), 10000);
      process.child.stdout.on('data', (chunk) => {
        if (chunk.toString().includes('READY')) { clearTimeout(timer); resolve(); }
      });
      process.child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`Python server exited ${code}: ${process.errors()}`)); });
    });
    const socket = io(`http://127.0.0.1:${number}/chat`, { transports: ['polling'], reconnection: false });
    try {
      const notice = new Promise((resolve) => socket.once('notice', resolve));
      await new Promise((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('connect_error', reject);
      });
      const ack = await socket.timeout(5000).emitWithAck('ask', { value: 7 });
      assert.deepEqual(ack, { doubled: 14 });
      assert.deepEqual(await notice, { doubled: 14 });
    } finally { socket.disconnect(); }
  } finally {
    process.child.kill();
  }
}

async function tsServerToPythonClient() {
  const number = await port();
  const httpServer = http.createServer();
  const server = new Server(httpServer);
  const peerAck = new Promise((resolve, reject) => {
    server.of('/chat').on('connection', (socket) => {
      socket.on('ask', (request, ack) => {
        assert.deepEqual(request, { value: 7 });
        ack({ doubled: 14 });
        socket.timeout(5000).emit('notice', { value: 3 }, (error, answer) => {
          if (error) reject(error);
          else {
            socket.emit('confirmed');
            resolve(answer);
          }
        });
      });
    });
  });
  await new Promise((resolve) => httpServer.listen(number, '127.0.0.1', resolve));
  try {
    const process = pythonProcess('client', number);
    const exit = await new Promise((resolve) => process.child.on('exit', resolve));
    assert.equal(exit, 0, process.errors() + process.output());
    assert.match(process.output(), /PYTHON_CLIENT_OK/);
    assert.deepEqual(await peerAck, { doubled: 6 });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const timer = setTimeout(() => { console.error('Live Socket.IO check timed out'); process.exit(1); }, 30000);
(async () => { await pythonServerToTsClient(); await tsServerToPythonClient(); })()
  .then(() => console.log('Python server ↔ TypeScript client; TypeScript server ↔ Python client: passed'))
  .catch((error) => { console.error(error); process.exitCode = 1; })
  .finally(() => clearTimeout(timer));
