const { compile } = require('json-schema-to-typescript');

const EXTENSION = 'x-pydantic-socketio';

function pointer(document, reference) {
  if (typeof reference !== 'string' || !reference.startsWith('#/')) {
    throw new Error(`Expected a local JSON reference, got ${JSON.stringify(reference)}`);
  }
  const value = reference.slice(2).split('/').reduce((value, part) => {
    const key = part.replace(/~1/g, '/').replace(/~0/g, '~');
    if (value === null || typeof value !== 'object' || !(key in value)) {
      throw new Error(`Unresolved JSON reference: ${reference}`);
    }
    return value[key];
  }, document);
  if (value && typeof value === 'object' && typeof value.$ref === 'string') {
    return pointer(document, value.$ref);
  }
  return value;
}

function safeName(text) {
  const words = text.normalize('NFKD').replace(/[^A-Za-z0-9]+/g, ' ').trim().split(/\s+/);
  const name = words.map((word) => word[0].toUpperCase() + word.slice(1)).join('');
  return /^[A-Za-z_]/.test(name) ? name : `Namespace${name}`;
}

function namespaceName(address, used) {
  const base = address === '/' ? 'Root' : safeName(address);
  let candidate = base;
  let suffix = 2;
  while (used.has(candidate)) candidate = `${base}${suffix++}`;
  used.add(candidate);
  return candidate;
}

function assertDocument(document) {
  if (document?.asyncapi !== '3.1.0') {
    throw new Error('Expected an AsyncAPI 3.1.0 document');
  }
  const extension = document[EXTENSION];
  if (extension?.formatVersion !== 1 || !['server', 'client'].includes(extension.role)) {
    throw new Error('Expected x-pydantic-socketio formatVersion 1 and server/client role');
  }
  if (!document.operations || !document.channels || !document.components?.schemas) {
    throw new Error('Document is missing operations, channels, or component schemas');
  }
}

async function generate(document) {
  assertDocument(document);
  const role = document[EXTENSION].role;
  const models = [];
  let modelNumber = 0;

  async function valueType(schema) {
    const number = ++modelNumber;
    const name = `Value${number}`;
    const namespace = `Model${number}`;
    const source = await compile(
      { ...schema, title: name, components: { schemas: document.components.schemas } },
      name,
      { bannerComment: '', additionalProperties: false },
    );
    models.push(`export namespace ${namespace} {\n${source}\n}`);
    return `${namespace}.${name}`;
  }

  async function argumentsType(schema) {
    if (Array.isArray(schema?.anyOf)) {
      const variants = [];
      for (const variant of schema.anyOf) variants.push(await argumentsType(variant));
      return variants.join(' | ');
    }
    if (schema?.type !== 'array') throw new Error('Socket.IO arguments must be an array schema');
    if (Array.isArray(schema.prefixItems)) {
      if (schema.minItems !== schema.prefixItems.length || schema.maxItems !== schema.prefixItems.length) {
        throw new Error('Socket.IO argument tuple has inconsistent arity');
      }
      const items = [];
      for (const item of schema.prefixItems) items.push(await valueType(item));
      return `[${items.join(', ')}]`;
    }
    if (schema.items) return `${await valueType(schema.items)}[]`;
    return 'unknown[]';
  }

  const operations = [];
  const addresses = new Set(['/']);
  for (const [id, operation] of Object.entries(document.operations)) {
    if (!['send', 'receive'].includes(operation.action)) throw new Error(`${id}: invalid action`);
    const channel = pointer(document, operation.channel?.$ref);
    if (channel.address !== null && (typeof channel.address !== 'string' || !channel.address.startsWith('/'))) {
      throw new Error(`${id}: invalid namespace`);
    }
    if (channel.address !== null) addresses.add(channel.address);
    if (!Array.isArray(operation.messages) || operation.messages.length !== 1) {
      throw new Error(`${id}: expected exactly one event message`);
    }
    const message = pointer(document, operation.messages[0].$ref);
    const event = message?.[EXTENSION]?.event;
    if (typeof event !== 'string' || !event) throw new Error(`${id}: missing event name`);
    operations.push({ id, operation, channel, message, event });
  }

  const namespaces = new Map([...addresses].sort().map((address) => [address, {
    ClientToServerEvents: new Map(), ServerToClientEvents: new Map(),
  }]));
  const unscoped = { ClientToServerEvents: new Map(), ServerToClientEvents: new Map() };
  for (const { id, operation, channel, message, event } of operations) {
    const payload = await argumentsType(message.payload);
    let ack;
    if (operation.reply) {
      if (operation.reply[EXTENSION]?.ack !== true || operation.reply.messages?.length !== 1) {
        throw new Error(`${id}: reply is not a Socket.IO ACK`);
      }
      ack = await argumentsType(pointer(document, operation.reply.messages[0].$ref).payload);
    } else if (operation[EXTENSION]?.ack !== 'unspecified') {
      throw new Error(`${id}: missing ACK declaration`);
    }
    const signature = ack === undefined
      ? `(...args: [...${payload}, ack?: (...args: unknown[]) => void]) => void`
      : `(...args: [...${payload}, ack?: (...args: ${ack}) => void]) => void`;
    const side = (role === 'server') === (operation.action === 'receive')
      ? 'ClientToServerEvents' : 'ServerToClientEvents';
    const except = channel[EXTENSION]?.namespace?.except || [];
    const targets = channel.address === null
      ? [...addresses].filter((address) => !except.includes(address))
      : [channel.address];
    if (channel.address === null) {
      if (channel[EXTENSION]?.namespace?.scope !== 'all' || !Array.isArray(except)) {
        throw new Error(`${id}: unscoped event lacks fallback semantics`);
      }
      unscoped[side].set(event, signature);
    }
    for (const address of targets) {
      const events = namespaces.get(address)[side];
      if (events.has(event) && events.get(event) !== signature) {
        throw new Error(`${id}: conflicting ${event} contract in ${address}`);
      }
      events.set(event, signature);
    }
  }

  const output = [
    '// Generated from a Pydantic-SocketIO AsyncAPI contract. Do not edit. ',
    '// Use with Socket<ServerToClientEvents, ClientToServerEvents> from socket.io-client.',
  ];
  output.push(...models);
  const used = new Set();
  function render(name, sides, path) {
    output.push(`export namespace ${name} {`);
    if (path !== undefined) output.push(`  export const path = ${JSON.stringify(path)};`);
    for (const side of ['ClientToServerEvents', 'ServerToClientEvents']) {
      output.push(`  export interface ${side} {`);
      for (const [event, signature] of sides[side]) {
        output.push(`    ${JSON.stringify(event)}: ${signature};`);
      }
      output.push('  }');
    }
    output.push('}');
  }
  for (const [address, sides] of namespaces) render(namespaceName(address, used), sides, address);
  if (unscoped.ClientToServerEvents.size || unscoped.ServerToClientEvents.size) {
    render(namespaceName('Unscoped', used), unscoped);
  }
  return output.join('\n') + '\n';
}

module.exports = { generate };
