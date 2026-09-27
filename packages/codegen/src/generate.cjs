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
  const words = text.normalize('NFKD').replace(/[^A-Za-z0-9]+/g, ' ').trim().split(/\s+/).filter(Boolean);
  const name = words.map((word) => word[0].toUpperCase() + word.slice(1)).join('');
  return !name ? 'Root' : /^[A-Za-z_]/.test(name) ? name : `Namespace${name}`;
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

function plainType(schema) {
  if (!schema || typeof schema !== 'object' || schema.$ref || schema.enum || schema.const !== undefined) return null;
  if (Array.isArray(schema.anyOf)) {
    const values = schema.anyOf.map(plainType);
    return values.every(Boolean) ? values.join(' | ') : null;
  }
  if (Array.isArray(schema.type)) {
    const values = schema.type.map((type) => plainType({ type }));
    return values.every(Boolean) ? values.join(' | ') : null;
  }
  const scalar = { integer: 'number', number: 'number', string: 'string', boolean: 'boolean', null: 'null' }[schema.type];
  if (scalar) return scalar;
  if (schema.type === 'array' && schema.items) {
    const item = plainType(schema.items);
    return item ? `(${item})[]` : null;
  }
  return null;
}

function modelRegistry(document) {
  const components = document.components.schemas;
  const records = [];
  const byComponent = new Map();
  const roots = [];

  function fingerprint(schema, seen = new Set()) {
    if (Array.isArray(schema)) return schema.map((part) => fingerprint(part, seen));
    if (!schema || typeof schema !== 'object') return schema;
    if (schema.$ref) {
      const reference = schema.$ref;
      if (seen.has(reference)) return { $recursive: pointer(document, reference).title || reference };
      return fingerprint(pointer(document, reference), new Set([...seen, reference]));
    }
    return Object.fromEntries(Object.entries(schema).sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => [key, fingerprint(value, seen)]));
  }

  function add(schema, context, component) {
    const title = typeof schema.title === 'string' && schema.title.trim() ? schema.title : null;
    const base = safeName(title || context);
    const key = `${base}:${JSON.stringify(fingerprint(schema))}`;
    const record = { schema, context, component, base, key, name: null };
    records.push(record);
    if (component) byComponent.set(component, record);
    return record;
  }

  for (const [name, schema] of Object.entries(components).sort(([a], [b]) => a.localeCompare(b))) {
    add(schema, name, name);
  }
  function registerRoot(schema, context) {
    if (plainType(schema)) return;
    if (schema.$ref) return;
    roots.push(add(schema, context, null));
    function describeReferences(value, trail, seen = new Set()) {
      if (Array.isArray(value)) {
        value.forEach((part, index) => describeReferences(part, `${trail}${index + 1}`, seen));
      } else if (value && typeof value === 'object') {
        if (value.$ref) {
          const component = value.$ref.split('/').at(-1).replace(/~1/g, '/').replace(/~0/g, '~');
          const target = byComponent.get(component);
          if (!target) throw new Error(`Unknown schema reference: ${value.$ref}`);
          const suggestion = `${safeName(schema.title || context)}${safeName(trail)}`;
          if (target.context === component || suggestion.localeCompare(target.context) < 0) {
            target.context = suggestion;
          }
          if (!seen.has(component)) describeReferences(target.schema, trail, new Set([...seen, component]));
        } else {
          for (const [key, part] of Object.entries(value)) {
            describeReferences(part, key === 'properties' ? trail : `${trail}${safeName(key)}`, seen);
          }
        }
      }
    }
    describeReferences(schema, '');
  }
  function resolve(reserved) {
    const groups = new Map();
    for (const record of records) {
      if (!groups.has(record.key)) groups.set(record.key, []);
      groups.get(record.key).push(record);
    }
    const unique = [...groups.values()].map((group) => {
      group.sort((a, b) => a.context.localeCompare(b.context));
      return { ...group[0], members: group };
    }).sort((a, b) => a.base.localeCompare(b.base) || a.key.localeCompare(b.key));
    const byBase = new Map();
    for (const item of unique) byBase.set(item.base, (byBase.get(item.base) || 0) + 1);
    const used = new Set(['PydanticSocketIOModels', ...reserved]);
    for (const item of unique) {
      const contextName = safeName(item.context.replace(/(?:Payload|Ack)Argument\d+$/, '').replace(/Item$/, ''));
      const candidate = byBase.get(item.base) === 1
        ? (reserved.has(item.base) ? `${item.base}Model` : item.base)
        : contextName.endsWith(item.base) ? contextName : `${item.base}${contextName}`;
      let name = candidate;
      if (used.has(name)) {
        const digest = require('node:crypto').createHash('sha256').update(item.key).digest('hex').slice(0, 8);
        name = `${candidate}${digest}`;
      }
      used.add(name);
      item.name = name;
      for (const member of item.members) member.name = name;
    }
    return unique;
  }
  function rewrite(schema) {
    if (Array.isArray(schema)) return schema.map(rewrite);
    if (!schema || typeof schema !== 'object') return schema;
    if (schema.$ref) {
      const component = schema.$ref.split('/').at(-1).replace(/~1/g, '/').replace(/~0/g, '~');
      const record = byComponent.get(component);
      if (!record) throw new Error(`Unknown schema reference: ${schema.$ref}`);
      return { $ref: `#/definitions/${record.name}` };
    }
    const result = Object.fromEntries(Object.entries(schema).map(([key, value]) => [key, rewrite(value)]));
    if (plainType(result)) delete result.title;
    return result;
  }
  function nameOf(schema, context) {
    const scalar = plainType(schema);
    if (scalar) return scalar;
    if (schema.$ref) {
      const component = schema.$ref.split('/').at(-1).replace(/~1/g, '/').replace(/~0/g, '~');
      return byComponent.get(component).name;
    }
    const root = roots.find((item) => item.schema === schema && item.context === context);
    if (!root) throw new Error(`Missing model for ${context}`);
    return root.name;
  }
  async function declarations(unique) {
    if (!unique.length) return '';
    const definitions = Object.fromEntries(unique.map((item) => [item.name, {
      ...rewrite(item.schema), title: item.name,
    }]));
    const source = await compile({
      title: 'PydanticSocketIOModels',
      anyOf: unique.map((item) => ({ $ref: `#/definitions/${item.name}` })),
      definitions,
    }, 'PydanticSocketIOModels', { bannerComment: '', additionalProperties: false });
    return source.replace(/^export type PydanticSocketIOModels =[\s\S]*?;\n/, '').trim();
  }
  return { registerRoot, resolve, nameOf, declarations };
}

async function generate(document) {
  assertDocument(document);
  const role = document[EXTENSION].role;
  const registry = modelRegistry(document);

  function argumentsType(schema, context, names) {
    if (Array.isArray(schema?.anyOf)) {
      const variants = schema.anyOf.map((variant) => argumentsType(variant, context, names));
      return variants.join(' | ');
    }
    if (schema?.type !== 'array') throw new Error('Socket.IO arguments must be an array schema');
    if (Array.isArray(schema.prefixItems)) {
      if (schema.minItems !== schema.prefixItems.length || schema.maxItems !== schema.prefixItems.length) {
        throw new Error('Socket.IO argument tuple has inconsistent arity');
      }
      if (names && names.length !== schema.prefixItems.length) {
        throw new Error(`${context}: argument names do not match the payload arity`);
      }
      const items = schema.prefixItems.map((item, index) => {
        const name = names?.[index]?.name;
        const type = registry.nameOf(item, `${context}Argument${index + 1}`);
        const label = name && /^[A-Za-z_$][\w$]*$/.test(name) ? `${name}: ` : '';
        return label + type;
      });
      return `[${items.join(', ')}]`;
    }
    if (schema.items) return `${registry.nameOf(schema.items, `${context}Item`)}[]`;
    return 'unknown[]';
  }

  function registerArguments(schema, context) {
    if (Array.isArray(schema?.anyOf)) {
      for (const variant of schema.anyOf) registerArguments(variant, context);
    } else if (Array.isArray(schema?.prefixItems)) {
      for (const [index, item] of schema.prefixItems.entries()) {
        registry.registerRoot(item, `${context}Argument${index + 1}`);
      }
    } else if (schema?.items) {
      registry.registerRoot(schema.items, `${context}Item`);
    }
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
  operations.sort((a, b) => a.id.localeCompare(b.id));

  const namespaces = new Map([...addresses].sort().map((address) => [address, {
    ClientToServerEvents: new Map(), ServerToClientEvents: new Map(),
  }]));
  const unscoped = { ClientToServerEvents: new Map(), ServerToClientEvents: new Map() };
  for (const { id, operation, channel, message, event } of operations) {
    registerArguments(message.payload, `${safeName(channel.address || 'All')}${safeName(event)}Payload`);
    if (operation.reply) {
      registerArguments(pointer(document, operation.reply.messages[0].$ref).payload,
        `${safeName(channel.address || 'All')}${safeName(event)}Ack`);
    }
  }
  const reservedNames = new Set([...addresses].map((address) => address === '/' ? 'Root' : safeName(address)));
  reservedNames.add('Unscoped');
  const uniqueModels = registry.resolve(reservedNames);
  for (const { id, operation, channel, message, event } of operations) {
    const context = `${safeName(channel.address || 'All')}${safeName(event)}Payload`;
    const metadata = message[EXTENSION]?.arguments;
    if (metadata !== undefined && (!Array.isArray(metadata) || metadata.some((item) => typeof item?.name !== 'string'))) {
      throw new Error(`${id}: invalid argument names`);
    }
    const payload = argumentsType(message.payload, context, metadata);
    let ack;
    if (operation.reply) {
      if (operation.reply[EXTENSION]?.ack !== true || operation.reply.messages?.length !== 1) {
        throw new Error(`${id}: reply is not a Socket.IO ACK`);
      }
      ack = argumentsType(pointer(document, operation.reply.messages[0].$ref).payload,
        `${safeName(channel.address || 'All')}${safeName(event)}Ack`);
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
    '// Generated from a Pydantic-SocketIO AsyncAPI contract. Do not edit.',
    '// Use with Socket<ServerToClientEvents, ClientToServerEvents> or Server<ClientToServerEvents, ServerToClientEvents>.',
  ];
  const declarations = await registry.declarations(uniqueModels);
  if (declarations) output.push(declarations);
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
