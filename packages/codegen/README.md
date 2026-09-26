# TypeScript codegen

`@pydantic-socketio/codegen` turns a Pydantic-SocketIO AsyncAPI 3.1 JSON
document into event interfaces for the official `socket.io-client` types. It
is currently private and has not been published to npm.
Its installed CLI name will be `pydantic-socketio-codegen`. It accepts
`x-pydantic-socketio` contract format version 1.

From a repository checkout:
```sh
npm ci --prefix packages/codegen
node packages/codegen/bin/generate.cjs asyncapi.json -o socketio.generated.ts
```

```ts
import { io, Socket } from "socket.io-client";
import { Chat } from "./socketio.generated";

const socket: Socket<Chat.ServerToClientEvents, Chat.ClientToServerEvents> =
  io(Chat.path);
```

For outgoing registrations without a namespace, the output includes their
default types under `Unscoped`. A named namespace's types apply its scoped
overrides. An absent ACK declaration yields an unknown ACK type; it does not
claim that the event has no ACK.

Run `uv sync --locked`, `npm ci --prefix packages/codegen`, then
`npm test --prefix packages/codegen` from the repository root to exercise a real
Python export and TypeScript compile.
