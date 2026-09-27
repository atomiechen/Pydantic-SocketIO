# TypeScript types for Pydantic-SocketIO

`@pydantic-socketio/codegen` generates event types for the official
`socket.io-client` from a Pydantic-SocketIO AsyncAPI document. Define events in
Python, export the contract, then generate TypeScript types for event names,
payloads, namespaces, and acknowledgements (ACKs).

Requires a Pydantic-SocketIO version with `asyncapi_schema()` and Node.js 22 or
newer.

## From Python to a typed client

Define the events on your Python server and export its contract after the
handlers and outgoing events are registered:

```python
# contract.py
import json
from pathlib import Path

from pydantic import BaseModel
import pydantic_socketio


class Ask(BaseModel):
    text: str


class Answer(BaseModel):
    accepted: bool


class Notice(BaseModel):
    text: str


server = pydantic_socketio.Server(async_mode="threading")
server.register_emit("notice", Notice, namespace="/chat")


@server.on("ask", namespace="/chat")
def ask(sid: str, data: Ask) -> Answer:
    server.emit("notice", Notice(text=data.text), to=sid, namespace="/chat")
    return Answer(accepted=True)


document = pydantic_socketio.asyncapi_schema(
    server, title="Chat API", version="1.0.0"
)
Path("asyncapi.json").write_text(json.dumps(document, indent=2))
```

Run `python contract.py` to write `asyncapi.json`. The exporter reads the
registered operations on this server; it does not read Python source files or
discover events on the client automatically.

Generate the TypeScript file in your frontend project. If the frontend is in a
different directory from `contract.py`, replace `asyncapi.json` below with the
path to the exported file:

```sh
npm install --save-dev @pydantic-socketio/codegen
npx @pydantic-socketio/codegen asyncapi.json -o src/socketio.generated.ts
```

The `/chat` Socket.IO namespace in the Python code becomes `Chat` in the
generated file. `Chat.path` is `"/chat"`. Use its event interfaces with the
Socket.IO client:

```ts
import { io, type Socket } from "socket.io-client";
import { Chat } from "./socketio.generated";

const socket: Socket<
  Chat.ServerToClientEvents,
  Chat.ClientToServerEvents
> = io(Chat.path);

socket.on("notice", (notice) => {
  console.log(notice.text);
});

socket.emit("ask", { text: "Hello" }, (answer) => {
  console.log(answer.accepted);
});
```

The server's `@server.on("ask")` handler supplies `ClientToServerEvents`;
`register_emit("notice", ...)` supplies `ServerToClientEvents`. The handler's
`Answer` return annotation supplies the `ask` ACK type. The example assumes
your Socket.IO server is available at the same origin as the frontend.

## Namespaces and event contracts

The generated names come from Socket.IO namespace paths:

| Python namespace | Generated TypeScript namespace |
| --- | --- |
| `/` (default) | `Root` |
| `/chat` | `Chat` |
| `/admin` | `Admin` |

Each namespace has its own `path`, `ServerToClientEvents`, and
`ClientToServerEvents`. If your contract uses several namespaces, import the
corresponding generated names and create a typed socket for each one. When
exporting a Python *client* contract, its outgoing registrations map to
`ClientToServerEvents` and its handlers map to `ServerToClientEvents`.

An outgoing `register_emit()` without `namespace` applies across namespaces;
the generator also exposes those default types under `Unscoped`. A registration
for a specific namespace overrides the default type there. Declare
`ack_type` on outgoing registrations or a return annotation on handlers to
give ACKs a known type. An undeclared ACK remains unknown.

## Keep types in sync

After changing Python event names, models, namespaces, or ACK types, export
`asyncapi.json` again and rerun codegen. Type-check the frontend as part of
your normal build so calls that no longer match the contract fail early.

`--output` is equivalent to `-o`; use `--help` for the CLI syntax.
