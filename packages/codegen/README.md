# TypeScript types for Pydantic-SocketIO

`@pydantic-socketio/codegen` turns a Pydantic-SocketIO AsyncAPI contract into event types for the official Socket.IO TypeScript client **or server**. Event names, namespace paths, payloads, handler argument names, and ACKs come from the Python registrations. The generated file contains types; it does not replace Socket.IO.

Requires Pydantic-SocketIO with `asyncapi_schema()` and Node.js 18 or newer.

## Python server → TypeScript client

Register both incoming and outgoing events, then export the contract:

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
def ask(sid: str, request: Ask) -> Answer:
    server.emit("notice", Notice(text=request.text), to=sid, namespace="/chat")
    return Answer(accepted=True)


schema = pydantic_socketio.asyncapi_schema(server, title="Chat API", version="1.0.0")
Path("asyncapi.json").write_text(json.dumps(schema, indent=2))
```

Run `python contract.py`. In the TypeScript project, generate and use the types:

```sh
npm install --save-dev @pydantic-socketio/codegen
npx @pydantic-socketio/codegen asyncapi.json -o src/socketio.generated.ts
```

```ts
import { io, type Socket } from "socket.io-client";
import { Chat, type Notice, type Ask, type Answer } from "./socketio.generated";

const socket: Socket<Chat.ServerToClientEvents, Chat.ClientToServerEvents> = io(Chat.path);
// /chat becomes Chat; Chat.path is "/chat".

socket.on("notice", (notice: Notice) => console.log(notice.text));
socket.emit("ask", { text: "Hello" } satisfies Ask, (answer: Answer) => {
  console.log(answer.accepted);
});
```

The server's `ask` handler supplies `ClientToServerEvents`, its `Answer` return annotation supplies the ACK type, and `register_emit("notice", ...)` supplies `ServerToClientEvents`.

## Python client → TypeScript server

The same command works when Python is the client. Its outgoing registrations become `ClientToServerEvents`; its handlers become `ServerToClientEvents`:

```python
# client_contract.py
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


client = pydantic_socketio.Client()
client.register_emit("ask", Ask, namespace="/chat", ack_type=Answer)


@client.on("notice", namespace="/chat")
def notice(message: Notice) -> Answer:
    print(message.text)
    return Answer(accepted=True)


schema = pydantic_socketio.asyncapi_schema(client, title="Chat API", version="1.0.0")
Path("asyncapi.json").write_text(json.dumps(schema, indent=2))
```

Run `python client_contract.py`, then run the same `npx @pydantic-socketio/codegen asyncapi.json -o src/socketio.generated.ts` command. On the TypeScript side, use the generated interfaces with the official server:

```ts
import { Server } from "socket.io";
import { Chat } from "./socketio.generated";

const server = new Server<Chat.ClientToServerEvents, Chat.ServerToClientEvents>(3000);
server.of(Chat.path).on("connection", (socket) => {
  socket.on("ask", (request, ack) => {
    console.log(request.text); // Ask.text is a string
    ack?.({ accepted: true }); // Answer
    socket.emit("notice", { text: "Received" }, (answer) => {
      console.log(answer.accepted); // boolean
    });
  });
});
```

A Python client can connect to that server and call `ask` with `response_model=Answer` to validate the ACK at runtime. The generated TypeScript describes both directions; no second generator or wrapper is needed.

## Namespaces and regeneration

`/` becomes `Root`, `/chat` becomes `Chat`, and `/admin` becomes `Admin`. Each generated namespace has `path`, `ClientToServerEvents`, and `ServerToClientEvents`. Create a typed Socket.IO endpoint for each namespace you use. Unscoped outgoing registrations also appear under `Unscoped`; a registration for a specific namespace overrides that fallback there.

Named Pydantic models are exported as named TypeScript declarations such as `Ask`, `Answer`, and `Notice`. Primitive event arguments stay inline, and Python handler argument names appear in tuple labels. If two different models share a name, codegen adds event context so their types remain distinct. The JSON contract is sufficient to understand the generated file without Python source access.

After changing event names, models, namespaces, or ACK types, export `asyncapi.json` again, rerun codegen, and type-check the TypeScript project. Use `--help` for CLI syntax.
