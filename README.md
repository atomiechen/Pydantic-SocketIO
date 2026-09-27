# Pydantic-SocketIO

[![Python CI](https://github.com/atomiechen/Pydantic-SocketIO/actions/workflows/test.yml/badge.svg)](https://github.com/atomiechen/Pydantic-SocketIO/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/Pydantic--SocketIO?logo=pypi&logoColor=white)](https://pypi.org/project/pydantic-socketio/)
[![npm codegen](https://img.shields.io/npm/v/%40pydantic-socketio%2Fcodegen?logo=npm&label=codegen)](https://www.npmjs.com/package/@pydantic-socketio/codegen)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**One Socket.IO contract from Python to TypeScript.**

Pydantic-SocketIO adds runtime validation to [python-socketio](https://github.com/miguelgrinberg/python-socketio), exports an AsyncAPI 3.1 contract, and generates event interfaces for the official TypeScript Socket.IO client or server. Define events, namespaces, payloads, and acknowledgements in Python; avoid maintaining a second TypeScript event map by hand.

**Runtime-safe Python. Compile-time-safe TypeScript. Without replacing Socket.IO.**

## Quick start

```sh
pip install pydantic-socketio
```

Register Python events, export the contract, then generate TypeScript event interfaces:

```python
# contract.py
import json
from pathlib import Path

from pydantic import BaseModel
from pydantic_socketio import Server

class Ask(BaseModel):
    text: str

class Answer(BaseModel):
    accepted: bool

server = Server(async_mode="threading")

@server.on("ask", namespace="/chat")
def ask(sid: str, request: Ask) -> Answer:
    return Answer(accepted=bool(request.text))

document = server.asyncapi(title="Chat", version="1")
Path("asyncapi.json").write_text(json.dumps(document))
```

```sh
python contract.py
npx @pydantic-socketio/codegen asyncapi.json -o socketio.generated.ts
```

Install `socket.io-client` in your TypeScript project. The generated types plug
into its official client:

```ts
import { io, type Socket } from "socket.io-client";
import { Chat } from "./socketio.generated";

const socket: Socket<Chat.ServerToClientEvents, Chat.ClientToServerEvents> = io(Chat.path);
socket.emit("ask", { text: "Hello" }, (answer) => console.log(answer.accepted));
```

Pydantic validates the Python event at runtime; TypeScript checks the payload and ACK during compilation. The generated file contains event types and does not add another frontend runtime. For a live FastAPI server, browser client, and regeneration commands, run the [five-minute chat example](examples/fastapi-typescript-chat/README.md).

## Features

- **Python as the source of truth:** Define Socket.IO events and Pydantic models once in the Python server or client.
- **Runtime validation:** Validate incoming and registered outgoing payloads with Pydantic.
- **Typed payloads and acknowledgements:** Validate handler returns and opt in to typed `call(response_model=...)` results.
- **AsyncAPI 3.1 export:** Describe the registered Socket.IO operations without maintaining a separate schema file.
- **Socket.IO-native TypeScript codegen:** Generate interfaces for the official `socket.io-client` or `socket.io` package.
- **Namespaces and both directions:** Generate Python server → TS client or Python client → TS server contracts, including scoped events and ACKs.
- **FastAPI integration:** Mount an async Socket.IO server alongside a FastAPI application.
- **Migration support:** Use enhanced server/client classes, or monkey patch existing `python-socketio` code when needed.

## Installation

```sh
pip install pydantic-socketio
```

If you want FastAPI integration, you can install the extra dependencies:

```sh
pip install pydantic-socketio[fastapi]
```

Extras from [python-socketio](https://github.com/miguelgrinberg/python-socketio) are also available: `client`, `asyncio-client`, and `docs`.


## Usage

### Recommended: Pydantic-Enhanced Socket.IO Server and Client

Drop-in replacements for the original [python-socketio](https://github.com/miguelgrinberg/python-socketio) server and client are provided.

The enhanced Socket.IO server with Pydantic validation:

```python
from pydantic import BaseModel
import pydantic_socketio

class ChatMessage(BaseModel):
    role: str
    content: str

# Create a server; use AsyncServer for an asyncio server
sio = pydantic_socketio.Server()

# Register an event handler with Pydantic validation
@sio.event
def message(sid: str, data: ChatMessage):
    print(f"Received chat message from {data.role}: {data.content}")
    data.content = data.content.upper()
    print(f"Sending uppercase message: {data.content}")
    # Emit a Pydantic model without manual conversion
    sio.emit("message", data)

# `on` decorator is also supported
@sio.on("custom_event")
def handle_custom_event(sid: str, data: int):
    ...

# Register an emit event with Pydantic validation
sio.register_emit("message", payload_type=ChatMessage)

# Or, use the decorator form
@sio.register_emit("misc")
class MiscData(BaseModel):
    value: int
```

The enhanced Socket.IO client with Pydantic validation:

```python
from pydantic import BaseModel
import pydantic_socketio

# Create a client; use AsyncClient for an asyncio client
sio = pydantic_socketio.Client()

@sio.register_emit("ping")
class PingData(BaseModel):
    value: int

sio.register_emit("pong", payload_type=int)

@sio.event
def ping(data: PingData):
    ...

@sio.on("pong")
def handle_pong(data: int):
    ...
```

### Typed calls and acknowledgements

`call()` supports the original Socket.IO arguments and an optional
`response_model`. When it is omitted, the acknowledgement is returned unchanged.
When supplied, Pydantic validates the acknowledgement and returns the requested
type. Request data follows the same registered emit validation and model
serialization as `emit()`.

```python
from pydantic import BaseModel
import pydantic_socketio

class Question(BaseModel):
    value: int

class Answer(BaseModel):
    value: int

server = pydantic_socketio.AsyncServer(async_mode="asgi")

@server.on("question")
async def answer(sid: str, data: Question) -> Answer:
    return Answer(value=data.value + 1)

async def ask() -> None:
    client = pydantic_socketio.AsyncClient()
    client.register_emit("question", Question)
    # Connect the client to the server before calling.
    result = await client.call("question", Question(value=3), response_model=Answer)
    assert result == Answer(value=4)
```

On Python 3.8/3.9, create `AsyncClient` inside a running event loop, as shown.

To scope outgoing validation to one namespace and declare its expected
acknowledgement, use the optional `namespace` and `ack_type` arguments:

```python
client.register_emit(
    "question", Question, namespace="/chat", ack_type=Answer
)
```

Registrations without `namespace` still apply to every namespace; an explicit
namespace takes precedence for that namespace. `ack_type` describes the
acknowledgement contract and can also be a tuple type for multiple ACK arguments
or `None` for an empty ACK. `call(response_model=...)` remains the way to
validate and type an individual call's returned value. A plain `emit()` without
a callback does not request an acknowledgement.

Handler return annotations are validated before their model values are sent as
acknowledgements. A tuple of return values remains multiple Socket.IO ack
arguments. The `response_model` can also be a `typing.Union` of response types.

### AsyncAPI schema

Export the operations registered on one server or client as an AsyncAPI 3.1
dictionary:

```python
document = server.asyncapi(title="Chat API", version="1.0.0")
```

The method is available on `Server`, `AsyncServer`, `Client`, and `AsyncClient`.
Title and version are explicit because Socket.IO endpoints do not store
AsyncAPI document metadata. Each call exports the current registrations,
including handlers or emits added since the previous call.

The same exporter is also available as a function:

```python
from pydantic_socketio import asyncapi_schema

document = asyncapi_schema(server, title="Chat API", version="1.0.0")
```

The export reflects this instance's local handlers and `register_emit()` calls;
it does not inspect the other endpoint. Each message payload is the Socket.IO
argument list. A declared ACK becomes an AsyncAPI reply, marked as a Socket.IO
ACK because it is tied to the event packet rather than sent as a separate event.
An omitted `ack_type` or handler return annotation leaves the ACK unspecified.
Legacy unscoped emit registrations are shown as applying to all namespaces,
with scoped overrides excluded. Lifecycle and catch-all handlers are listed as
omitted in the document because they are not concrete events.

### TypeScript codegen

[`@pydantic-socketio/codegen`](https://www.npmjs.com/package/@pydantic-socketio/codegen)
reads an exported AsyncAPI JSON file and generates event types for the official
Socket.IO TypeScript client or server. Export the contract from Python, then run:

```sh
npx @pydantic-socketio/codegen asyncapi.json -o src/socketio.generated.ts
```

See the [codegen guide](packages/codegen/README.md) for both client and server examples.
The Python runtime does not need Node.js.


### Migration: Monkey Patching Original Socket.IO

If replacing the original [python-socketio](https://github.com/miguelgrinberg/python-socketio)
constructors is impractical, call `monkey_patch()` before creating any Socket.IO
server or client instances. It changes the upstream classes throughout the
process; already-created instances do not have the required validation state.
For new code, use the enhanced classes above.

```python
from pydantic_socketio import monkey_patch
import socketio

# Apply the patch to the original Socket.IO server and client
monkey_patch()

# Use the original Socket.IO classes with Pydantic validation
sio = socketio.Server()

@sio.event
def ping(sid: str, data: int):
    print(f"Received ping: {data}")
    data += 1
    print(f"Sending pong: {data}")
    sio.emit("pong", data)
```


### FastAPI Integration

You can integrate the enhanced Socket.IO server with FastAPI using `FastAPISocketIO`:

```python
from fastapi import FastAPI
from pydantic_socketio import FastAPISocketIO

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}

# Create a FastAPI Socket.IO server
sio = FastAPISocketIO(app)

@sio.event
async def ping(sid: str, data: int):
    print(f"Received ping: {data}")
    data += 1
    print(f"Sending pong: {data}")
    await sio.emit("pong", data)

# Both sync and async event handlers are supported, as per the original python-socketio
@sio.on("custom_event")
def handle_custom_event(sid: str, data: int):
    ...
```

You can also integrate the Socket.IO server after creating the FastAPI app:

```python
from fastapi import FastAPI
from pydantic_socketio import FastAPISocketIO

sio = FastAPISocketIO()
app = FastAPI()

# Integrate the Socket.IO server with FastAPI
sio.integrate(app)
```


### FastAPI Dependency Injection

You can use `SioDep` as a `FastAPISocketIO` dependency injection in FastAPI applications:

```python
from fastapi import FastAPI
from pydantic_socketio import FastAPISocketIO, SioDep

app = FastAPI()
sio = FastAPISocketIO(app)

# You may define this endpoint in another file, like in a separate router
@app.get("/")
async def root(sio: SioDep):
    await sio.emit("message", "API root called")
    return {"Hello": "World"}
```


## Original Documentation

More details can be found in the original [python-socketio documentation](https://python-socketio.readthedocs.io/en/stable/).


## License

[Pydantic-SocketIO](https://github.com/atomiechen/Pydantic-SocketIO) © 2025 by [Atomie CHEN](https://github.com/atomiechen) is licensed under the [MIT License](https://github.com/atomiechen/Pydantic-SocketIO/blob/main/LICENSE).
