# Pydantic-SocketIO

[![GitHub](https://img.shields.io/badge/github-Pydantic--SocketIO-blue?logo=github)](https://github.com/atomiechen/Pydantic-SocketIO)
[![PyPI](https://img.shields.io/pypi/v/Pydantic--SocketIO?logo=pypi&logoColor=white)](https://pypi.org/project/pydantic-socketio/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/atomiechen/Pydantic-SocketIO)


A Pydantic-enhanced SocketIO library for Python, with FastAPI integration.


## Features

⭐️ **Pydantic-Enhanced SocketIO**: Drop-in replacements for the original [python-socketio](https://github.com/miguelgrinberg/python-socketio) server and client (sync and async), with built-in Pydantic validation for event data. You can also easily monkey patch this validation to the original `socketio` server and client.

🪐 **Easy Integration with FastAPI**: Seamlessly integrates `Socket.IO` with FastAPI, allowing you to manage event-driven communication effortlessly.


## Installation

```sh
pip install pydantic-socketio
```

If you want FastAPI integration, you can install the extra dependencies:

```sh
pip install pydantic-socketio[fastapi]
```

Other options of original [python-socketio](https://github.com/miguelgrinberg/python-socketio) are also available: `client`, `asyncio-client`, `docs`.


## Usage

### Recommended: Pydantic-Enhanced SocketIO Server and Client

Drop-in replacements for the original [python-socketio](https://github.com/miguelgrinberg/python-socketio) server and client are provided. 

The enhanced SocketIO server with Pydantic validation:

```python
from pydantic import BaseModel
import pydantic_socketio

class ChatMessage(BaseModel):
    role: str
    content: str

# Create an enhanced SocketIO server; use AsyncServer for async server
sio = pydantic_socketio.Server()

# Define a listen event with Pydantic validation
@sio.event
def message(data: ChatMessage):
    print(f"Received chat message from {data.role}: {data.content}")
    data.content = data.content.upper()
    print(f"Sending uppercase message: {data.content}")
    # Emit an event with Pydantic model without any additional conversion
    sio.emit("message", data)

# `on` decorator is also supported
@sio.on("custom_event")
def handle_custom_event(data: int):
    ...

# Register an emit event with Pydantic validation
sio.register_emit("message", payload_type=ChatMessage)

# Or, use the decorator form
@sio.register_emit("misc")
class MiscData(BaseModel):
    value: int
```

The enhanced SocketIO client with Pydantic validation:

```python
import pydantic_socketio

# Create an enhanced SocketIO client; use AsyncClient for async client
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

client = pydantic_socketio.AsyncClient()
client.register_emit("question", Question)
# After connecting the client:
result = await client.call("question", Question(value=3), response_model=Answer)
assert result == Answer(value=4)
```

Handler return annotations are validated before their model values are sent as
acknowledgements. A tuple of return values remains multiple Socket.IO ack
arguments. The `response_model` can also be a `typing.Union` of response types.


### Alternative: Monkey Patching for Original SocketIO

Alternatively, if you want to apply Pydantic validation to the original [python-socketio](https://github.com/miguelgrinberg/python-socketio) server and client without replacing them, you can use the `monkey_patch()` method:

```python
from pydantic_socketio import monkey_patch
import socketio

# Apply monkey patch to the original socketio server and client
monkey_patch()

# Now, you can use the original socketio server and client with Pydantic validation
sio = socketio.Server()

@sio.event
def ping(data: int):
    print(f"Received ping: {data}")
    data += 1
    print(f"Sending pong: {data}")
    sio.emit("poing", data)
```


### FastAPI Integration

You can easily integrate the enhanced socketio server with FastAPI by using FastAPISocketIO:

```python
from fastapi import FastAPI
from pydantic_socketio import FastAPISocketIO

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}
...

# Create a FastAPI socketio server
sio = FastAPISocketIO(app)

@sio.event
async def ping(data: int):
    print(f"Received ping: {data}")
    data += 1
    print(f"Sending pong: {data}")
    await sio.emit("pong", data)

# Both sync and async event handlers are supported, as per the original python-socketio
@sio.on("custom_event")
def handle_custom_event(data: int):
    ...
```

You can also integrate the SocketIO server manually after FastAPI initialization:

```python
from fastapi import FastAPI
from pydantic_socketio import FastAPISocketIO

sio = FastAPISocketIO()
...
app = FastAPI()
...

# Integrate the SocketIO server to FastAPI
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
