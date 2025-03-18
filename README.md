# Pydantic-SocketIO

[![GitHub](https://img.shields.io/badge/github-Pydantic--SocketIO-blue?logo=github)](https://github.com/atomiechen/Pydantic-SocketIO)
[![PyPI](https://img.shields.io/pypi/v/Pydantic--SocketIO?logo=pypi&logoColor=white)](https://pypi.org/project/pydantic-socketio/)


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

# Define an event with Pydantic validation
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
```

The enhanced SocketIO client with Pydantic validation:

```python
import pydantic_socketio

# Create an enhanced SocketIO client; use AsyncClient for async client
sio = pydantic_socketio.Client()

@sio.event
def ping(data: int):
    ...

@sio.on("pong")
def handle_pong(data: int):
    ...
```


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
