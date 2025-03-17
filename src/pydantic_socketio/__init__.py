# first import everything from socketio
from socketio import *  # type: ignore # noqa: F403

from .pydantic_socketio import (
    BaseClient as BaseClient,
    Client as Client,
    AsyncClient as AsyncClient,
    BaseServer as BaseServer,
    Server as Server,
    AsyncServer as AsyncServer,
    monkey_patch as monkey_patch,
)

from .fastapi_socketio import (
    FastAPISocketIO as FastAPISocketIO,
    SioDep as SioDep,
)
