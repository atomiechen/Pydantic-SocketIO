# first import everything from socketio
from socketio import *  # type: ignore # noqa: F403

from .pydantic_socketio import (
    Client as Client,
    AsyncClient as AsyncClient,
    Server as Server,
    AsyncServer as AsyncServer,
    monkey_patch as monkey_patch,
)

# import only if fastapi is installed
try:
    import fastapi as _fastapi  # noqa: F401
except ImportError:
    pass
else:
    from .fastapi_socketio import (
        FastAPISocketIO as FastAPISocketIO,
        SioDep as SioDep,
    )
