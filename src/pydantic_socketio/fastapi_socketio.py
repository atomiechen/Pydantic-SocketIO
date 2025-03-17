from typing import TYPE_CHECKING, Annotated, Optional

from fastapi import Depends, HTTPException, Request

if TYPE_CHECKING:
    from fastapi import FastAPI

from . import AsyncServer, ASGIApp


class FastAPISocketIO(AsyncServer):
    """
    Pydantic SocketIO server for FastAPI. This class is a subclass of AsyncServer
    and is used to create a SocketIO server that can be mounted on a FastAPI app.
    It also adds `sio` to the FastAPI app state.
    """

    def __init__(
        self,
        app: Optional["FastAPI"] = None,
        socketio_path: str = "socket.io",
        **kwargs,
    ) -> None:
        # disable socketio CORS handling and let fastapi CORS handle it
        super().__init__(cors_allowed_origins=[], async_mode="asgi", **kwargs)
        self.socketio_path = socketio_path
        if app:
            self.integrate(app)

    def integrate(self, app: "FastAPI"):
        """Integrate the FastAPISocketIO server with a FastAPI app."""
        try:
            from fastapi import FastAPI
        except ImportError:
            raise ImportError(
                "FastAPI is not installed. Please install FastAPI to use FastAPISocketIO."
            )
        assert isinstance(app, FastAPI), "app must be a FastAPI instance"
        self.sio_app = ASGIApp(socketio_server=self, socketio_path=self.socketio_path)
        app.mount("/" + self.socketio_path, self.sio_app)
        app.state.sio = self
        self.fastapi_app = app


async def get_sio(request: Request) -> FastAPISocketIO:
    app: "FastAPI" = request.app
    try:
        sio = app.state.sio
    except AttributeError:
        sio = None
    if not isinstance(sio, FastAPISocketIO):
        raise HTTPException(status_code=500, detail="Internal server error")
    return sio


SioDep = Annotated[FastAPISocketIO, Depends(get_sio)]
