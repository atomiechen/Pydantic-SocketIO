import select  # for macos python 3.9 # noqa
import eventlet
from pydantic import BaseModel
import socketio
import pydantic_socketio


# pydantic_socketio.monkey_patch()


# create a Socket.IO server
# sio = socketio.Server()
sio = pydantic_socketio.Server()

# wrap with a WSGI application
app = socketio.WSGIApp(sio)


class Data(BaseModel):
    value: int
    description: str


@sio.event
def connect(sid: str, environ):
    print("==== connect ", sid)


@sio.on("*")
def get_event(sid: str, event: str, data):
    print("==== get_event ", sid, event, data)


@sio.on("disconnect")
def disconnect(sid: str, reason: str):
    print("==== disconnect ", sid, reason)


@sio.on("misc")
def misc(sid: str, data: Data):
    print("==== misc ", sid, type(data), data)
    ret = Data(value=data.value + 1, description="value increased by 1")
    sio.emit("misc", ret)


if __name__ == "__main__":
    eventlet.wsgi.server(eventlet.listen(("", 8000)), app)  # type: ignore
