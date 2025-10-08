import time

from pydantic import BaseModel
import pydantic_socketio

# pydantic_socketio.monkey_patch()


def test_client():
    class Data(BaseModel):
        value: int
        description: str

    sio = pydantic_socketio.Client()

    @sio.on("misc")
    def misc(data: Data):
        print("==== misc ", data, type(data))

    data = Data(value=123, description="test")
    return sio, data


if __name__ == "__main__":
    sio, data = test_client()
    sio.connect("http://localhost:8000")
    # sio.connect("http://localhost:8000", transports=["websocket"])
    sio.emit("misc", data)
    time.sleep(2)
