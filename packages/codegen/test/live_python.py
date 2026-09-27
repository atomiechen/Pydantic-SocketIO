"""Real Socket.IO counterpart for the codegen integration check."""

import sys
from threading import Event
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, make_server

from pydantic import BaseModel
import socketio

import pydantic_socketio


class Request(BaseModel):
    value: int


class Answer(BaseModel):
    doubled: int


class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def serve(port: int) -> None:
    server = pydantic_socketio.Server(async_mode="threading", async_handlers=False)
    server.register_emit("notice", Answer, namespace="/chat")

    @server.on("ask", namespace="/chat")
    def ask(sid: str, request: Request) -> Answer:
        server.emit(
            "notice", Answer(doubled=request.value * 2), to=sid, namespace="/chat"
        )
        return Answer(doubled=request.value * 2)

    app = socketio.WSGIApp(server)
    with make_server("127.0.0.1", port, app, server_class=ThreadedWSGIServer) as httpd:
        print("READY", flush=True)
        httpd.serve_forever()


def connect(port: int) -> None:
    client = pydantic_socketio.Client()
    observed = []
    notice_received = Event()
    confirmed = Event()

    @client.on("notice", namespace="/chat")
    def notice(request: Request) -> Answer:
        observed.append(request.value)
        notice_received.set()
        return Answer(doubled=request.value * 2)

    client.register_emit("ask", Request, namespace="/chat", ack_type=Answer)

    @client.on("confirmed", namespace="/chat")
    def confirmed_handler() -> None:
        confirmed.set()

    client.connect(
        f"http://127.0.0.1:{port}", namespaces=["/chat"], transports=["polling"]
    )
    response = client.call(
        "ask", Request(value=7), namespace="/chat", response_model=Answer
    )
    assert response.doubled == 14, response
    assert notice_received.wait(5), "notice was not received"
    assert observed == [3], observed
    assert confirmed.wait(5), "server did not confirm the notice ACK"
    client.disconnect()
    print("PYTHON_CLIENT_OK", flush=True)


if __name__ == "__main__":
    port = int(sys.argv[2])
    if sys.argv[1] == "server":
        serve(port)
    elif sys.argv[1] == "client":
        connect(port)
    else:
        raise ValueError(sys.argv[1])
