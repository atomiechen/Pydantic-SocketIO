import asyncio
import subprocess
import sys
import threading
from socketserver import ThreadingMixIn
from typing import Union
from unittest.mock import patch
from wsgiref.simple_server import WSGIServer, make_server

import pytest
import socketio
from pydantic import BaseModel, ValidationError

import pydantic_socketio


class Request(BaseModel):
    value: int


class Response(BaseModel):
    value: int


class Error(BaseModel):
    message: str


def test_sync_client_call_validates_both_sides():
    client = pydantic_socketio.Client()
    client.register_emit("ask", Request)
    with patch("pydantic_socketio.pydantic_socketio._old_client_call") as original:
        original.return_value = {"value": 4}
        result = client.call(
            "ask",
            Request(value=3),
            namespace="/chat",
            timeout=7,
            response_model=Union[Response, Error],
        )
        assert result == Response(value=4)
        original.assert_called_once_with(
            client,
            "ask",
            data={"value": 3},
            namespace="/chat",
            timeout=7,
        )

        original.return_value = {"untyped": True}
        assert client.call("other", {"value": 3}) == {"untyped": True}
        with pytest.raises(ValidationError):
            client.call("ask", {"value": "not an int"})
        with pytest.raises(ValidationError):
            client.call("ask", Request(value=3), response_model=Response)


def test_call_keeps_multiple_socketio_arguments():
    client = pydantic_socketio.Client()
    with patch("pydantic_socketio.pydantic_socketio._old_client_call") as original:
        original.return_value = (1, 2)
        assert client.call("ask", (Request(value=3), "extra")) == (1, 2)
        assert original.call_args.kwargs["data"] == ({"value": 3}, "extra")

    with patch("pydantic_socketio.pydantic_socketio._old_client_emit") as original_emit:
        client.emit("ask", (Request(value=3), "extra"))
        assert original_emit.call_args.kwargs["data"] == ({"value": 3}, "extra")


def test_sync_server_call_forwards_native_arguments():
    server = pydantic_socketio.Server(async_mode="threading")
    with patch("pydantic_socketio.pydantic_socketio._old_server_call") as original:
        original.return_value = {"value": 5}
        assert server.call(
            "ask",
            Request(value=3),
            to="recipient",
            sid="alias",
            namespace="/chat",
            timeout=7,
            ignore_queue=True,
            response_model=Response,
        ) == Response(value=5)
        original.assert_called_once_with(
            server,
            "ask",
            data={"value": 3},
            to="recipient",
            sid="alias",
            namespace="/chat",
            timeout=7,
            ignore_queue=True,
        )


def test_async_client_and_server_call():
    async def run():
        client = pydantic_socketio.AsyncClient()
        server = pydantic_socketio.AsyncServer(async_mode="asgi")
        with patch(
            "pydantic_socketio.pydantic_socketio._old_client_call_async"
        ) as client_call:
            client_call.return_value = {"value": 4}
            assert await client.call(
                "ask", Request(value=3), response_model=Response
            ) == Response(value=4)
            client_call.assert_awaited_once_with(
                client,
                "ask",
                data={"value": 3},
                namespace=None,
                timeout=60,
            )
        with patch(
            "pydantic_socketio.pydantic_socketio._old_server_call_async"
        ) as server_call:
            server_call.return_value = {"value": 5}
            assert await server.call(
                "ask", Request(value=3), response_model=Response
            ) == Response(value=5)
            server_call.assert_awaited_once_with(
                server,
                "ask",
                data={"value": 3},
                to=None,
                sid=None,
                namespace=None,
                timeout=60,
                ignore_queue=False,
            )

    asyncio.run(run())


def test_handler_return_validation_and_ack_arguments():
    server = pydantic_socketio.Server(async_mode="threading")

    @server.on("ask")
    def ask(sid: str, data: Request) -> Response:
        return Response(value=data.value + 1)

    assert server.handlers["/"]["ask"]("sid", {"value": 3}) == {"value": 4}

    @server.on("invalid")
    def invalid(sid: str, data: Request) -> Response:
        return Error(message="wrong type")

    with pytest.raises(ValidationError):
        server.handlers["/"]["invalid"]("sid", {"value": 3})

    @server.on("multiple")
    def multiple(sid: str) -> tuple:
        return Response(value=1), Response(value=2)

    assert server.handlers["/"]["multiple"]("sid") == (
        {"value": 1},
        {"value": 2},
    )

    @server.on("connect")
    def connect(sid: str, environ: dict) -> bool:
        return False

    assert server.handlers["/"]["connect"]("sid", {}) is False


def test_async_handler_return_validation():
    async def run():
        server = pydantic_socketio.AsyncServer(async_mode="asgi")

        @server.on("ask")
        async def ask(sid: str, data: Request) -> Response:
            return Response(value=data.value + 1)

        assert await server.handlers["/"]["ask"]("sid", {"value": 3}) == {"value": 4}

    asyncio.run(run())


def test_monkey_patch_call_in_separate_process():
    code = """
import socketio
from unittest.mock import patch
from pydantic import BaseModel
import pydantic_socketio

class Reply(BaseModel):
    value: int

pydantic_socketio.monkey_patch()
client = socketio.Client()
client.register_emit('ask', Reply, namespace='/chat', ack_type=Reply)
assert client._operation_contracts
with patch('pydantic_socketio.pydantic_socketio._old_client_call', return_value={'value': 2}) as original:
    result = client.call('ask', {'value': 1}, namespace='/chat', response_model=Reply)
    assert result == Reply(value=2)
    assert original.call_args.kwargs['data'] == {'value': 1}
"""
    subprocess.run([sys.executable, "-c", code], check=True)


class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def test_real_client_server_ack_round_trip():
    server = pydantic_socketio.Server(
        async_mode="threading", ping_interval=2, ping_timeout=5
    )
    connected = []

    @server.on("connect")
    def connect(sid: str, environ: dict) -> None:
        connected.append(sid)

    @server.on("ask")
    def ask(sid: str, data: Request) -> Response:
        return Response(value=data.value + 1)

    http = make_server(
        "127.0.0.1", 0, socketio.WSGIApp(server), server_class=ThreadedWSGIServer
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    client = pydantic_socketio.Client()

    @client.on("probe")
    def probe(data: Request) -> Response:
        return Response(value=data.value + 2)

    try:
        client.connect("http://127.0.0.1:%d" % http.server_port, transports=["polling"])
        assert client.call(
            "ask", Request(value=3), response_model=Response
        ) == Response(value=4)
        assert server.call(
            "probe", Request(value=5), to=connected[0], response_model=Response
        ) == Response(value=7)
    finally:
        if client.connected:
            client.disconnect()
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)
