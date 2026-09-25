"""Outgoing declarations and upstream ACK argument behavior."""

import asyncio
import inspect
import threading
from socketserver import ThreadingMixIn
from typing import Tuple
from unittest.mock import patch
from wsgiref.simple_server import WSGIServer, make_server

import pytest
import socketio
from pydantic import BaseModel, ValidationError

import pydantic_socketio
from pydantic_socketio._operation_contract import UNSPECIFIED, OperationKey


class RootPayload(BaseModel):
    value: int


class ChatPayload(BaseModel):
    text: str


class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def make_sio(factory):
    if factory is pydantic_socketio.Server:
        return factory(async_mode="threading")
    if factory is pydantic_socketio.AsyncServer:
        return factory(async_mode="asgi")
    return factory()


@pytest.mark.parametrize(
    "factory",
    [
        pydantic_socketio.Server,
        pydantic_socketio.AsyncServer,
        pydantic_socketio.Client,
        pydantic_socketio.AsyncClient,
    ],
)
def test_scoped_registration_overrides_legacy_unscoped_registration(factory):
    sio = make_sio(factory)
    assert sio.register_emit("shared", RootPayload) is RootPayload
    assert (
        sio.register_emit(
            "shared", ChatPayload, namespace="/chat", ack_type=Tuple[int, str]
        )
        is ChatPayload
    )

    sio.validate_emit("shared", RootPayload(value=1))
    sio.validate_emit("shared", RootPayload(value=1), namespace="/other")
    sio.validate_emit("shared", ChatPayload(text="ok"), namespace="/chat")
    with pytest.raises(ValidationError):
        sio.validate_emit("shared", RootPayload(value=1), namespace="/chat")
    with pytest.raises(ValidationError):
        sio.validate_emit("shared", ChatPayload(text="ok"), namespace="/other")

    unscoped = sio._operation_contracts[OperationKey(None, "shared", "send")]
    scoped = sio._operation_contracts[OperationKey("/chat", "shared", "send")]
    assert unscoped.ack_type is UNSPECIFIED
    assert scoped.ack_type == Tuple[int, str]


def test_decorator_and_explicit_default_namespace():
    client = pydantic_socketio.Client()

    @client.register_emit("hello", namespace="/", ack_type=None)
    class Hello(BaseModel):
        value: int

    contract = client._operation_contracts[OperationKey("/", "hello", "send")]
    assert contract.payload_types == (Hello,)
    assert contract.ack_type is None  # an empty ACK, distinct from unspecified
    client.validate_emit("hello", Hello(value=1))
    client.validate_emit("hello", {"other": True}, namespace="/chat")


def test_postponed_handler_annotations_are_resolved_for_contract():
    server = pydantic_socketio.Server(async_mode="threading")

    @server.on("forward")
    def handler(sid: str, data: "RootPayload") -> "ChatPayload":
        return ChatPayload(text=str(data.value))

    contract = server._operation_contracts[OperationKey("/", "forward", "receive")]
    assert contract.payload_types == (RootPayload,)
    assert contract.ack_type is ChatPayload


def test_registered_tuple_payload_keeps_multiple_wire_arguments():
    client = pydantic_socketio.Client()
    payload_type = Tuple[RootPayload, str]
    client.register_emit("multi", payload_type, namespace="/chat")
    contract = client._operation_contracts[OperationKey("/chat", "multi", "send")]
    assert contract.payload_types == (payload_type,)

    with patch("pydantic_socketio.pydantic_socketio._old_client_emit") as original:
        client.emit("multi", (RootPayload(value=2), "ok"), namespace="/chat")
        assert original.call_args.kwargs["data"] == ({"value": 2}, "ok")
        with pytest.raises(ValidationError):
            client.emit("multi", (RootPayload(value=2), 7), namespace="/chat")


@pytest.mark.parametrize(
    "factory,original_name",
    [
        (pydantic_socketio.Server, "_old_server_call"),
        (pydantic_socketio.AsyncServer, "_old_server_call_async"),
        (pydantic_socketio.Client, "_old_client_call"),
        (pydantic_socketio.AsyncClient, "_old_client_call_async"),
    ],
)
def test_call_uses_scoped_request_and_keeps_explicit_response_model(
    factory, original_name
):
    async def run():
        sio = make_sio(factory)
        sio.register_emit("ask", RootPayload)
        sio.register_emit("ask", ChatPayload, namespace="/chat", ack_type=RootPayload)
        with patch("pydantic_socketio.pydantic_socketio." + original_name) as original:
            original.return_value = {"value": 2}
            issued = sio.call("ask", ChatPayload(text="hi"), namespace="/chat")
            raw = await issued if inspect.isawaitable(issued) else issued
            assert raw == {"value": 2}  # no implicit response_model inference

            issued = sio.call(
                "ask",
                ChatPayload(text="hi"),
                namespace="/chat",
                response_model=RootPayload,
            )
            typed = await issued if inspect.isawaitable(issued) else issued
            assert typed == RootPayload(value=2)
            assert original.call_args.kwargs["namespace"] == "/chat"

            with pytest.raises(ValidationError):
                issued = sio.call("ask", RootPayload(value=1), namespace="/chat")
                if inspect.isawaitable(issued):
                    await issued

    asyncio.run(run())


@pytest.mark.parametrize(
    "ack_value,wire_args", [(None, []), (3, [3]), ((3, "ok"), [3, "ok"])]
)
def test_upstream_handler_ack_wire_shape(ack_value, wire_args):
    server = pydantic_socketio.Server(async_mode="threading")

    @server.on("ack")
    def handler(sid: str):
        return ack_value

    with patch.object(server, "_send_packet") as send:
        server._handle_event_internal(server, "sid", "eio", ["ack"], "/", None)
        send.assert_not_called()  # one-way emit requests no ACK packet

        server._handle_event_internal(server, "sid", "eio", ["ack"], "/", 7)
        assert send.call_args.args[1].data == wire_args


@pytest.mark.parametrize(
    "wire_args,result", [((), None), ((3,), 3), ((3, "ok"), (3, "ok"))]
)
def test_upstream_call_flattens_ack_argument_count(wire_args, result):
    client = pydantic_socketio.Client()

    def emit(event, data=None, namespace=None, callback=None):
        callback(*wire_args)

    with patch.object(client, "emit", side_effect=emit):
        assert client.call("ack") == result


@pytest.mark.parametrize(
    "factory,original_name",
    [
        (pydantic_socketio.Server, "_old_server_emit"),
        (pydantic_socketio.AsyncServer, "_old_server_emit_async"),
        (pydantic_socketio.Client, "_old_client_emit"),
        (pydantic_socketio.AsyncClient, "_old_client_emit_async"),
    ],
)
def test_emit_uses_scoped_payload_validation(factory, original_name):
    async def run():
        sio = make_sio(factory)
        sio.register_emit("shared", RootPayload)
        sio.register_emit("shared", ChatPayload, namespace="/chat")
        with patch("pydantic_socketio.pydantic_socketio." + original_name) as original:
            issued = sio.emit("shared", ChatPayload(text="ok"), namespace="/chat")
            if inspect.isawaitable(issued):
                await issued
            assert original.call_args.kwargs["namespace"] == "/chat"
            with pytest.raises(ValidationError):
                issued = sio.emit("shared", RootPayload(value=1), namespace="/chat")
                if inspect.isawaitable(issued):
                    await issued

    asyncio.run(run())


def test_real_custom_namespace_call_and_emit_callback_tuple_ack():
    server = pydantic_socketio.Server(async_mode="threading")

    @server.on("ask", namespace="/chat")
    def ask(sid: str, data: ChatPayload) -> Tuple[int, str]:
        return len(data.text), "ok"

    http = make_server(
        "127.0.0.1", 0, socketio.WSGIApp(server), server_class=ThreadedWSGIServer
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    client = pydantic_socketio.Client()
    client.register_emit(
        "ask", ChatPayload, namespace="/chat", ack_type=Tuple[int, str]
    )
    seen = []
    acknowledged = threading.Event()

    def callback(*args):
        seen.append(args)
        acknowledged.set()

    try:
        client.connect(
            "http://127.0.0.1:%d" % http.server_port,
            namespaces=["/chat"],
            transports=["polling"],
        )
        assert client.call(
            "ask",
            ChatPayload(text="abc"),
            namespace="/chat",
            response_model=Tuple[int, str],
        ) == (3, "ok")
        client.emit(
            "ask", ChatPayload(text="abcd"), namespace="/chat", callback=callback
        )
        assert acknowledged.wait(5)
        assert seen == [(4, "ok")]
    finally:
        if client.connected:
            client.disconnect()
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)
