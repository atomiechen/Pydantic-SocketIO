"""Behavior that the operation-contract work must preserve or account for."""

import asyncio
from typing import Tuple, Union
from unittest.mock import patch

import pytest
from pydantic import BaseModel, ValidationError
from socketio.exceptions import TimeoutError as SocketIOTimeoutError

import pydantic_socketio
from pydantic_socketio._operation_contract import OperationKey


class Incoming(BaseModel):
    value: int


class Outgoing(BaseModel):
    text: str


class Reply(BaseModel):
    value: int


@pytest.mark.parametrize(
    "factory", [pydantic_socketio.Server, pydantic_socketio.Client]
)
def test_same_event_has_independent_receive_and_send_types(factory):
    sio = factory()

    if isinstance(sio, pydantic_socketio.Server):

        @sio.on("shared", namespace="/chat")
        def receive(sid: str, data: Incoming) -> Reply:
            return Reply(value=data.value + 1)

        args = ("sid", {"value": 2})
    else:

        @sio.on("shared", namespace="/chat")
        def receive(data: Incoming) -> Reply:
            return Reply(value=data.value + 1)

        args = ({"value": 2},)

    sio.register_emit("shared", Outgoing)
    assert sio.handlers["/chat"]["shared"](*args) == {"value": 3}
    receive_contract = sio._operation_contracts[
        OperationKey("/chat", "shared", "receive")
    ]
    send_contract = sio._operation_contracts[OperationKey(None, "shared", "send")]
    assert receive_contract.payload_types == (Incoming,)
    assert receive_contract.ack_type is Reply
    assert send_contract.payload_types == (Outgoing,)
    sio.validate_emit("shared", Outgoing(text="ok"))
    with pytest.raises(ValidationError):
        sio.validate_emit("shared", Incoming(value=2))


@pytest.mark.parametrize(
    "factory", [pydantic_socketio.Server, pydantic_socketio.Client]
)
def test_emit_registration_currently_applies_to_every_namespace(factory):
    sio = factory()
    sio.register_emit("shared", Outgoing)
    sio.validate_emit("shared", Outgoing(text="ok"))
    # register_emit has no namespace argument. Both emit and call use this
    # event-only registration even when their namespace is /chat.
    with pytest.raises(ValidationError):
        sio.validate_emit("shared", Incoming(value=2))

    original_name = (
        "_old_server_emit"
        if isinstance(sio, pydantic_socketio.Server)
        else "_old_client_emit"
    )
    with patch("pydantic_socketio.pydantic_socketio." + original_name) as original:
        sio.emit("shared", Outgoing(text="ok"), namespace="/chat")
        assert original.call_args.kwargs["namespace"] == "/chat"
        with pytest.raises(ValidationError):
            sio.emit("shared", Incoming(value=2), namespace="/chat")


@pytest.mark.parametrize(
    "factory", [pydantic_socketio.AsyncServer, pydantic_socketio.AsyncClient]
)
def test_async_event_decorator_keeps_custom_namespace_and_ack(factory):
    async def run():
        sio = (
            factory(async_mode="asgi")
            if factory is pydantic_socketio.AsyncServer
            else factory()
        )

        if isinstance(sio, pydantic_socketio.AsyncServer):

            @sio.event(namespace="/chat")
            async def shared(sid: str, data: Incoming) -> Reply:
                return Reply(value=data.value + 1)

            args = ("sid", {"value": 2})
        else:

            @sio.event(namespace="/chat")
            async def shared(data: Incoming) -> Reply:
                return Reply(value=data.value + 1)

            args = ({"value": 2},)

        assert await sio.handlers["/chat"]["shared"](*args) == {"value": 3}
        contract = sio._operation_contracts[OperationKey("/chat", "shared", "receive")]
        assert contract.payload_types == (Incoming,)
        assert contract.ack_type is Reply

    asyncio.run(run())


def test_call_response_type_is_per_invocation_and_timeout_propagates():
    client = pydantic_socketio.Client()
    with patch("pydantic_socketio.pydantic_socketio._old_client_call") as original:
        original.return_value = {"value": 2}
        assert client.call("ask", response_model=Reply) == Reply(value=2)
        assert client.call("ask") == {"value": 2}
        assert client.call("ask", response_model=Union[Reply, Outgoing]) == Reply(
            value=2
        )
        original.side_effect = SocketIOTimeoutError()
        with pytest.raises(SocketIOTimeoutError):
            client.call("ask", response_model=Reply)
    assert OperationKey(None, "ask", "send") not in client._operation_contracts


def test_emit_callback_is_forwarded_unmodified():
    client = pydantic_socketio.Client()

    def callback(*args):
        return args

    with patch("pydantic_socketio.pydantic_socketio._old_client_emit") as original:
        client.emit("ask", Incoming(value=1), callback=callback)
        assert original.call_args.kwargs["data"] == {"value": 1}
        assert original.call_args.kwargs["callback"] is callback


def test_multiple_handler_arguments_and_tuple_ack_are_recorded():
    server = pydantic_socketio.Server(async_mode="threading")

    @server.on("combine")
    def combine(sid: str, first: Incoming, second: str) -> Tuple[Reply, str]:
        return Reply(value=first.value + 1), second

    assert server.handlers["/"]["combine"]("sid", {"value": 2}, "ok") == (
        {"value": 3},
        "ok",
    )
    contract = server._operation_contracts[OperationKey("/", "combine", "receive")]
    assert contract.payload_types == (Incoming, str)
    assert contract.ack_type == Tuple[Reply, str]


def test_receive_contracts_are_separate_by_namespace():
    server = pydantic_socketio.Server(async_mode="threading")

    @server.on("shared")
    def root(sid: str, data: Incoming) -> Reply:
        return Reply(value=data.value)

    @server.on("shared", namespace="/chat")
    def chat(sid: str, data: Outgoing) -> str:
        return data.text

    root_contract = server._operation_contracts[OperationKey("/", "shared", "receive")]
    chat_contract = server._operation_contracts[
        OperationKey("/chat", "shared", "receive")
    ]
    assert root_contract.payload_types == (Incoming,)
    assert chat_contract.payload_types == (Outgoing,)
    assert server.handlers["/"]["shared"]("sid", {"value": 2}) == {"value": 2}
    assert server.handlers["/chat"]["shared"]("sid", {"text": "ok"}) == "ok"


def test_catch_all_and_lifecycle_handlers_do_not_confuse_payload_roles():
    server = pydantic_socketio.Server(async_mode="threading")

    @server.on("*", namespace="*")
    def any_event(event: str, namespace: str, sid: str, data: Incoming) -> Reply:
        return Reply(value=data.value)

    @server.on("connect")
    def connect(sid: str, environ: dict) -> bool:
        return True

    wildcard = server._operation_contracts[OperationKey("*", "*", "receive")]
    lifecycle = server._operation_contracts[OperationKey("/", "connect", "receive")]
    assert wildcard.payload_types == (Incoming,)
    assert wildcard.ack_type is Reply
    assert lifecycle.payload_types == ()
    assert server.handlers["*"]["*"]("shared", "/chat", "sid", {"value": 2}) == {
        "value": 2
    }
