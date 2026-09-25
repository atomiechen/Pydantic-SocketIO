"""AsyncAPI projection from real local registrations."""

import json
import subprocess
import sys
from typing import Any, Tuple, Union

import pytest
import socketio
from pydantic import BaseModel, create_model
from typing_extensions import Annotated

import pydantic_socketio


class Nested(BaseModel):
    value: int


class Request(BaseModel):
    nested: Nested


class Response(BaseModel):
    answer: str


def operation_message(document, operation):
    ref = operation["messages"][0]["$ref"]
    name = ref.split("/")[-1]
    return document["components"]["messages"][name]


def reply_message(document, operation):
    ref = operation["reply"]["messages"][0]["$ref"]
    name = ref.split("/")[-1]
    return document["components"]["messages"][name]


def channel(document, operation):
    name = operation["channel"]["$ref"].split("/")[-1]
    return document["channels"][name]


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
def test_export_scoped_send_and_ack_shapes(factory):
    sio = make_sio(factory)
    sio.register_emit("empty", Request, namespace="/chat", ack_type=None)
    sio.register_emit("single", Request, namespace="/chat", ack_type=Response)
    sio.register_emit("multiple", Request, namespace="/chat", ack_type=Tuple[int, str])
    sio.register_emit("unknown", Request, namespace="/chat")

    document = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    assert document["asyncapi"] == "3.1.0"
    assert document["info"] == {"title": "Test", "version": "1.0"}
    expected_role = (
        "server"
        if factory in (pydantic_socketio.Server, pydantic_socketio.AsyncServer)
        else "client"
    )
    assert document["x-pydantic-socketio"]["role"] == expected_role
    assert len(document["operations"]) == 4
    by_event = {
        operation_message(document, operation)["name"]: operation
        for operation in document["operations"].values()
    }
    for operation in by_event.values():
        assert operation["action"] == "send"
        assert operation["summary"].startswith("Send ")
        assert channel(document, operation)["address"] == "/chat"
        message = operation_message(document, operation)
        assert message["x-pydantic-socketio"]["event"] == message["name"]
        request = message["payload"]
        assert request["type"] == "array"
        assert request["minItems"] == request["maxItems"] == 1
        nested_ref = request["prefixItems"][0]["properties"]["nested"]["$ref"]
        assert nested_ref.startswith("#/components/schemas/")
    assert "reply" not in by_event["unknown"]
    assert by_event["unknown"]["x-pydantic-socketio"]["ack"] == "unspecified"
    assert reply_message(document, by_event["empty"])["payload"]["maxItems"] == 0
    assert reply_message(document, by_event["single"])["payload"]["maxItems"] == 1
    assert reply_message(document, by_event["multiple"])["payload"]["maxItems"] == 2
    assert by_event["single"]["reply"]["x-pydantic-socketio"]["ack"] is True
    # Local component refs are valid even with nested Pydantic models.
    assert document["components"]["schemas"]


@pytest.mark.parametrize(
    "factory", [pydantic_socketio.Server, pydantic_socketio.AsyncServer]
)
def test_export_server_receive_multiarg_and_bidirectional(factory):
    sio = make_sio(factory)
    sio.register_emit("shared", Response, namespace="/chat", ack_type=None)

    if factory is pydantic_socketio.AsyncServer:

        @sio.on("shared", namespace="/chat")
        async def receive(sid: str, first: Request, second: int) -> Tuple[int, str]:
            return first.nested.value + second, "ok"

    else:

        @sio.on("shared", namespace="/chat")
        def receive(sid: str, first: Request, second: int) -> Tuple[int, str]:
            return first.nested.value + second, "ok"

    document = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    operations = list(document["operations"].values())
    assert len(operations) == 2
    assert {item["action"] for item in operations} == {"send", "receive"}
    incoming = next(item for item in operations if item["action"] == "receive")
    assert operation_message(document, incoming)["payload"]["maxItems"] == 2
    assert reply_message(document, incoming)["payload"]["maxItems"] == 2
    assert channel(document, incoming)["address"] == "/chat"


@pytest.mark.parametrize(
    "factory", [pydantic_socketio.Client, pydantic_socketio.AsyncClient]
)
def test_export_client_receive(factory):
    sio = make_sio(factory)
    if factory is pydantic_socketio.AsyncClient:

        @sio.on("update", namespace="/chat")
        async def receive(data: Request) -> Response:
            return Response(answer=str(data.nested.value))

    else:

        @sio.on("update", namespace="/chat")
        def receive(data: Request) -> Response:
            return Response(answer=str(data.nested.value))

    document = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    operation = next(iter(document["operations"].values()))
    assert operation["action"] == "receive"
    assert operation_message(document, operation)["payload"]["maxItems"] == 1
    assert reply_message(document, operation)["payload"]["maxItems"] == 1


def test_legacy_unscoped_registration_and_scoped_override():
    sio = pydantic_socketio.Client()
    sio.register_emit("same", Request)
    sio.register_emit("same", Response, namespace="/chat")
    sio.register_emit("same", Request, namespace="/other")
    first = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    second = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert len(first["operations"]) == 3
    addresses = [
        channel(first, item)["address"] for item in first["operations"].values()
    ]
    assert addresses == [None, "/chat", "/other"]
    wildcard = next(
        item
        for item in first["operations"].values()
        if channel(first, item)["address"] is None
    )
    assert channel(first, wildcard)["x-pydantic-socketio"]["namespace"] == {
        "scope": "all",
        "except": ["/chat", "/other"],
    }


def test_wire_shape_handles_annotated_tuple_and_union():
    sio = pydantic_socketio.Client()
    sio.register_emit(
        "variable",
        Annotated[Tuple[int, str], "two arguments"],
        namespace="/",
        ack_type=Union[None, Response, Tuple[int, str]],
    )
    document = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    operation = next(iter(document["operations"].values()))
    assert operation_message(document, operation)["payload"]["maxItems"] == 2
    variants = reply_message(document, operation)["payload"]["anyOf"]
    assert [item["maxItems"] for item in variants] == [0, 1, 2]


def test_any_ack_does_not_claim_a_single_argument():
    sio = pydantic_socketio.Client()
    sio.register_emit("unknown-shape", Any, namespace="/", ack_type=Any)
    document = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    operation = next(iter(document["operations"].values()))
    assert operation_message(document, operation)["payload"] == {"type": "array"}
    assert reply_message(document, operation)["payload"] == {"type": "array"}


def test_same_event_across_namespaces_and_punctuation_has_unique_operations():
    sio = pydantic_socketio.Server(async_mode="threading")

    @sio.on("a/b", namespace="/one")
    def one(sid: str, data: Request) -> None:
        pass

    @sio.on("a_b", namespace="/one")
    def punctuation(sid: str, data: Response) -> None:
        pass

    @sio.on("a/b", namespace="/two")
    def two(sid: str, data: Response) -> None:
        pass

    document = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    assert len(document["operations"]) == 3
    assert all(name.startswith("op_a_b_receive_") for name in document["operations"])
    observed = {
        (
            channel(document, operation)["address"],
            operation_message(document, operation)["name"],
        )
        for operation in document["operations"].values()
    }
    assert observed == {("/one", "a/b"), ("/one", "a_b"), ("/two", "a/b")}


def test_export_keys_do_not_depend_on_registration_order():
    first = pydantic_socketio.Client()
    second = pydantic_socketio.Client()
    for event in ("alpha", "beta"):
        first.register_emit(event, Request, namespace="/chat")
    for event in ("beta", "alpha"):
        second.register_emit(event, Request, namespace="/chat")
    assert pydantic_socketio.asyncapi_schema(first, title="Test", version="1.0") == (
        pydantic_socketio.asyncapi_schema(second, title="Test", version="1.0")
    )


def test_same_named_models_have_distinct_component_schemas():
    first = create_model("Item", __module__="first_module", value=(int, ...))
    second = create_model("Item", __module__="second_module", value=(str, ...))
    first_outer = create_model("Container", item=(first, ...))
    second_outer = create_model("Container", item=(second, ...))
    sio = pydantic_socketio.Client()
    sio.register_emit("first", first_outer, namespace="/")
    sio.register_emit("second", second_outer, namespace="/")
    document = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    fields = {}
    for operation in document["operations"].values():
        payload = operation_message(document, operation)["payload"]["prefixItems"][0]
        reference = payload["properties"]["item"]["$ref"]
        component = reference.split("/")[-1]
        fields[operation_message(document, operation)["name"]] = document["components"][
            "schemas"
        ][component]["properties"]["value"]["type"]
    assert fields == {"first": "integer", "second": "string"}


def test_lifecycle_and_catchall_are_reported_without_blocking_specific_events():
    sio = pydantic_socketio.Server(async_mode="threading")

    @sio.on("connect")
    def connect(sid: str, environ: dict) -> None:
        pass

    @sio.on("*", namespace="*")
    def catchall(event: str, namespace: str, sid: str, data: Request) -> None:
        pass

    @sio.on("normal")
    def normal(sid: str) -> None:
        pass

    document = pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")
    assert len(document["operations"]) == 1
    operation = next(iter(document["operations"].values()))
    assert operation_message(document, operation)["payload"]["maxItems"] == 0
    assert document["x-pydantic-socketio"]["omittedOperations"] == [
        {"event": "*", "namespace": "*", "reason": "catch-all"},
        {"event": "connect", "namespace": "/", "reason": "lifecycle"},
    ]


def test_unannotated_payload_fails_with_operation_context():
    sio = pydantic_socketio.Server(async_mode="threading")

    @sio.on("broken")
    def broken(sid: str, data) -> None:
        pass

    with pytest.raises(ValueError, match="receive 'broken' in '/'"):
        pydantic_socketio.asyncapi_schema(sio, title="Test", version="1.0")


def test_unpatched_socketio_instance_is_rejected_clearly():
    with pytest.raises(TypeError, match="no Pydantic-SocketIO registrations"):
        pydantic_socketio.asyncapi_schema(
            socketio.Client(), title="Test", version="1.0"
        )


def test_monkey_patch_uses_same_exporter_in_fresh_process():
    code = """
import json
import socketio
import pydantic_socketio
from pydantic import BaseModel
pydantic_socketio.monkey_patch()
class Data(BaseModel):
    value: int
for factory in (socketio.Server, socketio.AsyncServer, socketio.Client, socketio.AsyncClient):
    sio = factory(async_mode='asgi') if factory is socketio.AsyncServer else factory()
    sio.register_emit('event', Data, namespace='/chat', ack_type=int)
    document = pydantic_socketio.asyncapi_schema(sio, title='Test', version='1.0')
    assert len(document['operations']) == 1
    assert json.dumps(document)
"""
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
