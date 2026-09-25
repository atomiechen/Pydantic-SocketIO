"""Project registered Socket.IO operations onto AsyncAPI 3.1."""

import hashlib
import inspect
import json
import re
import types
from typing import Any, Dict, Iterable, List, Literal, Tuple, Union

from pydantic import TypeAdapter
from typing_extensions import Annotated, get_args, get_origin

from ._operation_contract import UNSPECIFIED, OperationContract

_EXTENSION = "x-pydantic-socketio"


def _operation_id(contract: OperationContract) -> str:
    key = contract.key
    parts = (key.direction, key.namespace, key.event)
    digest = hashlib.sha256(
        json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]

    def slug(value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()[:32] or "event"

    if key.namespace is None:
        namespace = "all"
    elif key.namespace == "/":
        namespace = "root"
    else:
        namespace = slug(key.namespace)
    return (
        "op_" + slug(key.event) + "_" + key.direction + "_" + namespace + "_" + digest
    )


def _arguments_schema(
    types: Tuple[Any, ...], context: str, prefix: str, schemas: Dict[str, Any]
) -> Dict[str, Any]:
    if any(item is Ellipsis for item in types):
        if len(types) != 2 or types[1] is not Ellipsis:
            raise ValueError("Unsupported variadic tuple in " + context)
        return {
            "type": "array",
            "items": _type_schema(types[0], context, prefix + "_0", schemas),
        }
    return {
        "type": "array",
        "prefixItems": [
            _type_schema(item, context, prefix + "_" + str(index), schemas)
            for index, item in enumerate(types)
        ],
        "minItems": len(types),
        "maxItems": len(types),
    }


def _type_schema(
    annotation: Any, context: str, prefix: str, schemas: Dict[str, Any]
) -> Dict[str, Any]:
    if annotation is inspect.Signature.empty or isinstance(annotation, str):
        raise ValueError("Unresolved or missing type annotation in " + context)
    try:
        schema = TypeAdapter(annotation).json_schema(
            ref_template="#/components/schemas/" + prefix + "_{model}"
        )
    except Exception as exc:
        raise ValueError("Cannot generate JSON Schema for " + context) from exc
    for name, definition in schema.pop("$defs", {}).items():
        schemas[prefix + "_" + name] = definition
    return schema


def _wire_schema(
    annotation: Any, context: str, prefix: str, schemas: Dict[str, Any]
) -> Dict[str, Any]:
    """Map a value to its Socket.IO argument list (tuple expands, None omits)."""
    if annotation is Any or annotation is object:
        return {"type": "array"}
    origin = get_origin(annotation)
    if origin is Annotated:
        inner_origin = get_origin(get_args(annotation)[0])
        if inner_origin in (tuple, Tuple):
            return _type_schema(annotation, context, prefix, schemas)
        union_type = getattr(types, "UnionType", None)
        if inner_origin is Union or (
            union_type is not None and inner_origin is union_type
        ):
            raise ValueError("Annotated union has ambiguous wire shape in " + context)
        return _arguments_schema((annotation,), context, prefix, schemas)
    union_type = getattr(types, "UnionType", None)
    if origin is Union or (union_type is not None and origin is union_type):
        return {
            "anyOf": [
                _wire_schema(item, context, prefix + "_" + str(index), schemas)
                for index, item in enumerate(get_args(annotation))
            ]
        }
    if annotation is None or annotation is type(None):
        arguments: Tuple[Any, ...] = ()
    elif origin in (tuple, Tuple):
        return _type_schema(annotation, context, prefix, schemas)
    else:
        arguments = (annotation,)
    return _arguments_schema(arguments, context, prefix, schemas)


def _operation_sort_key(contract: OperationContract) -> Tuple[str, str, str]:
    key = contract.key
    return key.namespace or "", key.event, key.direction


def generate_asyncapi(
    contracts: Iterable[OperationContract],
    title: str,
    version: str,
    role: Literal["server", "client"],
) -> Dict[str, Any]:
    """Build a document from local contracts; no network or runtime mutation."""
    document: Dict[str, Any] = {
        "asyncapi": "3.1.0",
        "info": {"title": title, "version": version},
        "channels": {},
        "operations": {},
        "components": {"messages": {}, "schemas": {}},
        _EXTENSION: {"formatVersion": 1, "role": role},
    }
    ordered = sorted(contracts, key=_operation_sort_key)
    omitted: List[Dict[str, str]] = []
    scoped = {
        (item.key.namespace, item.key.event)
        for item in ordered
        if item.key.direction == "send" and item.key.namespace is not None
    }
    for contract in ordered:
        key = contract.key
        if key.event in ("connect", "disconnect") and key.direction == "receive":
            # These handlers take connection metadata, not event payloads.
            omitted.append(
                {
                    "event": key.event,
                    "namespace": key.namespace or "*",
                    "reason": "lifecycle",
                }
            )
            continue
        if key.event == "*" or key.namespace == "*":
            omitted.append(
                {
                    "event": key.event,
                    "namespace": key.namespace or "*",
                    "reason": "catch-all",
                }
            )
            continue
        name = _operation_id(contract)
        if name in document["operations"]:
            raise ValueError("Operation identifier collision for " + repr(key))
        channel_name = name + "_channel"
        message_name = name + "_message"
        context = key.direction + " " + repr(key.event) + " in " + repr(key.namespace)
        document["components"]["messages"][message_name] = {
            "name": key.event,
            _EXTENSION: {"event": key.event},
            "payload": (
                _wire_schema(
                    contract.payload_types[0],
                    context,
                    message_name,
                    document["components"]["schemas"],
                )
                if key.direction == "send"
                else _arguments_schema(
                    contract.payload_types,
                    context,
                    message_name,
                    document["components"]["schemas"],
                )
            ),
        }
        channel: Dict[str, Any] = {
            "address": key.namespace,
            "messages": {
                message_name: {"$ref": "#/components/messages/" + message_name}
            },
        }
        if key.namespace is None:
            overrides: List[str] = sorted(
                namespace
                for namespace, event in scoped
                if event == key.event and namespace is not None
            )
            channel[_EXTENSION] = {"namespace": {"scope": "all", "except": overrides}}
        document["channels"][channel_name] = channel
        operation: Dict[str, Any] = {
            "summary": key.direction.capitalize()
            + " "
            + key.event
            + " ("
            + (key.namespace or "all namespaces")
            + ")",
            "action": key.direction,
            "channel": {"$ref": "#/channels/" + channel_name},
            "messages": [
                {"$ref": "#/channels/" + channel_name + "/messages/" + message_name}
            ],
        }
        if contract.ack_type is UNSPECIFIED:
            operation[_EXTENSION] = {"ack": "unspecified"}
        else:
            ack_channel_name = name + "_ack_channel"
            ack_message_name = name + "_ack_message"
            document["components"]["messages"][ack_message_name] = {
                "name": key.event + ".ack",
                "payload": _wire_schema(
                    contract.ack_type,
                    context + " ACK",
                    ack_message_name,
                    document["components"]["schemas"],
                ),
            }
            document["channels"][ack_channel_name] = {
                "address": None,
                "messages": {
                    ack_message_name: {
                        "$ref": "#/components/messages/" + ack_message_name
                    }
                },
            }
            operation["reply"] = {
                "channel": {"$ref": "#/channels/" + ack_channel_name},
                "messages": [
                    {
                        "$ref": "#/channels/"
                        + ack_channel_name
                        + "/messages/"
                        + ack_message_name
                    }
                ],
                _EXTENSION: {"ack": True},
            }
        document["operations"][name] = operation
    if omitted:
        document[_EXTENSION]["omittedOperations"] = omitted
    return document
