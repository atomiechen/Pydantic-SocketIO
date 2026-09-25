"""Private description of locally registered Socket.IO operations."""

import inspect
from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional, Tuple

from typing_extensions import get_type_hints


class _Unspecified:
    """An absent declaration, distinct from an explicit empty ACK (None)."""


UNSPECIFIED = _Unspecified()


@dataclass(frozen=True)
class OperationKey:
    # None means an unscoped outgoing registration, which applies to all
    # namespaces. Inbound registrations always have a concrete namespace.
    namespace: Optional[str]
    event: str
    direction: Literal["send", "receive"]


@dataclass(frozen=True)
class OperationContract:
    key: OperationKey
    payload_types: Tuple[Any, ...]
    # The handler's return type or an outgoing ACK declaration. Socket.IO
    # expands tuple values into multiple ACK arguments and None into zero.
    # UNSPECIFIED means no type was declared; it does not mean no ACK occurs.
    ack_type: Any = UNSPECIFIED


def send_contract(
    event: str, namespace: Optional[str], payload_type: Any, ack_type: Any
) -> OperationContract:
    resolved_namespace = None if namespace is None else namespace or "/"
    key = OperationKey(resolved_namespace, event, "send")
    return OperationContract(key, (payload_type,), ack_type)


def receive_contract(
    event: str,
    namespace: Optional[str],
    handler: Callable,
    role: Literal["server", "client"],
) -> OperationContract:
    key = OperationKey(namespace or "/", event, "receive")
    signature = inspect.signature(handler)
    try:
        hints = get_type_hints(handler, include_extras=True)
    except (NameError, TypeError):
        # Validation still belongs to Pydantic. Unsupported or unresolved
        # annotations remain visible as such to future schema exporters.
        hints = {}
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    # Catch-all handlers receive an event and/or namespace before the normal
    # arguments. Server handlers additionally receive a sid.
    prefix = (role == "server") + (event == "*") + (namespace == "*")
    if event in ("connect", "disconnect"):
        payload_types = ()
        ack_type = UNSPECIFIED
    else:
        payload_types = tuple(
            hints.get(parameter.name, parameter.annotation)
            for parameter in positional[prefix:]
        )
        ack_type = signature.return_annotation
        if ack_type is inspect.Signature.empty:
            ack_type = UNSPECIFIED
        elif ack_type is not None:
            ack_type = hints.get("return", ack_type)
    return OperationContract(key, payload_types, ack_type)
