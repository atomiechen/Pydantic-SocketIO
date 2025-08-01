from typing import Protocol, Any, Union


class JsonModule(Protocol):
    def dumps(self, obj: Any, *args, **kwargs) -> str: ...
    def loads(self, s: Union[str, bytes, bytearray], *args, **kwargs) -> Any: ...
