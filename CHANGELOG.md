# Change Log

All notable changes to Pydantic-SocketIO will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).



## [TODO]

### Added

- [ ] 支持注册的函数签名自动生成 JSON Schema 文档
  - 根据函数签名生成 ClientToServerEvents 文档
  - 要求用户手动 register_emit 注册事件名和参数类型 生成 ServerToClientEvents 文档，可以用装饰器对pydantic model class使用；Optional：运行时校验



## [0.1.2] - 2025-06-19

### Fixed

- Check fastapi installation to avoid module not found error.



## [0.1.1] - 2025-03-18

### Added

- `SioDep` as `FastAPISocketIO` dependency injection in FastAPI applications.



## [0.1.0] - 2025-03-16

### Added

Initial features:

- Pydantic enhanced socketio server and client (both sync and async). They should be drop-in replacements for the original socketio server and client.
- Alternatively, monkey patching method `monkey_patch()` for the original socketio server and client.
- Integration with fastapi `FastAPISocketIO`.
