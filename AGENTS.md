# Repository guidance

Pydantic-SocketIO keeps Python/Pydantic as the source of truth for Socket.IO events. The Python runtime validates payloads and exports AsyncAPI; `packages/codegen/` turns that contract into types for the official TypeScript Socket.IO packages.

- Preserve Python 3.8+ and the public `python-socketio` compatible API.
- Python implementation is in `src/pydantic_socketio/`; contract tests are in `tests/`.
- Codegen and its Python↔TypeScript consumer tests are in `packages/codegen/`.
- Run `uv run --locked --no-sync bash scripts/lint.sh`, `uv run --locked --no-sync bash scripts/test.sh`, and `npm test --prefix packages/codegen` after relevant changes.
- The checked-in example contract and generated TypeScript file must be regenerated together; see `examples/fastapi-typescript-chat/README.md`.
- Preserve Socket.IO event direction, namespaces, payload argument order, and ACK shape when changing contract or codegen logic.
- Do not start `workflow_dispatch` release workflows. Publishing and version tags are owner decisions.
