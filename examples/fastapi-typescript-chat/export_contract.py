"""Regenerate the checked-in AsyncAPI document from the Python registrations."""

import json
from pathlib import Path

from backend import sio


destination = Path(__file__).with_name("asyncapi.json")
document = sio.asyncapi(title="Chat example", version="1.0.0")
destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
