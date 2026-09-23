"""``python -m asm_sensors.adapters.screenshot`` — the browser self-test (see selftest())."""

import asyncio
import json
import sys

from . import selftest

result = asyncio.run(selftest())
print(json.dumps(result, indent=2))
sys.exit(0 if result["ok"] else 1)
