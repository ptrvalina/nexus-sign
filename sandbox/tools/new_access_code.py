#!/usr/bin/env python3
"""Prints a new access-code entry for SANDBOX_ACCESS_CODES.

    python3 tools/new_access_code.py acme-bank
    -> acme-bank:<random code>

Add the line to the comma-separated list in deploy/.env, restart the sandbox,
and send the code to the guest through a separate channel from the URL.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import access  # noqa: E402

if len(sys.argv) != 2 or not access.WORKSPACE_NAME.match(sys.argv[1]):
    sys.exit('usage: new_access_code.py <workspace-name>   (lowercase letters, digits, hyphens; 2-32 characters)')
print(f'{sys.argv[1]}:{access.generate_code()}')
