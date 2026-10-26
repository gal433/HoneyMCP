"""Container entrypoint: one image, two apps.

APP=dashboard starts the private dashboard; anything else (or unset) starts the
honeypot. Set APP on the dashboard's Railway service only.
"""

from __future__ import annotations

import os

if __name__ == "__main__":
    if os.environ.get("APP", "").strip().lower() == "dashboard":
        from dashboard.app import main
    else:
        from honeypot.server import main
    main()
