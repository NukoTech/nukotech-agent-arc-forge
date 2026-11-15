"""Allow ``python -m nukotech_agent_arc`` (no console-script launcher needed)."""

from .cli import main

raise SystemExit(main())
