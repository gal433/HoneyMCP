"""The in-process emulated environment.

This package is the sandbox-by-construction core of the high-interaction
honeypot. Attacker input is interpreted here against a virtual filesystem, a
virtual shell, an in-process SQLite app DB, and a virtual internal network. None
of it touches a real process, a real file on the host, or a real network socket,
so there is nothing to escape to and our own secrets are simply not part of the
world.

Public entry point: `honeypot.world.engine.ENGINE`.
"""
