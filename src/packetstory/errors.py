"""Exceptions. The CLI maps these to exit codes."""

from __future__ import annotations


class PacketStoryError(Exception):
    """A problem the user can act on: unreadable file, not a capture, file too large."""
