"""Console UI helpers for the P2P chat client."""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime


RESET = "\033[0m"
SYSTEM_COLOR = "\033[90m"
COLOR_MAP = {
    "alice": "\033[92m",
    "bob": "\033[94m",
}
FALLBACK_COLORS = ("\033[96m", "\033[93m", "\033[95m", "\033[91m")


def format_message(sender: str, text: str, timestamp: str) -> str:
    """Format a chat line for terminal display."""

    return f"[{timestamp}] {sender}: {text}"


async def read_input(prompt: str) -> str:
    """Read a line of terminal input without blocking the event loop."""

    loop = asyncio.get_running_loop()
    sys.stdout.write(prompt)
    sys.stdout.flush()
    return await loop.run_in_executor(None, input, "")


class ConsoleUI:
    """Small terminal UI state wrapper for prompt-aware rendering."""

    def __init__(self, username: str) -> None:
        """Initialize prompt state for the current user."""

        self.username = username
        self.prompt = f"{username}> "

    def set_username(self, username: str) -> None:
        """Update the local username and prompt."""

        self.username = username
        self.prompt = f"{username}> "

    def render_message(self, sender: str, text: str, timestamp: str) -> str:
        """Render a colored chat message for display."""

        color = self._color_for_sender(sender)
        return f"{color}{format_message(sender, text, timestamp)}{RESET}"

    def print_message(self, sender: str, text: str, timestamp: str) -> None:
        """Print a chat message above the current input line."""

        self._print_above_prompt(self.render_message(sender, text, timestamp))

    def print_system(self, text: str) -> None:
        """Print a system message above the current input line."""

        self._print_above_prompt(f"{SYSTEM_COLOR}[system] {text}{RESET}")

    def current_timestamp(self) -> str:
        """Return the current local time formatted for chat output."""

        return datetime.now().strftime("%H:%M:%S")

    def _print_above_prompt(self, line: str) -> None:
        sys.stdout.write("\r\033[K")
        sys.stdout.write(f"{line}\n{self.prompt}")
        sys.stdout.flush()

    def _color_for_sender(self, sender: str) -> str:
        normalized = sender.lower()
        if normalized in COLOR_MAP:
            return COLOR_MAP[normalized]
        return FALLBACK_COLORS[sum(ord(char) for char in normalized) % len(FALLBACK_COLORS)]
