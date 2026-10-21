"""Invoke a command through the shell."""

import subprocess


def run_command(command: str) -> None:
    """The command string reaches a shell, so it can carry shell syntax."""
    subprocess.run(command, shell=True, check=True)
