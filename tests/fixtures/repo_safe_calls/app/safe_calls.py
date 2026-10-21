"""Invoke a program without a shell."""

import subprocess


def run_tool(tool: str, argument: str) -> str:
    """An argument array is passed straight to the program."""
    result = subprocess.run([tool, argument], capture_output=True, text=True)
    return result.stdout


def run_tool_explicit(tool: str, argument: str) -> str:
    """The shell is disabled explicitly."""
    result = subprocess.run([tool, argument], shell=False, capture_output=True, text=True)
    return result.stdout
