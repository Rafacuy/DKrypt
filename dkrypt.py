#!/usr/bin/env python3
"""
DKrypt - Advanced Penetration Testing Framework
Command-line entry point with proper error handling and logging
"""

import sys
from rich.console import Console
from dkrypt_main import main as typer_main
from core import version

console = Console()

__version__ = version.__version__
__status__ = version.__status__


def main():
    """
    Main entry point for DKrypt.
    Delegates to Typer-based implementation for improved CLI experience.
    """
    typer_main()


if __name__ == "__main__":
    main()
