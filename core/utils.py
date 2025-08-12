# core/utils.py
import os
import re
from rich.console import Console

console = Console()

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_wordlist(path='wordlists/subdomain.txt'):
    try:
        with open(path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        console.print(f"[bold red]⨯  Wordlist file '{path}' not found! Using default list.[/bold red]")
        return [
            'www', 'mail', 'ftp', 'admin', 'blog',
            'dev', 'test', 'api', 'secure', 'portal',
            'webmail', 'shop', 'app', 'cloud', 'm'
        ]
        
def sanitize_filename(name: str) -> str:
    """Removes characters that are invalid for filenames."""
    return re.sub(r'[^\w\-_.]', '_', name)[:100]        
