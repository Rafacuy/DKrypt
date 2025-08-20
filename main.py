# main.py
# AUTHOR: Rafacuy

"""
This is a entry-point for the DKrypt.

DKrypt is a Python tool for all-in-one penetration testing with autonomous scripts, offering efficiency, accuracy, and speed. It's specifically designed for pentesting and web vulnerability detection.
"""


import asyncio
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.utils import clear_console, load_wordlist
from core.banner import display_header
from core.menu import show_menu
from core.randomizer import HeaderFactory
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from modules import subdomain, ssl_inspector, vulnerability, scraper, admin_finder, dir_bruteforcer, header_audit, port_scanner, waf_test

console = Console()

def main():
    wordlist = load_wordlist()
    
    while True:
        clear_console()
        
        display_header()
        choice = show_menu()

        if choice == '1':
            subdomain.main_menu()
        elif choice == '2':
            ssl_inspector.run_ssl_inspector()
        elif choice == '3':
            vulnerability.run_vulnerability_scan()
        elif choice == '4':
           header_audit.HeaderAuditor().run()
        elif choice == '5':
            try:
                asyncio.run(scraper.main_menu(HeaderFactory()))
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Program interrupted by user. Exiting.[/bold yellow]")         
        elif choice == '6':
            admin_finder.main()
        elif choice == '7':
            dir_bruteforcer.main()       
        elif choice == '8':
            try:
                asyncio.run(port_scanner.main_menu()) 
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Program interrupted by user. Exiting.[/bold yellow]") 
        elif choice == '9': 
            app = waf_test.WAFTUI()
            app.run()
        elif choice == '10':
            console.print("[bold red]\n  Exiting... \n[/bold red]")
            sys.exit(0)
        else:
            console.print("[bold red]  Invalid selection![/bold red]")

        console.input("\n[dim]Press Enter to return to main menu...[/dim]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation cancelled by user![/bold red]")
        sys.exit(1)
