import sys
import asyncio
from rich.console import Console
from core.menu import MenuSystem
from core.utils import clear_console
from core.banner import display_header

# Import modul
from modules import (
    subdomain, ssl_inspector,
    dir_bruteforcer, header_audit, port_scanner,
    cors_scan, sqli_scan, tracepulse, 
    jscrawler, py_obfuscator
)
from modules.crawler_engine import crawler_utils
from modules.waf_bypass import tui
from modules.http_desync import main_runner
from modules.xss import scanner

console = Console()

def run_tui():
    menu = MenuSystem()
    while True:
        clear_console()
        display_header()
        choice = menu.show_menu()

        if choice == 1:
            subdomain.main_menu()
        elif choice == 2:
            ssl_inspector.run_ssl_inspector()
        elif choice == 3:
            sqli_scan.run_sqli_scan()
        elif choice == 4:
            asyncio.run(scanner.run_xss_scan())
        elif choice == 5:
            header_audit.HeaderAuditor().run()
        elif choice == 6:
            asyncio.run(crawler_utils.main())
        elif choice == 7:
            dir_bruteforcer.main()
        elif choice == 8:
            asyncio.run(port_scanner.main_menu())
        elif choice == 9:
            app = tui.WAFTUI()
            app.run()
        elif choice == 10:
            cors_scan.main()
        elif choice == 11:
            main_runner.run()
        elif choice == 12:
            tracepulse.main()
        elif choice == 13:
            jscrawler.main()    
        elif choice == 14:
            py_obfuscator.main()
        elif choice == 15:
            console.print("[bold red]\n  Exiting... \n[/bold red]")
            sys.exit(0)
        else:
            console.print("[bold red]Invalid selection![/bold red]")

        console.input("\n[dim]Press Enter to return to main menu...[/dim]")

from core.cli import run_cli

def main():
    if len(sys.argv) > 1:
        run_cli()
    else:
        run_tui()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation cancelled by user![/bold red]")
        sys.exit(1)
