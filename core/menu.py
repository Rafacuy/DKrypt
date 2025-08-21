# core/menu.py
from rich.console import Console
from rich.text import Text
from rich.live import Live
from rich.panel import Panel
import time

console = Console()

def show_menu():
    menu_options = [
        ("1", "Subdomain Discovery", "Comprehensively scan target subdomains"),
        ("2", "SSL/TLS Inspector", "Analyze website security certificates"),
        ("3", "Web Vulnerability Scanner", "Detect common vulnerabilities in web applications"),
        ("4", "Security Header Audit", "Check HTTP security headers"),
        ("5", "Website Scraper", "Extract website content in a structured manner"),
        ("6", "Admin Page Finder", "Find hidden admin pages"),
        ("7", "Directory BruteForcer", "Search for hidden directories and files"),
        ("8", "Port Scanner", "Find a port within the website"),
        ("9", "WAF Bypass tester", "Find a vulnerabilites on the WAF's target website"),
        ("10","CORS Misconfig Auditor", "Find a vulnerabilites on the CORS configuration"),
        ("11", "Exit", "Exit the application")
    ]
    
    # Opening
    with console.status("[bold green]Preparing security tools...") as status:
        time.sleep(0.8)
    
    # header
    header_text = Text()
    header_text.append(" DKrypt ", style="bold #FF6B6B on #2D3047")
    header_text.stylize("gradient(45, #FF6B6B, #FFD166) bold", 0, 7)
    
    # Render menu with panel
    menu_content = Text("\n", justify="center")
    
    # app description
    menu_content.append("Integrated Security Toolkit\n", style="bold #118AB2")
    menu_content.append("Version 1.2.0 (STABLE) • © 2025 DKrypt Security\n\n", style="italic #6C757D")
    
    # Menu options
    for number, label, desc in menu_options:
        menu_content.append(f"{number}.  ", style="#EF476F")
        menu_content.append(f"{label}", style="bold #06D6A0")
        menu_content.append("\n")
        menu_content.append(f"   → {desc}", style="italic #ADB5BD")
        menu_content.append("\n\n")

    # footer
    footer = Text("Select option 1-11 • Confirm: ENTER", style="italic #6C757D", justify="center")
    
    # custom border
    console.print()
    console.print(Panel(
        menu_content,
        title=header_text,
        subtitle=footer,
        border_style="#118AB2",
        padding=(1, 8),
        width=80
    ))
    
    return console.input("\n[blink bold #EF476F]>>>[/blink bold #EF476F] Select option (1-10): ")

if __name__ == '__main__':
    show_menu()