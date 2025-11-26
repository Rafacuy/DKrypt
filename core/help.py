#!/usr/bin/env python3
"""
DKrypt Help System and Documentation Generator
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from .module_registry import ModuleRegistry


class HelpSystem:
    """Comprehensive help system for DKrypt"""
    
    def __init__(self):
        self.console = Console()
        self.modules = ModuleRegistry.get_modules()
    
    def show_main_help(self):
        """Show main help screen"""
        help_text = """
[bold cyan]DKrypt - Advanced Penetration Testing Framework[/bold cyan]

[bold]USAGE:[/bold]
  python dkrypt.py [OPTIONS] MODULE [MODULE_OPTIONS]
  python dkrypt.py --interactive  # Interactive mode
  python dkrypt.py --help         # Show this help

[bold]COMMON TASKS:[/bold]
  [cyan]Scan for SQL injection:[/cyan]
    python dkrypt.py sqli --url https://example.com

  [cyan]Check security headers:[/cyan]
    python dkrypt.py headers single --url https://example.com

  [cyan]Enumerate subdomains:[/cyan]
    python dkrypt.py subdomain single --target example.com

  [cyan]Run interactive CLI:[/cyan]
    python dkrypt.py -i

[bold]AVAILABLE MODULES:[/bold]
"""
        self.console.print(help_text)
        
        # Show modules table
        table = Table(title="Modules", show_header=True)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Category", style="magenta")
        table.add_column("Description", style="green")
        
        for module_key, module_info in self.modules.items():
            table.add_row(
                module_key,
                module_info.get("category", "unknown"),
                module_info.get("description", "")
            )
        
        self.console.print(table)
        
        help_footer = """
[bold]GET HELP:[/bold]
  python dkrypt.py MODULE --help       # Show module-specific help
  python dkrypt.py --diagnostic        # Run system diagnostics
  python dkrypt.py --list-modules      # List all available modules

[bold]DOCUMENTATION:[/bold]
  CLI Guide:   See CLI-guide.md
  Contributor: See CONTRIBUTOR.md
  
[bold]EXAMPLES:[/bold]
  python dkrypt.py subdomain single --target google.com --api-only
  python dkrypt.py portscanner single --target 192.168.1.1 --ports 1-1000
  python dkrypt.py crawler single --url https://example.com --depth 2
"""
        self.console.print(help_footer)
    
    def show_module_help(self, module_key: str):
        """Show detailed help for a specific module"""
        if module_key not in self.modules:
            self.console.print(f"[red]Unknown module: {module_key}[/red]")
            return
        
        module = self.modules[module_key]
        
        help_text = f"""
[bold cyan]{module['name']}[/bold cyan]

[bold]Description:[/bold]
  {module.get('description', 'No description available')}

[bold]Category:[/bold]
  {module.get('category', 'unknown')}

[bold]Author:[/bold]
  {module.get('author', 'Unknown')}
"""
        self.console.print(help_text)
        
        # Show options
        if 'options' in module:
            self.console.print("[bold]Options:[/bold]")
            table = Table()
            table.add_column("Option", style="cyan")
            table.add_column("Required", style="magenta")
            table.add_column("Type", style="yellow")
            table.add_column("Description", style="green")
            
            for opt_name, opt_info in module['options'].items():
                required = "Yes" if opt_info.get('required', False) else "No"
                opt_type = opt_info.get('type', 'string')
                description = opt_info.get('description', '')
                table.add_row(opt_name, required, opt_type, description)
            
            self.console.print(table)
    
    def list_all_modules(self):
        """List all available modules with categorization"""
        categories = {}
        
        for module_key, module_info in self.modules.items():
            category = module_info.get('category', 'other')
            if category not in categories:
                categories[category] = []
            categories[category].append((module_key, module_info))
        
        self.console.print("[bold cyan]DKrypt Modules by Category[/bold cyan]\n")
        
        for category in sorted(categories.keys()):
            self.console.print(f"[bold magenta]{category.upper()}[/bold magenta]")
            for module_key, module_info in categories[category]:
                self.console.print(f"  [cyan]{module_key:15}[/cyan] - {module_info.get('description', '')}")
            self.console.print()
    
    def show_quick_start(self):
        """Show quick start guide"""
        quick_start = """
[bold cyan]DKrypt Quick Start Guide[/bold cyan]

[bold yellow]Step 1: Choose Your Mode[/bold yellow]

  [bold]Interactive Mode[/bold] - Recommended for beginners
    $ python dkrypt.py -i
    
    Then use commands:
      [cyan]use sqli[/cyan]
      [cyan]set URL https://example.com[/cyan]
      [cyan]run[/cyan]

  [bold]CLI Mode[/bold] - For scripting and automation
    $ python dkrypt.py sqli --url https://example.com

[bold yellow]Step 2: Common Scanning Tasks[/bold yellow]

  [cyan]Web Application Testing:[/cyan]
    - SQLi Scanning: [dim]python dkrypt.py sqli --url <target>[/dim]
    - XSS Scanning:  [dim]python dkrypt.py xss --url <target>[/dim]
    - CORS Testing:  [dim]python dkrypt.py corstest --url <target>[/dim]

  [cyan]Reconnaissance:[/cyan]
    - Subdomain Enum:   [dim]python dkrypt.py subdomain single --target <domain>[/dim]
    - Port Scanning:    [dim]python dkrypt.py portscanner single --target <host>[/dim]
    - SSL/TLS Analysis: [dim]python dkrypt.py sslinspect --target <host:port>[/dim]

  [cyan]Content Discovery:[/cyan]
    - Directory Brute:  [dim]python dkrypt.py dirbrute --url <target>[/dim]
    - Web Crawling:     [dim]python dkrypt.py crawler single --url <target>[/dim]
    - JS Extraction:    [dim]python dkrypt.py js-crawler --url <target>[/dim]

[bold yellow]Step 3: Get Help[/bold yellow]

  [cyan]Module help:[/cyan]
    $ python dkrypt.py <module> --help
    
  [cyan]System diagnostics:[/cyan]
    $ python dkrypt.py --diagnostic

[bold yellow]Step 4: Check Results[/bold yellow]

  Results are saved in [cyan].dkrypt/outputs/[/cyan]
  Logs are saved in [cyan].dkrypt/logs/[/cyan]
"""
        self.console.print(quick_start)
    
    def show_tips(self):
        """Show useful tips and tricks"""
        tips = """
[bold cyan]DKrypt Tips & Tricks[/bold cyan]

[bold yellow]Performance Tips:[/bold yellow]
  • Use [cyan]--rate-limit[/cyan] to avoid detection
  • Increase [cyan]--threads[/cyan] for faster scans (be careful!)
  • Use [cyan]--batch[/cyan] mode for multiple targets

[bold yellow]Stealth Tips:[/bold yellow]
  • Enable [cyan]--stealth-mode[/cyan] for XSS scanner
  • Use [cyan]--jitter[/cyan] to randomize request timing
  • Rotate user agents with [cyan]--rotate-headers[/cyan]

[bold yellow]Output Tips:[/bold yellow]
  • Export to JSON: [cyan]--export json[/cyan]
  • Export to CSV:  [cyan]--export csv[/cyan]
  • Save to file:   [cyan]--output result.json[/cyan]

[bold yellow]Scripting Tips:[/bold yellow]
  • Use [cyan]-q[/cyan] or [cyan]--quiet[/cyan] for minimal output
  • Parse JSON output for automation
  • Chain commands with shell scripts

[bold yellow]Troubleshooting:[/bold yellow]
  • Check logs: [cyan].dkrypt/logs/[/cyan]
  • Run diagnostics: [cyan]python dkrypt.py --diagnostic[/cyan]
  • Enable verbose mode: [cyan]--verbose[/cyan]
"""
        self.console.print(tips)


def show_help(topic: str = None, module: str = None):
    """Main help dispatcher"""
    helper = HelpSystem()
    
    if topic == "quick-start":
        helper.show_quick_start()
    elif topic == "tips":
        helper.show_tips()
    elif topic == "modules":
        helper.list_all_modules()
    elif module:
        helper.show_module_help(module)
    else:
        helper.show_main_help()
