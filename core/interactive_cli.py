#!/usr/bin/env python3

import argparse
import cmd
import sys
import asyncio
import os
import json
import sqlite3
import readline
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown
from .banner import display_header
from .parsers import create_parser
from .help import HelpSystem
from modules import (
    subdomain, ssl_inspector, dir_bruteforcer, header_audit, port_scanner,
    cors_scan, sqli_scan, tracepulse, jscrawler, py_obfuscator, graphql_introspect
)
from modules.crawler_engine import crawler_utils
from modules.waf_bypass import tui
from modules.http_desync import main_runner
from modules.xss import scanner

console = Console()

class WorkspaceManager:
    """Manage workspaces for organizing scan results"""
    def __init__(self, db_path=".dkrypt/workspaces.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS workspaces
                     (id INTEGER PRIMARY KEY, name TEXT UNIQUE, created TEXT, description TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS scan_results
                     (id INTEGER PRIMARY KEY, workspace_id INTEGER, module TEXT, 
                      target TEXT, timestamp TEXT, results TEXT)''')
        conn.commit()
        conn.close()
        
    def create_workspace(self, name, description=""):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO workspaces VALUES (NULL, ?, ?, ?)",
                     (name, datetime.now().isoformat(), description))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
            
    def list_workspaces(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM workspaces")
        workspaces = c.fetchall()
        conn.close()
        return workspaces
        
    def delete_workspace(self, name):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM workspaces WHERE name=?", (name,))
        conn.commit()
        conn.close()

class SessionManager:
    """Manage active sessions and targets"""
    def __init__(self):
        self.sessions = {}
        self.active_session = None
        
    def create_session(self, target, module):
        session_id = len(self.sessions) + 1
        self.sessions[session_id] = {
            'target': target,
            'module': module,
            'created': datetime.now().isoformat(),
            'status': 'active'
        }
        return session_id
        
    def list_sessions(self):
        return self.sessions
        
    def kill_session(self, session_id):
        if session_id in self.sessions:
            self.sessions[session_id]['status'] = 'killed'
            return True
        return False

class InteractiveCLI(cmd.Cmd):
    intro = ''
    prompt = '(dkrypt) '
    ruler = '-'

    def __init__(self):
        super().__init__()
        self.module = None
        self.options = {}
        self.workspace_manager = WorkspaceManager()
        self.session_manager = SessionManager()
        self.current_workspace = "default"
        self.history_file = os.path.expanduser("~/.dkrypt_history")
        self.resource_scripts = []
        self.help_system = HelpSystem()

        # Setup history
        self._setup_history()

        # Setup auto-completion
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")

        self.module_list = {
            'sqli': {
                'name': 'SQLI Scanner',
                'description': 'Detect SQL injection vulnerabilities in web applications',
                'category': 'scanner',
                'function': lambda args: sqli_scan.run_sqli_scan(**{k: v for k, v in vars(args).items() if k != 'command'}),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL to scan'},
                    'TEST_FORMS': {'required': False, 'description': 'Test POST forms', 'default': False},
                    'TEST_HEADERS': {'required': False, 'description': 'Test HTTP headers', 'default': False},
                    'EXPORT': {'required': False, 'description': 'Export format (html/csv/none)', 'default': 'html'}
                },
                'helper': 'Use this tool to detect SQL injection vulnerabilities. Set URL to target and optionally enable test forms/headers.'
            },
            'xss': {
                'name': 'XSS Scanner',
                'description': 'Detect Cross-Site Scripting vulnerabilities in web applications',
                'category': 'scanner',
                'function': lambda args: asyncio.run(scanner.run_xss_scan(**{k: v for k, v in vars(args).items() if k != 'command'})),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL to scan'},
                    'THREADS': {'required': False, 'description': 'Number of threads', 'default': 20},
                    'RATE_LIMIT': {'required': False, 'description': 'Requests per second', 'default': 5},
                    'SMART_MODE': {'required': False, 'description': 'Enable smart mode', 'default': False}
                },
                'helper': 'Scan for XSS vulnerabilities. Use URL parameter and adjust threads/rate for performance.'
            },
            'graphql': {
                'name': 'GraphQL Introspector',
                'description': 'Introspect queries from GraphQL endpoints',
                'category': 'scanner',
                'function': lambda args: graphql_introspect.run_cli(**{k: v for k, v in vars(args).items() if k != 'command'}),
                'options': {
                    'URL': {'required': True, 'description': 'GraphQL endpoint URL'},
                    'HEADERS': {'required': False, 'description': 'Custom headers (JSON)', 'default': '{}'},
                    'VERBOSE': {'required': False, 'description': 'Verbose output', 'default': False}
                },
                'helper': 'Analyze GraphQL endpoints for queries and mutations. Supply the GraphQL endpoint URL.'
            },
            'portscanner': {
                'name': 'Port Scanner',
                'description': 'Advanced Port Scanner (based on NMAP)',
                'category': 'recon',
                'function': lambda args: asyncio.run(port_scanner.main_menu(args)),
                'options': {
                    'TARGET': {'required': True, 'description': 'Target host to scan'},
                    'PORTS': {'required': False, 'description': 'Ports to scan', 'default': '1-1024'},
                    'SCAN_TYPE': {'required': False, 'description': 'Scan type (SYN/CON/UDP)', 'default': 'SYN'}
                },
                'helper': 'Scan target hosts for open ports and services. Specify target and ports range.'
            },
            'subdomain': {
                'name': 'Subdomain Scanner',
                'description': 'Discover target subdomains comprehensively',
                'category': 'recon',
                'function': lambda args: asyncio.run(subdomain.main_menu(args)),
                'options': {
                    'TARGET': {'required': True, 'description': 'Target domain'},
                    'RATE_LIMIT': {'required': False, 'description': 'DNS queries rate', 'default': 200},
                    'API_ONLY': {'required': False, 'description': 'Use only API sources', 'default': False}
                },
                'helper': 'Find subdomains of a target domain. Use API_ONLY for fast results or full scan for thoroughness.'
            },
            'crawler': {
                'name': 'Website Crawler',
                'description': 'Extract and analyze website content',
                'category': 'recon',
                'function': lambda args: asyncio.run(crawler_utils.main(args)),
                'options': {
                    'URL': {'required': True, 'description': 'Starting URL'},
                    'DEPTH': {'required': False, 'description': 'Crawl depth', 'default': 3},
                    'MAX_URLS': {'required': False, 'description': 'Maximum URLs', 'default': 100}
                },
                'helper': 'Crawl websites to find links and pages. Set URL and adjust depth/max URLs for scope.'
            },
            'headers': {
                'name': 'Security Header Audit',
                'description': 'Evaluate HTTP security headers',
                'category': 'audit',
                'function': lambda args: header_audit.HeaderAuditor().run(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL'},
                    'VERBOSE': {'required': False, 'description': 'Verbose output', 'default': False}
                },
                'helper': 'Check security headers of web applications. Requires target URL.'
            },
            'dirbrute': {
                'name': 'Directory Bruteforcer',
                'description': 'Search for hidden directories and files',
                'category': 'recon',
                'function': lambda args: dir_bruteforcer.main(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL'},
                    'WORDLIST': {'required': False, 'description': 'Wordlist path', 'default': 'wordlists/directory-brute.txt'},
                    'EXTENSIONS': {'required': False, 'description': 'File extensions', 'default': '.php,.html'},
                    'EXPORT': {'required': False, 'description': 'Export report to file', 'default': 'dir_reports.txt'}
                },
                'helper': 'Discover hidden directories and files. Set target URL and optionally specify wordlist/extensions.'
            },
            'sslinspect': {
                'name': 'SSL/TLS Inspector',
                'description': 'Analyze website security certificates',
                'category': 'audit',
                'function': lambda args: ssl_inspector.run_ssl_inspector(args),
                'options': {
                    'TARGET': {'required': True, 'description': 'Target host:port'},
                    'EXPORT': {'required': False, 'description': 'Export format (json/txt)', 'default': 'json'}
                },
                'helper': 'Analyze SSL/TLS certificates of target host. Requires host:port format.'
            },
            'corstest': {
                'name': 'CORS Misconfig Auditor',
                'description': 'Identify CORS configuration issues',
                'category': 'audit',
                'function': lambda args: cors_scan.main(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL'},
                    'EXPORT': {'required': False, 'description': 'Export format', 'default': 'json'}
                },
                'helper': 'Test for CORS misconfigurations. Provide target URL for testing.'
            },
            'smuggler': {
                'name': 'HTTP Desync Tester',
                'description': 'Test for HTTP request smuggling',
                'category': 'exploit',
                'function': lambda args: main_runner.run(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL'},
                    'PORT': {'required': False, 'description': 'Target port', 'default': 80}
                },
                'helper': 'Test for HTTP request smuggling vulnerabilities. Requires URL and optionally port.'
            },
            'tracepulse': {
                'name': 'Tracepulse',
                'description': 'Trace network routes and identify issues',
                'category': 'recon',
                'function': lambda args: tracepulse.main(args),
                'options': {
                    'DESTINATION': {'required': True, 'description': 'Target host/IP'},
                    'PROTOCOL': {'required': False, 'description': 'Protocol (icmp/tcp/udp)', 'default': 'icmp'}
                },
                'helper': 'Trace network routes to identify network issues. Specify destination and protocol.'
            },
            'js-crawler': {
                'name': 'JS Crawler',
                'description': 'Extract endpoints from JavaScript files',
                'category': 'recon',
                'function': lambda args: jscrawler.main(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL'},
                    'SELENIUM': {'required': False, 'description': 'Use Selenium', 'default': False}
                },
                'helper': 'Extract endpoints from JavaScript files. Target URL required.'
            },
            'py-obfuscator': {
                'name': 'Python Obfuscator',
                'description': 'Obfuscate Python code for protection',
                'category': 'utility',
                'function': lambda args: py_obfuscator.main(args),
                'options': {
                    'INPUT': {'required': True, 'description': 'Input Python file'},
                    'OUTPUT': {'required': False, 'description': 'Output file path'},
                    'LEVEL': {'required': False, 'description': 'Protection level (1-3)', 'default': 2}
                },
                'helper': 'Obfuscate Python code to protect it. Specify input/output files and protection level.'
            },
            'waftester': {
                'name': 'WAF Bypass Tester',
                'description': 'Test Web Application Firewall bypasses',
                'category': 'exploit',
                'function': lambda args: tui.WAFTUI().run(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL'},
                    'METHOD': {'required': False, 'description': 'HTTP method', 'default': 'GET'}
                },
                'helper': 'Test WAF bypass techniques. Requires target URL and optionally HTTP method.'
            }
        }

        # Initialize argparse parser
        self.argparse_parser = create_parser()
        
    def _setup_history(self):
        """Setup command history"""
        try:
            readline.read_history_file(self.history_file)
        except FileNotFoundError:
            pass
            
    def _save_history(self):
        """Save command history"""
        try:
            readline.write_history_file(self.history_file)
        except:
            pass

    # ============ MODULE COMMANDS ============
    
    def do_use(self, arg):
        if not arg:
            console.print("[red]Error: Module name required. Use 'show modules' to list available modules.[/red]")
            return
            
        module_name = arg.strip()
        
        if module_name in self.module_list:
            self.module = module_name
            self.prompt = f'(dkrypt:{module_name}) '
            console.print(f"[green]Using module: {self.module_list[module_name]['name']}[/green]")
        else:
            console.print(f"[red]Error: Module '{module_name}' not found. Use 'show modules' to list available modules.[/red]")
    
    def do_show(self, arg):
        """Show different types of information: show modules, show options"""
        if not arg or arg.strip() == 'modules':
            self._show_modules()
        elif arg.strip() == 'options':
            if self.module:
                self._show_module_options()
            else:
                console.print("[red]No module selected. Use 'use <module>' first.[/red]")
        else:
            console.print(f"[red]Unknown show option: {arg}. Available: modules, options[/red]")
    
    def _show_modules(self):
        """Display all available modules"""
        console.print("\n[bright_cyan]Available Modules[/bright_cyan]\n")
        table = Table(box=None, show_header=True, header_style="bold cyan")
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Category", style="magenta", justify="center")
        table.add_column("Description", style="green")

        for module_key, module_info in self.module_list.items():
            table.add_row(module_key, module_info['category'], module_info['description'])

        console.print(table)
        console.print("\n[dim]Use 'help <module>' or 'info <module>' for detailed information[/dim]")
    
    def _show_module_options(self):
        """Show options for the current module"""
        if not self.module:
            console.print("[red]No module selected.[/red]")
            return

        module_info = self.module_list[self.module]
        console.print(f"\n[bright_cyan]{module_info['name']} Options[/bright_cyan]")

        # Show currently set options
        if self.options:
            console.print("\n[bold]Current Configuration:[/bold]")
            table = Table(box=None)
            table.add_column("Option", style="cyan", no_wrap=True)
            table.add_column("Value", style="magenta")
            table.add_column("Status", style="green")

            for opt, val in self.options.items():
                status = "[green]SET[/green]" if val else "[red]NOT SET[/red]"
                table.add_row(opt, str(val), status)

            console.print(table)

        # Show available options from module definition
        if 'options' in module_info:
            console.print("\n[bold]Available Options:[/bold]")
            table = Table(box=None)
            table.add_column("Option", style="cyan", no_wrap=True)
            table.add_column("Required", style="magenta", justify="center")
            table.add_column("Default", style="yellow")
            table.add_column("Description", style="green")

            for opt_name, opt_info in module_info['options'].items():
                required = "[red]YES[/red]" if opt_info.get('required', False) else "[green]NO[/green]"
                default = str(opt_info.get('default', 'N/A'))
                description = opt_info.get('description', '')
                table.add_row(opt_name, required, default, description)

            console.print(table)

        if not self.options:
            console.print("\n[dim]Configure options using: set <OPTION> <value>[/dim]")
        else:
            console.print(f"\n[dim]Use 'run' to execute the module[/dim]")
    
    def do_set(self, arg):
        """Set an option: set URL http://example.com"""
        if not self.module:
            console.print("[red]No module selected. Use 'use <module>' first.[/red]")
            return
            
        args = arg.split(None, 1)
        if len(args) != 2:
            console.print("[red]Usage: set <option> <value>[/red]")
            return
            
        option, value = args
        self.options[option.upper()] = value
        console.print(f"[green]{option.upper()} => {value}[/green]")
    
    def do_unset(self, arg):
        """Unset an option: unset URL"""
        option = arg.strip().upper()
        if option in self.options:
            del self.options[option]
            console.print(f"[green]Unset {option}[/green]")
        else:
            console.print(f"[red]Option {option} not set.[/red]")
    
    def do_run(self, arg):
        """Run the selected module with current options"""
        if not self.module:
            console.print("[red]No module selected. Use 'use <module>' first.[/red]")
            return

        module_info = self.module_list[self.module]
        
        # 1. Start with all default options for the module
        final_options = {}
        for opt_name, opt_info in module_info.get('options', {}).items():
            if 'default' in opt_info:
                final_options[opt_name.lower()] = opt_info['default']

        # 2. Override defaults with user-set options
        for opt_name, opt_value in self.options.items():
            final_options[opt_name.lower()] = opt_value

        # 3. Add the command name itself
        final_options['command'] = self.module

        # 4. Check for missing required options
        missing_required = []
        for opt_name, opt_info in module_info.get('options', {}).items():
            if opt_info.get('required', False) and opt_name.lower() not in final_options:
                missing_required.append(opt_name)

        if missing_required:
            console.print(f"[red]Error: Missing required options: {', '.join(missing_required)}[/red]")
            console.print("[dim]Use 'show options' to see what's required.[/dim]")
            return

        try:
            console.print(f"\n[bold blue]Executing: {module_info['name']}[/bold blue]")
            console.print(f"[dim]Module: {self.module} | Effective options: {len(final_options)}[/dim]")

            # Create the args object from the complete set of options
            args_obj = argparse.Namespace(**final_options)
            
            # Call the module's function
            module_func = module_info['function']
            module_func(args_obj)

            console.print(f"\n[green]✓ Module {self.module} completed successfully.[/green]")

        except Exception as e:
            console.print(f"[red]✗ Error running {self.module}: {str(e)}[/red]")
            import traceback
            console.print(f"[dim]Error details: {traceback.format_exc()}[/dim]")
    
    def do_back(self, arg):
        """Go back from the current module context"""
        self.module = None
        self.options = {}
        self.prompt = '(dkrypt) '
        console.print("[green]Returned to main context.[/green]")
        
    def do_search(self, arg):
        """Search for modules by name or description: search sql"""
        if not arg:
            console.print("[red]Usage: search <term>[/red]")
            return
            
        term = arg.lower().strip()
        matches = []
        
        for module_key, module_info in self.module_list.items():
            if (term in module_key.lower() or 
                term in module_info['name'].lower() or 
                term in module_info['description'].lower()):
                matches.append((module_key, module_info))
        
        if matches:
            table = Table(title=f"Search results for '{term}'")
            table.add_column("Module", style="cyan", no_wrap=True)
            table.add_column("Name", style="magenta")
            table.add_column("Description", style="green")
            
            for module_key, module_info in matches:
                table.add_row(module_key, module_info['name'], module_info['description'])
            
            console.print(table)
        else:
            console.print(f"[yellow]No modules found matching '{term}'.[/yellow]")

    def _show_module_info(self, module_name):
        """Display detailed information about a specific module"""
        if module_name not in self.module_list:
            console.print(f"[red]Module '{module_name}' not found.[/red]")
            return

        module_info = self.module_list[module_name]

        # Display module information panel
        console.print(f"\n[bright_cyan]{module_info['name']}[/bright_cyan]")
        console.print(f"[bold]Description:[/bold] {module_info['description']}")
        console.print(f"[bold]Category:[/bold] {module_info['category']}")
        if 'helper' in module_info:
            console.print(f"[bold]Helper:[/bold] {module_info['helper']}")

        # Show options for the module
        console.print(f"\n[bold]Available Options:[/bold]")
        if 'options' in module_info:
            table = Table()
            table.add_column("Option", style="cyan", no_wrap=True)
            table.add_column("Required", style="magenta")
            table.add_column("Default", style="yellow")
            table.add_column("Description", style="green")

            for opt_name, opt_info in module_info['options'].items():
                required = "Yes" if opt_info.get('required', False) else "No"
                default = str(opt_info.get('default', 'N/A'))
                description = opt_info.get('description', '')
                table.add_row(opt_name, required, default, description)

            console.print(table)

        console.print(f"\n[dim]Usage: use {module_name} -> set required options -> run[/dim]")

    def do_info(self, arg):
        """Show information about current module or a specified module"""
        if not arg and not self.module:
            console.print("[red]No module selected. Use 'use <module>' first or 'info <module>' to see specific module info.[/red]")
            return
        elif not arg and self.module:
            self._show_module_info(self.module)
        elif arg and arg in self.module_list:
            self._show_module_info(arg)
        else:
            console.print(f"[red]Unknown module: {arg}. Use 'show modules' to see available modules.[/red]")

    def do_options(self, arg):
        """Alias for show options"""
        self.do_show('options')
    
    def do_help(self, arg):
        """Show help information"""
        if not arg:
            console.print("\n[bright_cyan]Welcome to DKrypt - Advanced Penetration Testing Framework[/bright_cyan]")
            console.print("\n[bright_yellow]Available Commands:[/bright_yellow]")
            console.print("  [cyan]use <module>[/cyan]      - Select a module to use")
            console.print("  [cyan]show modules[/cyan]      - List all available modules")
            console.print("  [cyan]show options[/cyan]      - Show current module options")
            console.print("  [cyan]set <option> <value>[/cyan] - Configure module option")
            console.print("  [cyan]unset <option>[/cyan]    - Clear a module option")
            console.print("  [cyan]run[/cyan]               - Execute the selected module")
            console.print("  [cyan]back[/cyan]              - Return from current module context")
            console.print("  [cyan]search <term>[/cyan]     - Find modules by name/description")
            console.print("  [cyan]info[/cyan]              - Show current module information")
            console.print("  [cyan]help <module>[/cyan]     - Show detailed info about a specific module")
            console.print("  [cyan]exit/quit/q[/cyan]       - Exit the application")
            console.print("\n[dim]Type 'help <module>' for specific module assistance.[/dim]")
        else:
            # Check if arg is a module name
            if arg in self.module_list:
                self._show_module_info(arg)
            else:
                super().do_help(arg)
    
    def do_exit(self, arg):
        """Exit the application"""
        console.print("[yellow]Goodbye![/yellow]")
        return True
    
    def do_quit(self, arg):
        """Exit the application"""
        return self.do_exit(arg)
    
    def do_q(self, arg):
        """Exit the application"""
        return self.do_exit(arg)
    
    def emptyline(self):
        """Do nothing on empty line"""
        pass
    
    def default(self, line):
        """Handle unknown commands"""
        cmd, *args = line.split()
        if cmd == 'EOF':
            return self.do_exit('')
        console.print(f"[red]Unknown command: {cmd}. Type 'help' for available commands.[/red]")


def run_interactive_cli():
    """Main function to run the interactive CLI"""
    display_header()
    console.print("\n[dim]Type 'help' for available commands or 'show modules' to get started.[/dim]")
    interactive_cli = InteractiveCLI()
    try:
        interactive_cli.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[yellow]Exiting...[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error in interactive CLI: {str(e)}[/red]")
        sys.exit(1)
