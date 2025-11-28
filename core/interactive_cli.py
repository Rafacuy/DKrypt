#!/usr/bin/env python3

import argparse
import cmd
import sys
import asyncio
import os
import json
import sqlite3
import readline
import time
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
from .command_engine import CommandParser, CommandHistory, CommandValidator, CommandSuggester
from .ui_components import OutputFormatter, ProgressTracker, StatusIndicator, InteractivePrompt, ContextMenu
from .result_manager import ResultManager, WorkflowEngine, ThreatIntelligence
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
        
        self.ui_formatter = OutputFormatter(console)
        self.progress_tracker = ProgressTracker(console)
        self.interactive_prompt = InteractivePrompt(console)
        self.context_menu = ContextMenu(console)

        self._setup_history()

        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")

        self.module_list = {
            'sqli': {
                'name': 'SQLI Scanner',
                'description': 'Detect SQL injection vulnerabilities in web applications',
                'category': 'scanner',
                'function': lambda args: sqli_scan.run_sqli_scan(**{k: v for k, v in vars(args).items() if k != 'command'}),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL to scan', 'validator': 'validate_url'},
                    'TEST_FORMS': {'required': False, 'description': 'Test POST forms', 'default': False, 'validator': 'validate_boolean'},
                    'TEST_HEADERS': {'required': False, 'description': 'Test HTTP headers', 'default': False, 'validator': 'validate_boolean'},
                    'EXPORT': {'required': False, 'description': 'Export format (html/csv/none)', 'default': 'html', 'validator': 'validate_choice', 'choices': ['html', 'csv', 'none']}
                },
                'helper': 'Use this tool to detect SQL injection vulnerabilities. Set URL to target and optionally enable test forms/headers.'
            },
            'xss': {
                'name': 'XSS Scanner',
                'description': 'Detect Cross-Site Scripting vulnerabilities in web applications',
                'category': 'scanner',
                'function': lambda args: asyncio.run(scanner.run_xss_scan(**{k: v for k, v in vars(args).items() if k != 'command'})),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL to scan', 'validator': 'validate_url'},
                    'THREADS': {'required': False, 'description': 'Number of threads', 'default': 20, 'validator': 'validate_integer'},
                    'RATE_LIMIT': {'required': False, 'description': 'Requests per second', 'default': 5, 'validator': 'validate_integer'},
                    'SMART_MODE': {'required': False, 'description': 'Enable smart mode', 'default': False, 'validator': 'validate_boolean'}
                },
                'helper': 'Scan for XSS vulnerabilities. Use URL parameter and adjust threads/rate for performance.'
            },
            'graphql': {
                'name': 'GraphQL Introspector',
                'description': 'Introspect queries from GraphQL endpoints',
                'category': 'scanner',
                'function': lambda args: graphql_introspect.run_cli(**{k: v for k, v in vars(args).items() if k != 'command'}),
                'options': {
                    'URL': {'required': True, 'description': 'GraphQL endpoint URL', 'validator': 'validate_url'},
                    'HEADERS': {'required': False, 'description': 'Custom headers (JSON)', 'default': '{}'},
                    'VERBOSE': {'required': False, 'description': 'Verbose output', 'default': False, 'validator': 'validate_boolean'}
                },
                'helper': 'Analyze GraphQL endpoints for queries and mutations. Supply the GraphQL endpoint URL.'
            },
            'portscanner': {
                'name': 'Port Scanner',
                'description': 'Advanced Port Scanner (based on NMAP)',
                'category': 'recon',
                'function': lambda args: asyncio.run(port_scanner.main_menu(args)),
                'options': {
                    'TARGET': {'required': True, 'description': 'Target host to scan', 'validator': 'validate_host'},
                    'PORTS': {'required': False, 'description': 'Ports to scan', 'default': '1-1024'},
                    'SCAN_TYPE': {'required': False, 'description': 'Scan type (SYN/CON/UDP)', 'default': 'SYN', 'validator': 'validate_choice', 'choices': ['SYN', 'CON', 'UDP']}
                },
                'helper': 'Scan target hosts for open ports and services. Specify target and ports range.'
            },
            'subdomain': {
                'name': 'Subdomain Scanner',
                'description': 'Discover target subdomains comprehensively',
                'category': 'recon',
                'function': lambda args: asyncio.run(subdomain.main_menu(args)),
                'options': {
                    'TARGET': {'required': True, 'description': 'Target domain', 'validator': 'validate_domain'},
                    'RATE_LIMIT': {'required': False, 'description': 'DNS queries rate', 'default': 200, 'validator': 'validate_integer'},
                    'API_ONLY': {'required': False, 'description': 'Use only API sources', 'default': False, 'validator': 'validate_boolean'}
                },
                'helper': 'Find subdomains of a target domain. Use API_ONLY for fast results or full scan for thoroughness.'
            },
            'crawler': {
                'name': 'Website Crawler',
                'description': 'Extract and analyze website content',
                'category': 'recon',
                'function': lambda args: asyncio.run(crawler_utils.main(args)),
                'options': {
                    'URL': {'required': True, 'description': 'Starting URL', 'validator': 'validate_url'},
                    'DEPTH': {'required': False, 'description': 'Crawl depth', 'default': 3, 'validator': 'validate_integer'},
                    'MAX_URLS': {'required': False, 'description': 'Maximum URLs', 'default': 100, 'validator': 'validate_integer'}
                },
                'helper': 'Crawl websites to find links and pages. Set URL and adjust depth/max URLs for scope.'
            },
            'headers': {
                'name': 'Security Header Audit',
                'description': 'Evaluate HTTP security headers',
                'category': 'audit',
                'function': lambda args: header_audit.HeaderAuditor().run(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'validator': 'validate_url'},
                    'VERBOSE': {'required': False, 'description': 'Verbose output', 'default': False, 'validator': 'validate_boolean'}
                },
                'helper': 'Check security headers of web applications. Requires target URL.'
            },
            'dirbrute': {
                'name': 'Directory Bruteforcer',
                'description': 'Search for hidden directories and files',
                'category': 'recon',
                'function': lambda args: dir_bruteforcer.main(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'validator': 'validate_url'},
                    'WORDLIST': {'required': False, 'description': 'Wordlist path', 'default': 'wordlists/directory-brute.txt', 'validator': 'validate_file_path'},
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
                    'TARGET': {'required': True, 'description': 'Target host:port', 'validator': 'validate_host'},
                    'EXPORT': {'required': False, 'description': 'Export format (json/txt)', 'default': 'json', 'validator': 'validate_choice', 'choices': ['json', 'txt']}
                },
                'helper': 'Analyze SSL/TLS certificates of target host. Requires host:port format.'
            },
            'corstest': {
                'name': 'CORS Misconfig Auditor',
                'description': 'Identify CORS configuration issues',
                'category': 'audit',
                'function': lambda args: cors_scan.main(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'validator': 'validate_url'},
                    'EXPORT': {'required': False, 'description': 'Export format', 'default': 'json', 'validator': 'validate_choice', 'choices': ['json', 'html', 'csv']}
                },
                'helper': 'Test for CORS misconfigurations. Provide target URL for testing.'
            },
            'smuggler': {
                'name': 'HTTP Desync Tester',
                'description': 'Test for HTTP request smuggling',
                'category': 'exploit',
                'function': lambda args: main_runner.run(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'validator': 'validate_url'},
                    'PORT': {'required': False, 'description': 'Target port', 'default': 80, 'validator': 'validate_port'}
                },
                'helper': 'Test for HTTP request smuggling vulnerabilities. Requires URL and optionally port.'
            },
            'tracepulse': {
                'name': 'Tracepulse',
                'description': 'Trace network routes and identify issues',
                'category': 'recon',
                'function': lambda args: tracepulse.main(args),
                'options': {
                    'DESTINATION': {'required': True, 'description': 'Target host/IP', 'validator': 'validate_host'},
                    'PROTOCOL': {'required': False, 'description': 'Protocol (icmp/tcp/udp)', 'default': 'icmp', 'validator': 'validate_choice', 'choices': ['icmp', 'tcp', 'udp']}
                },
                'helper': 'Trace network routes to identify network issues. Specify destination and protocol.'
            },
            'js-crawler': {
                'name': 'JS Crawler',
                'description': 'Extract endpoints from JavaScript files',
                'category': 'recon',
                'function': lambda args: jscrawler.main(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'validator': 'validate_url'},
                    'SELENIUM': {'required': False, 'description': 'Use Selenium', 'default': False, 'validator': 'validate_boolean'}
                },
                'helper': 'Extract endpoints from JavaScript files. Target URL required.'
            },
            'py-obfuscator': {
                'name': 'Python Obfuscator',
                'description': 'Obfuscate Python code for protection',
                'category': 'utility',
                'function': lambda args: py_obfuscator.main(args),
                'options': {
                    'INPUT': {'required': True, 'description': 'Input Python file', 'validator': 'validate_file_path'},
                    'OUTPUT': {'required': False, 'description': 'Output file path'},
                    'LEVEL': {'required': False, 'description': 'Protection level (1-3)', 'default': 2, 'validator': 'validate_integer', 'min_val': 1, 'max_val': 3}
                },
                'helper': 'Obfuscate Python code to protect it. Specify input/output files and protection level.'
            },
            'waftester': {
                'name': 'WAF Bypass Tester',
                'description': 'Test Web Application Firewall bypasses',
                'category': 'exploit',
                'function': lambda args: tui.WAFTUI().run(args),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'validator': 'validate_url'},
                    'METHOD': {'required': False, 'description': 'HTTP method', 'default': 'GET', 'validator': 'validate_choice', 'choices': ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']}
                },
                'helper': 'Test WAF bypass techniques. Requires target URL and optionally HTTP method.'
            }
        }

        self.command_parser = CommandParser(self.module_list)
        self.command_history = self.command_parser.history
        self.result_manager = ResultManager()
        self.workflow_engine = WorkflowEngine(self.result_manager)
        self.threat_intelligence = ThreatIntelligence(self.result_manager)
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
            self.ui_formatter.print_status("warning", "Module name required. Use 'show modules' to list available modules.")
            return
            
        module_name = arg.strip().lower()
        
        if module_name in self.module_list:
            self.module = module_name
            self.prompt = f'(dkrypt:{module_name}) '
            self.ui_formatter.print_status("success", f"Using module: {self.module_list[module_name]['name']}")
            self.command_history.add_entry(module_name, {"action": "use"})
        else:
            suggestions = self.command_parser.suggester.suggest_module(module_name)
            self.ui_formatter.print_status("error", f"Module '{module_name}' not found.")
            if suggestions:
                self.ui_formatter.print_suggestion_box("Did you mean?", suggestions)
    
    def do_show(self, arg):
        if not arg or arg.strip() == 'modules':
            self._show_modules()
        elif arg.strip() == 'options':
            if self.module:
                self._show_module_options()
            else:
                self.ui_formatter.print_status("warning", "No module selected. Use 'use <module>' first.")
        else:
            self.ui_formatter.print_status("error", f"Unknown show option: {arg}. Available: modules, options")
    
    def _show_modules(self):
        self.ui_formatter.print_module_list(self.module_list)
        console.print("\n[dim]Use 'help <module>' or 'info <module>' for detailed information[/dim]")
    
    def _show_module_options(self):
        if not self.module:
            self.ui_formatter.print_status("error", "No module selected.")
            return

        module_info = self.module_list[self.module]
        self.ui_formatter.print_module_header(module_info['name'], module_info['description'])

        if self.options:
            console.print("[bold]Current Configuration:[/bold]")
            self.ui_formatter.print_config_table(self.options)

        if 'options' in module_info:
            console.print("\n[bold]Available Options:[/bold]")
            self.ui_formatter.print_options_table(module_info['options'])

        if not self.options:
            console.print("\n[dim]Configure options using: set <OPTION> <value>[/dim]")
        else:
            console.print(f"\n[dim]Use 'run' to execute the module[/dim]")
    
    def do_set(self, arg):
        if not self.module:
            self.ui_formatter.print_status("warning", "No module selected. Use 'use <module>' first.")
            return
            
        args = arg.split(None, 1)
        if len(args) != 2:
            self.ui_formatter.print_status("error", "Usage: set <option> <value>")
            return
            
        option, value = args
        option_upper = option.upper()
        
        is_valid, errors, suggestions = self.command_parser.validate_and_get_suggestions(
            self.module, 
            {option_upper: value}
        )
        
        if errors:
            self.ui_formatter.print_error_with_suggestions(f"Invalid value for {option_upper}", errors)
        else:
            self.options[option_upper] = value
            self.ui_formatter.print_status("success", f"{option_upper} => {value}")
    
    def do_unset(self, arg):
        """Unset an option: unset URL"""
        option = arg.strip().upper()
        if option in self.options:
            del self.options[option]
            console.print(f"[green]Unset {option}[/green]")
        else:
            console.print(f"[red]Option {option} not set.[/red]")
    
    def do_run(self, arg):
        if not self.module:
            self.ui_formatter.print_status("warning", "No module selected. Use 'use <module>' first.")
            return

        module_info = self.module_list[self.module]
        
        final_options = {}
        for opt_name, opt_info in module_info.get('options', {}).items():
            if 'default' in opt_info:
                final_options[opt_name.lower()] = opt_info['default']

        for opt_name, opt_value in self.options.items():
            final_options[opt_name.lower()] = opt_value

        final_options['command'] = self.module

        missing_required = []
        for opt_name, opt_info in module_info.get('options', {}).items():
            if opt_info.get('required', False) and opt_name.lower() not in final_options:
                missing_required.append(opt_name)

        if missing_required:
            self.ui_formatter.print_error_with_suggestions(
                f"Missing required options: {', '.join(missing_required)}", 
                [f"Set {opt} to proceed" for opt in missing_required]
            )
            return

        try:
            start_time = time.time()
            self.ui_formatter.print_module_header(module_info['name'])
            console.print(f"[dim]Module: {self.module} | Options: {len(final_options)}[/dim]\n")

            args_obj = argparse.Namespace(**final_options)
            module_func = module_info['function']
            module_func(args_obj)

            elapsed = time.time() - start_time
            self.ui_formatter.print_status("success", f"Module {self.module} completed in {elapsed:.2f}s")
            self.command_history.update_status(self.module, "success", "Execution completed", elapsed)

        except Exception as e:
            elapsed = time.time() - start_time
            self.ui_formatter.print_status("error", f"Error in {self.module}: {str(e)}")
            self.command_history.update_status(self.module, "error", str(e), elapsed)
    
    def do_back(self, arg):
        self.module = None
        self.options = {}
        self.prompt = '(dkrypt) '
        self.ui_formatter.print_status("success", "Returned to main context.")
        
    def do_history(self, arg):
        recent = self.command_history.get_recent(10)
        if not recent:
            self.ui_formatter.print_status("info", "No command history available.")
        else:
            self.ui_formatter.print_command_history(recent)
    
    def do_shortcut(self, arg):
        parts = arg.split(None, 2)
        if not parts:
            self.ui_formatter.print_status("error", "Usage: shortcut <create|list|run> [args]")
            return
        
        action = parts[0].lower()
        
        if action == "create" and len(parts) >= 3:
            name, rest = parts[1], " ".join(parts[2:])
            if self.module:
                self.command_history.add_shortcut(name, self.module, self.options.copy())
                self.ui_formatter.print_status("success", f"Shortcut '{name}' created")
            else:
                self.ui_formatter.print_status("warning", "No module selected")
        
        elif action == "list":
            if self.command_history.shortcuts:
                table = Table(title="Saved Shortcuts")
                table.add_column("Name", style="cyan")
                table.add_column("Module", style="magenta")
                for name, data in self.command_history.shortcuts.items():
                    table.add_row(name, data["module"])
                console.print(table)
            else:
                self.ui_formatter.print_status("info", "No shortcuts saved")
        
        elif action == "run" and len(parts) >= 2:
            shortcut_name = parts[1]
            shortcut = self.command_history.get_shortcut(shortcut_name)
            if shortcut:
                self.module = shortcut["module"]
                self.options = shortcut["options"].copy()
                self.do_run("")
            else:
                self.ui_formatter.print_status("error", f"Shortcut '{shortcut_name}' not found")
    
    def do_results(self, arg):
        parts = arg.split() if arg else []
        action = parts[0].lower() if parts else "list"
        
        if action == "list":
            recent = self.result_manager.get_recent_results(limit=10)
            if recent:
                self.ui_formatter.print_command_history(recent)
            else:
                self.ui_formatter.print_status("info", "No results available")
        
        elif action == "show" and len(parts) >= 2:
            target = parts[1]
            correlation = self.result_manager.correlate_results(target)
            
            table = Table(title=f"Scan History for {target}")
            table.add_column("Module", style="cyan")
            table.add_column("Findings", style="yellow", justify="right")
            table.add_column("Time", style="green")
            
            for entry in correlation['timeline']:
                table.add_row(entry['module'], str(entry['findings']), entry['time'][:10])
            
            console.print(table)
            console.print(f"\n[bold]Total: {correlation['total_findings']} findings across {correlation['total_scans']} scans[/bold]")
        
        elif action == "analyze":
            patterns = self.threat_intelligence.analyze_patterns()
            
            if patterns.get("status") == "no_data":
                self.ui_formatter.print_status("info", "No scan data available for analysis")
            else:
                console.print("\n[bold cyan]Threat Intelligence Analysis[/bold cyan]\n")
                
                table = Table(show_header=True, header_style="bold cyan")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="magenta")
                
                table.add_row("Most Used Module", patterns['most_common_module'])
                table.add_row("Avg Findings/Scan", f"{patterns['average_findings_per_scan']:.2f}")
                table.add_row("Risk Score", f"{patterns['risk_score']}/100")
                
                console.print(table)
                
                if patterns['critical_targets']:
                    console.print("\n[bold]Critical Targets:[/bold]")
                    for target in patterns['critical_targets']:
                        console.print(f"  [red]●[/red] {target}")
                
                console.print("\n[bold]Module Effectiveness:[/bold]")
                eff_table = Table(show_header=False)
                for module, effectiveness in patterns['module_effectiveness'].items():
                    eff_table.add_row(f"  {module}", f"{effectiveness:.1f}%")
                console.print(eff_table)
    
    def do_dashboard(self, arg):
        console.print("\n[bold cyan]DKrypt Dashboard[/bold cyan]\n")
        
        recent_results = self.result_manager.get_recent_results(limit=5)
        patterns = self.threat_intelligence.analyze_patterns()
        
        summary_table = Table(title="Summary", show_header=False)
        summary_table.add_row("Total Scans", str(len(self.result_manager.results)))
        summary_table.add_row("Recent Findings", str(sum(r.findings_count for r in recent_results)) if recent_results else "0")
        summary_table.add_row("Risk Score", f"{patterns.get('risk_score', 0)}/100")
        summary_table.add_row("Modules Used", str(len(patterns.get('module_effectiveness', {}))))
        console.print(summary_table)
        
        if recent_results:
            console.print("\n[bold]Recent Activity[/bold]")
            self.ui_formatter.print_command_history(recent_results)
        
        if patterns.get('critical_targets'):
            console.print("\n[bold red]Critical Targets Detected[/bold red]")
            for target in patterns['critical_targets']:
                console.print(f"  [red]⚠[/red] {target}")
    
    def do_export(self, arg):
        parts = arg.split()
        if not parts or len(parts) < 2:
            self.ui_formatter.print_status("error", "Usage: export <target> <format: json|html|txt>")
            return
        
        target = parts[0]
        format_type = parts[1].lower()
        
        if format_type not in ['json', 'html', 'txt']:
            self.ui_formatter.print_status("error", "Format must be: json, html, or txt")
            return
        
        report = self.result_manager.export_report(target, format_type)
        
        filename = f".dkrypt/reports/{target}_report.{format_type}"
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        
        with open(filename, 'w') as f:
            f.write(report)
        
        self.ui_formatter.print_status("success", f"Report exported to {filename}")
    
    def do_workspace(self, arg):
        parts = arg.split() if arg else []
        action = parts[0].lower() if parts else "list"
        
        if action == "list":
            workspaces = self.workspace_manager.list_workspaces()
            if workspaces:
                table = Table(title="Workspaces")
                table.add_column("Name", style="cyan")
                table.add_column("Created", style="yellow")
                for ws_id, name, created, desc in workspaces:
                    table.add_row(name, created[:10])
                console.print(table)
            else:
                self.ui_formatter.print_status("info", "No workspaces available")
        
        elif action == "create" and len(parts) >= 2:
            ws_name = parts[1]
            if self.workspace_manager.create_workspace(ws_name):
                self.current_workspace = ws_name
                self.prompt = f'(dkrypt:{ws_name}) '
                self.ui_formatter.print_status("success", f"Workspace '{ws_name}' created")
            else:
                self.ui_formatter.print_status("error", f"Workspace '{ws_name}' already exists")
        
        elif action == "switch" and len(parts) >= 2:
            ws_name = parts[1]
            self.current_workspace = ws_name
            self.prompt = f'(dkrypt:{ws_name}) '
            self.ui_formatter.print_status("success", f"Switched to workspace '{ws_name}'")
    
    def do_workflow(self, arg):
        parts = arg.split(None, 1)
        if not parts:
            self.ui_formatter.print_status("error", "Usage: workflow <create|list|run|delete> [args]")
            return
        
        action = parts[0].lower()
        
        if action == "list":
            workflows = self.workflow_engine.list_workflows()
            if workflows:
                console.print("\n[bold cyan]Available Workflows[/bold cyan]")
                for wf in workflows:
                    console.print(f"  [cyan]→[/cyan] {wf}")
            else:
                self.ui_formatter.print_status("info", "No workflows defined")
        
        elif action == "create" and len(parts) > 1:
            self.ui_formatter.print_status("info", "Workflow creation requires manual JSON editing in .dkrypt/workflows.json")
        
        elif action == "run" and len(parts) > 1:
            wf_name = parts[1].strip()
            workflow = self.workflow_engine.get_workflow(wf_name)
            if workflow:
                self.ui_formatter.print_status("success", f"Running workflow: {wf_name}")
                for i, step in enumerate(workflow, 1):
                    console.print(f"\n[dim]Step {i}/{len(workflow)}[/dim]")
                    if isinstance(step, dict) and 'module' in step:
                        self.module = step['module']
                        self.options = step.get('options', {})
                        self.do_run("")
            else:
                self.ui_formatter.print_status("error", f"Workflow '{wf_name}' not found")
        
        elif action == "delete" and len(parts) > 1:
            wf_name = parts[1].strip()
            if self.workflow_engine.delete_workflow(wf_name):
                self.ui_formatter.print_status("success", f"Workflow '{wf_name}' deleted")
            else:
                self.ui_formatter.print_status("error", f"Workflow '{wf_name}' not found")
        
    def do_search(self, arg):
        if not arg:
            self.ui_formatter.print_status("error", "Usage: search <term>")
            return
            
        term = arg.lower().strip()
        matches = []
        
        for module_key, module_info in self.module_list.items():
            if (term in module_key.lower() or 
                term in module_info['name'].lower() or 
                term in module_info['description'].lower()):
                matches.append((module_key, module_info))
        
        if not matches:
            suggestions = self.command_parser.suggester.suggest_module(term)
            self.ui_formatter.print_status("warning", f"No modules found matching '{term}'.")
            if suggestions:
                self.ui_formatter.print_suggestion_box("Similar modules", suggestions)
        else:
            table = Table(title=f"Search results for '{term}'")
            table.add_column("Module", style="cyan", no_wrap=True)
            table.add_column("Name", style="magenta")
            table.add_column("Description", style="green")
            
            for module_key, module_info in matches:
                table.add_row(module_key, module_info['name'], module_info['description'])
            
            console.print(table)

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
        if not arg:
            console.print("\n[bright_cyan]DKrypt - Advanced Penetration Testing Framework[/bright_cyan]")
            console.print("\n[bright_yellow]Core Commands:[/bright_yellow]")
            commands_help = [
                ("use <module>", "Select a module to use"),
                ("show modules", "List all available modules"),
                ("show options", "Show current module options"),
                ("set <option> <value>", "Configure module option"),
                ("unset <option>", "Clear a module option"),
                ("run", "Execute the selected module"),
                ("back", "Return from current module context"),
                ("search <term>", "Find modules by name/description"),
                ("history", "View recent command history"),
                ("shortcut <create|list|run>", "Manage command shortcuts"),
                ("results <list|show|analyze>", "View and analyze scan results"),
                ("workflow <create|list|run|delete>", "Manage automation workflows"),
                ("info [module]", "Show module information"),
                ("exit/quit/q", "Exit the application"),
            ]
            
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Command", style="cyan", no_wrap=True)
            table.add_column("Description", style="green")
            
            for cmd, desc in commands_help:
                table.add_row(cmd, desc)
            
            console.print(table)
            console.print("\n[dim]Type 'help <module>' for specific module assistance.[/dim]")
        else:
            if arg in self.module_list:
                self._show_module_info(arg)
            else:
                self.ui_formatter.print_status("error", f"Unknown module: {arg}")
    
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
        cmd, *args = line.split()
        if cmd == 'EOF':
            return self.do_exit('')

        suggestions = self.command_parser.suggester.suggest_command(cmd)
        self.ui_formatter.print_status("error", f"Unknown command: {cmd}")
        if suggestions:
            self.ui_formatter.print_suggestion_box("Did you mean?", suggestions)

    def complete_set(self, text, line, begidx, endidx):
        """Tab completion for the set command with improved context awareness"""
        # Extract current module context
        if self.module:
            # Use the improved suggester to get options for the current module
            suggestions = self.command_parser.suggester.suggest_options(self.module, text)
            return suggestions
        return []

    def complete_unset(self, text, line, begidx, endidx):
        """Tab completion for the unset command"""
        # Return currently set options
        return [opt for opt in self.options.keys() if opt.startswith(text.upper())]

    def complete_use(self, text, line, begidx, endidx):
        """Tab completion for the use command with fuzzy matching"""
        # Use the improved suggester to get module suggestions
        suggestions = self.command_parser.suggester.suggest_module(text, threshold=0.3)
        return [suggestion[0] for suggestion in suggestions]  # Return just the module names

    def complete_show(self, text, line, begidx, endidx):
        """Tab completion for the show command"""
        show_options = ['modules', 'options']
        return [opt for opt in show_options if opt.startswith(text.lower())]

    def complete_search(self, text, line, begidx, endidx):
        """Tab completion for the search command"""
        # Use the suggester to find matching modules
        suggestions = self.command_parser.suggester.suggest_module(text, threshold=0.3)
        return [suggestion[0] for suggestion in suggestions]


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
