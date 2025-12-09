#!/usr/bin/env python3

import argparse
import sys
import asyncio
import os
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.shortcuts import print_formatted_text
from prompt_toolkit.formatted_text import HTML

from core.ui.banner import display_header
from core.cli.parsers import create_parser
from core.utils.help import HelpSystem
from core.cli.command_engine import CommandParser, CommandHistory, CommandValidator
from core.cli.suggestor import EnhancedSuggester
from core.cli.completer import SmartCompleter
from core.cli.prompt_completer import DKryptCompleter
from core.error_reporter import ErrorLogger, prompt_error_report
from core.ui.ui_components import OutputFormatter, ProgressTracker, StatusIndicator, InteractivePrompt, ContextMenu
from core.result_manager import ResultManager, WorkflowEngine, ThreatIntelligence
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

class InteractiveCLI:
    def __init__(self):
        self.module = None
        self.options = {}
        self.workspace_manager = WorkspaceManager()
        self.session_manager = SessionManager()
        self.current_workspace = "default"
        self.history_file = os.path.expanduser("~/.dkrypt_history")
        self.resource_scripts = []
        self.help_system = HelpSystem()
        self.should_exit = False
        
        self.ui_formatter = OutputFormatter(console)
        self.progress_tracker = ProgressTracker(console)
        self.interactive_prompt = InteractivePrompt(console)
        self.context_menu = ContextMenu(console)

        # Load modules dynamically from central registry
        self._load_modules_from_registry()

        # Initialize enhanced suggester and completer
        self.suggester = EnhancedSuggester(self.module_list)
        self.smart_completer = SmartCompleter(self.suggester, self.module_list)
        self.prompt_completer = DKryptCompleter(self.smart_completer)

        self.session = PromptSession(
            history=FileHistory(self.history_file),
            auto_suggest=AutoSuggestFromHistory(),
            completer=self.prompt_completer,
            complete_in_thread=True,
        )

        self.command_parser = CommandParser(self.module_list)
        self.command_history = self.command_parser.history
        self.result_manager = ResultManager()
        self.workflow_engine = WorkflowEngine(self.result_manager)
        self.threat_intelligence = ThreatIntelligence(self.result_manager)
        self.argparse_parser = create_parser()

    def _load_modules_from_registry(self):
        """Load modules dynamically from central registry"""
        from core.cli.module_registry import registry
        
        self.module_list = {}
        for spec in registry.modules:
            # Convert OptionSpec to interactive CLI format
            options = {}
            for opt in spec.options:
                options[opt.name.upper()] = {
                    'required': opt.required,
                    'description': opt.help,
                    'default': opt.default
                }
                if opt.choices:
                    options[opt.name.upper()]['choices'] = opt.choices
            
            self.module_list[spec.name] = {
                'name': spec.help.split(':')[0] if ':' in spec.help else spec.help,
                'description': spec.help,
                'category': 'scanner',  # Default category
                'function': lambda args, runner=spec.runner: runner({k.lower(): v for k, v in vars(args).items() if k != 'command'}),
                'options': options,
                'helper': spec.help
            }
    
    async def run(self):
        """Main loop for the interactive CLI."""
        display_header()
        print_formatted_text(HTML("\n<dim>Type 'help' for available commands or 'show modules' to get started.</dim>"))

        while not self.should_exit:
            try:
                prompt_text = self.get_prompt()
                user_input = await self.session.prompt_async(prompt_text)
                await self.handle_command(user_input)
            except KeyboardInterrupt:
                continue
            except EOFError:
                self.should_exit = True
        
        self.suggester.save_patterns()
        print_formatted_text(HTML("<yellow>Goodbye!</yellow>"))

    def get_prompt(self):
        if self.module:
            return f'(dkrypt:{self.module}) '
        return '(dkrypt) '

    async def handle_command(self, user_input):
        """Parse and execute a command."""
        user_input = user_input.strip()
        if not user_input:
            return

        parts = user_input.split()
        command = parts[0].lower()
        arg = ' '.join(parts[1:])

        handler = getattr(self, f"do_{command}", self.default)
        if handler == self.default:
            # For unknown commands, pass the whole user_input
            await handler(user_input)
        elif asyncio.iscoroutinefunction(handler):
            await handler(arg)
        else:
            handler(arg)

    async def default(self, user_input):
        # This is now effectively the 'unknown command' handler
        parts = user_input.split()
        # The check 'if not user_input' in handle_command ensures parts is not empty.
        cmd = parts[0]

        suggestions = self.suggester.suggest_command(cmd)
        self.ui_formatter.print_status("error", f"Unknown command: {cmd}")
        if suggestions:
            self.ui_formatter.print_suggestion_box("Did you mean?", suggestions)

    # ============ MODULE COMMANDS (no changes needed) ============    
    def do_use(self, arg):
        if not arg:
            self.ui_formatter.print_status("warning", "Module name required. Use 'show modules' to list available modules.")
            return
            
        module_name = arg.strip().lower()
        
        if module_name in self.module_list:
            self.module = module_name
            if self.module not in self.options:
                self.options[self.module] = {}
            self.ui_formatter.print_status("success", f"Using module: {self.module_list[module_name]['name']}")
            self.command_history.add_entry(module_name, {"action": "use"})
            
            # Update completer context
            self.smart_completer.set_context(module=module_name, options=self.options.get(module_name, {}))
            # Record usage pattern
            self.suggester.record_usage(module=module_name)
        else:
            suggestions = self.suggester.suggest_module(module_name)
            self.ui_formatter.print_status("error", f"Module '{module_name}' not found.")
            if suggestions:
                self.ui_formatter.print_suggestion_box("Did you mean?", [s[0] for s in suggestions])
    
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
        module_options = self.options.get(self.module, {})
        self.ui_formatter.print_module_header(module_info['name'], module_info['description'])

        if module_options:
            console.print("[bold]Current Configuration:[/bold]")
            self.ui_formatter.print_config_table(module_options)

        if 'options' in module_info:
            console.print("\n[bold]Available Options:[/bold]")
            self.ui_formatter.print_options_table(module_info['options'])

        if not module_options:
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
        
        # Combine all previously set options with the new option being set
        options_to_validate = self.options[self.module].copy()
        options_to_validate[option_upper] = value
        
        is_valid, errors, suggestions = self.command_parser.validate_and_get_suggestions(
            self.module, 
            options_to_validate
        )
        
        if errors:
            self.ui_formatter.print_error_with_suggestions(f"Invalid value for {option_upper}", errors)
        else:
            self.options[self.module][option_upper] = value
            self.ui_formatter.print_status("success", f"{option_upper} => {value}")
            
            # Update completer context and record pattern
            self.smart_completer.set_context(module=self.module, options=self.options[self.module])
            self.suggester.record_usage(module=self.module, option=option_upper, value=value)
    
    def do_unset(self, arg):
        """Unset an option: unset URL"""
        if not self.module:
            self.ui_formatter.print_status("warning", "No module selected.")
            return
        
        option = arg.strip().upper()
        if self.module in self.options and option in self.options[self.module]:
            del self.options[self.module][option]
            console.print(f"[green]Unset {option}[/green]")
        else:
            console.print(f"[red]Option {option} not set for module {self.module}.[/red]")
    
    def do_run(self, arg):
        if not self.module:
            self.ui_formatter.print_status("warning", "No module selected. Use 'use <module>' first.")
            return

        module_info = self.module_list[self.module]
        
        # Start with default options
        final_options = {}
        for opt_name, opt_info in module_info.get('options', {}).items():
            if 'default' in opt_info:
                final_options[opt_name.lower()] = opt_info['default']

        # Get user-set options for the current module and overwrite defaults
        current_module_options = self.options.get(self.module, {})
        for opt_name, opt_value in current_module_options.items():
            final_options[opt_name.lower()] = opt_value

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

            if 'command' in [opt_name.lower() for opt_name, opt_info in module_info.get('options', {}).items()]:
                if 'command' not in final_options:
                    final_options['command'] = 'single'

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
            prompt_error_report(e, module=self.module, console=console)
    
    def do_back(self, arg):
        self.module = None
        self.ui_formatter.print_status("success", "Returned to main context.")
        self.smart_completer.set_context(module=None, options={})
        
    def do_history(self, arg):
        recent = self.command_history.get_recent(10)
        if not recent:
            self.ui_formatter.print_status("info", "No command history available.")
        else:
            self.ui_formatter.print_command_history(recent)
    
    def do_exit(self, arg):
        """Exit the application"""
        self.should_exit = True
    
    def do_quit(self, arg):
        """Exit the application"""
        self.do_exit(arg)
    
    def do_q(self, arg):
        """Exit the application"""
        self.do_exit(arg)

    # All other do_* commands remain the same
    def do_shortcut(self, arg):
        parts = arg.split(None, 2)
        if not parts:
            self.ui_formatter.print_status("error", "Usage: shortcut <create|list|run> [args]")
            return
        
        action = parts[0].lower()
        
        if action == "create" and len(parts) >= 3:
            name, rest = parts[1], " ".join(parts[2:])
            if self.module:
                module_options = self.options.get(self.module, {}).copy()
                self.command_history.add_shortcut(name, self.module, module_options)
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
                if self.module not in self.options:
                    self.options[self.module] = {}
                self.options[self.module] = shortcut["options"].copy()
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
                self.ui_formatter.print_status("success", f"Workspace '{ws_name}' created")
            else:
                self.ui_formatter.print_status("error", f"Workspace '{ws_name}' already exists")
        
        elif action == "switch" and len(parts) >= 2:
            ws_name = parts[1]
            self.current_workspace = ws_name
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
            if (
                term in module_key.lower() or 
                term in module_info['name'].lower() or 
                term in module_info['description'].lower()
            ):
                matches.append((module_key, module_info))
        
        if not matches:
            suggestions = self.suggester.suggest_module(term)
            self.ui_formatter.print_status("warning", f"No modules found matching '{term}'.")
            if suggestions:
                self.ui_formatter.print_suggestion_box("Similar modules", [s[0] for s in suggestions])
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

        console.print(f"\n[bright_cyan]{module_info['name']}[/bright_cyan]")
        console.print(f"[bold]Description:[/bold] {module_info['description']}")
        console.print(f"[bold]Category:[/bold] {module_info['category']}")
        if 'helper' in module_info:
            console.print(f"[bold]Helper:[/bold] {module_info['helper']}")

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
                ("errors <list|view|clear>", "Manage error logs"),
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
    
    def do_errors(self, arg):
        """Manage error logs: errors list|view <hash>|clear"""
        from core.error_reporter import ErrorLogger
        logger = ErrorLogger()
        
        parts = arg.split()
        action = parts[0].lower() if parts else "list"
        
        if action == "list":
            logs = logger.list_errors()
            if not logs:
                self.ui_formatter.print_status("info", "No error logs found")
                return
            
            table = Table(title="Recent Error Logs")
            table.add_column("Hash", style="cyan")
            table.add_column("File", style="yellow")
            table.add_column("Time", style="green")
            
            for log in logs:
                hash_id = log.stem.replace("error_", "")
                mtime = datetime.fromtimestamp(log.stat().st_mtime)
                table.add_row(hash_id, log.name, mtime.strftime("%Y-%m-%d %H:%M"))
            
            console.print(table)
            console.print("\n[dim]Use 'errors view <hash>' to see details[/dim]")
        
        elif action == "view" and len(parts) > 1:
            content = logger.view_error(parts[1])
            if content:
                console.print(Panel(content, title=f"Error {parts[1]}", border_style="red"))
            else:
                self.ui_formatter.print_status("error", f"Error log '{parts[1]}' not found")
        
        elif action == "clear":
            logger.clear_old_logs(30)
            self.ui_formatter.print_status("success", "Cleared logs older than 30 days")
        
        else:
            self.ui_formatter.print_status("error", "Usage: errors list|view <hash>|clear")

def run_interactive_cli():
    """Main function to run the interactive CLI"""
    try:
        interactive_cli = InteractiveCLI()
        asyncio.run(interactive_cli.run())
    except Exception as e:
        console.print(f"[red]Fatal error in interactive CLI: {str(e)}[/red]")
        prompt_error_report(e, module="interactive_cli", console=console)
        sys.exit(1)