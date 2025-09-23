# core/menu.py

import sys
import time
import subprocess
import sys
import os
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from rich.text import Text
from datetime import datetime
from pathlib import Path

@dataclass
class MenuOption:
    """Represents a single menu option"""
    id: int
    name: str
    description: str


class MenuConfig:
    """Core configuration for the menu system"""
    
    # Application metadata
    APP_NAME = "DKrypt"
    VERSION = "1.4.0"
    STATUS = "STABLE"
    COPYRIGHT = "© 2025 DKrypt Security"
    
    MENU_OPTIONS = [
        MenuOption(1, "Subdomain Scanner", "Discover target subdomains comprehensively"),
        MenuOption(2, "SSL/TLS Inspector", "Analyze website security certificates"),
        MenuOption(3, "SQLI Scanner", "Detect SQL injection vulnerabilities"),
        MenuOption(4, "XSS Scanner", "Detect Cross-Site Scripting vulnerabilities"),
        MenuOption(5, "Security Header Audit", "Evaluate HTTP security headers"),
        MenuOption(6, "Website Crawler", "Extract and analyze website content"),
        MenuOption(7, "Directory Bruteforcer", "Search for hidden directories and files"),
        MenuOption(8, "Port Scanner", "Identify open ports and services"),
        MenuOption(9, "WAF Bypass Tester", "Test Web Application Firewall bypasses"),
        MenuOption(10, "CORS Misconfig Auditor", "Identify CORS configuration issues"),
        MenuOption(11, "HTTP Desync Tester", "Test for HTTP request smuggling"),
        MenuOption(12, "Tracepulse", "Trace network routes and identify issues"),
        MenuOption(13, "JS Crawler", "Extract endpoints from JavaScript files"),
        MenuOption(14, "Python Obfuscator", "Obfuscate Python code for protection"),
        MenuOption(0, "Exit", "Exit the application"),
    ]
    
    # Colors for styling
    COLORS = {
        'primary': 'red',
        'secondary': 'white',
        'accent': 'bright_red',
        'success': 'green',
        'warning': 'yellow',
        'error': 'red',
        'muted': 'dim white',
        'highlight': 'bright_white'
    }


class MenuValidator:
    """Handles input validation"""
    
    @staticmethod
    def validate_choice(choice: str, max_options: int) -> Tuple[bool, Union[int, str]]:
        """Validate user menu choice."""
        if not choice or not choice.strip():
            return False, f"Enter a number between 1-{max_options}"
        
        choice = choice.strip()
        
        if not choice.isdigit():
            return False, f"Invalid input. Enter 1-{max_options}"
        
        choice_int = int(choice)
        if not 1 <= choice_int <= max_options:
            return False, f"Option {choice_int} out of range (1-{max_options})"
        
        return True, choice_int


class MenuRenderer:
    """Menu rendering class"""
    
    def __init__(self, console: Console) -> None:
        self.console = console
    
    def display_header(self) -> None:
        """Display application header"""
        self.console.print(f"\n[bold {MenuConfig.COLORS['accent']}]{MenuConfig.APP_NAME}[/] [dim]v{MenuConfig.VERSION}[/] [dim]({MenuConfig.STATUS})[/]")
        self.console.print(f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]\n")
    
    def display_menu_table(self, options: List[MenuOption], sort_by_name: bool = False) -> None:
        """Display menu options in a minimal table"""
        # Sort options if requested
        display_options = options.copy()
        if sort_by_name:
            display_options = sorted(display_options, key=lambda x: x.name)
        
        table = Table(show_header=False, show_lines=False, show_edge=False, pad_edge=False)
        table.add_column("ID", style=f"{MenuConfig.COLORS['warning']}", width=4, justify="right")
        table.add_column("Tool", style=f"bold {MenuConfig.COLORS['secondary']}", min_width=20)
        table.add_column("Description", style=f"{MenuConfig.COLORS['muted']}", min_width=35)
        
        # Add options to table
        for option in display_options:
            if option.id == 0:  # Exit option
                table.add_row(
                    f"[{MenuConfig.COLORS['error']}]{option.id}[/]",
                    f"[{MenuConfig.COLORS['error']}]{option.name}[/]",
                    f"[{MenuConfig.COLORS['error']}]{option.description}[/]"
                )
            else:
                table.add_row(
                    str(option.id),
                    option.name,
                    option.description
                )
        
        self.console.print(table)
    
    def display_prompt(self) -> None:
        """Display clean input promp"""
        self.console.print(f"\n[{MenuConfig.COLORS['primary']}]dkrypt[/] [dim]>[/] ", end="")
    
    def display_error(self, message: str) -> None:
        """Display minimal error message"""
        self.console.print(f"[{MenuConfig.COLORS['error']}]✗[/] {message}")
    
    def display_success(self, message: str) -> None:
        """Display minimal success message"""
        self.console.print(f"[{MenuConfig.COLORS['success']}]✓[/] {message}")
    
    def display_info(self, message: str) -> None:
        """Display minimal info message"""
        self.console.print(f"[{MenuConfig.COLORS['muted']}]ℹ[/] {message}")
    
    def display_loading(self, message: str = "Loading", duration: float = 0.5) -> None:
        """Display minimal loading indicator"""
        with self.console.status(f"[{MenuConfig.COLORS['muted']}]{message}...[/]", spinner="dots"):
            time.sleep(duration)
    
    def display_tool_selected(self, option: MenuOption) -> None:
        """Display selected tool information"""
        self.console.print(f"\n[{MenuConfig.COLORS['success']}]Selected:[/] [bold]{option.name}[/]")
        self.console.print(f"[{MenuConfig.COLORS['muted']}]{option.description}[/]")
    
    def display_exit_message(self) -> None:
        """Display exit message"""
        self.console.print(f"\n[{MenuConfig.COLORS['muted']}]Goodbye![/]")

class InteractivePrompt:
    """A class for handling the interactive command prompt"""
    
    def __init__(self, console: Console, renderer: MenuRenderer):
        self.console = console
        self.renderer = renderer
        self.current_dir = str(Path.home())
        self.command_history = []
        self.history_index = -1
        self.aliases = {
            'ls': 'ls -la',
            'll': 'ls -la',
            'la': 'ls -a',
            'l': 'ls -CF',
            'cls': 'clear',
            '..': 'cd ..',
            '...': 'cd ../..',
            'h': 'history',
            'p': 'pwd',
        }
        self.bookmarks = {}
        self.env_vars = {}
        self.last_exit_code = 0
        self.command_stats = {}
        self.session_start = datetime.now()
        self.output_buffer = []
        self.max_history = 1000
        self.auto_complete_cache = set()
    
    def clear_console(self) -> None:
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def display_prompt(self) -> None:
        """Display enhanced interactive prompt with status indicators"""
        display_dir = Path(self.current_dir)
        
        # Format directory display
        if str(display_dir) == str(Path.home()):
            display_dir = "~"
        else:
            try:
                display_dir = f"~/{display_dir.relative_to(Path.home())}"
            except ValueError:
                # If not in home directory tree, show absolute path
                display_dir = str(display_dir)
        
        # Get git branch if in a git repository
        git_branch = self._get_git_branch()
        git_display = f" [{MenuConfig.COLORS['warning']}]{git_branch}[/]" if git_branch else ""
        
        # Status indicator based on last command
        status_indicator = "[green]✓[/]" if self.last_exit_code == 0 else f"[red]✗[{self.last_exit_code}][/]"
        
        # Time display
        current_time = datetime.now().strftime("%H:%M:%S")
        
        self.console.print(
            f"[dim]{current_time}[/] {status_indicator} "
            f"[{MenuConfig.COLORS['primary']}]root@DKrypt[/]:"
            f"[{MenuConfig.COLORS['accent']}]{display_dir}[/]{git_display}# ",
            end=""
        )
    
    def _get_git_branch(self) -> Optional[str]:
        """Get current git branch if in a repository"""
        try:
            result = subprocess.run(
                "git branch --show-current",
                shell=True,
                cwd=self.current_dir,
                capture_output=True,
                text=True,
                timeout=1
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except:
            pass
        return None
    
    def execute_command(self, command: str) -> Tuple[bool, str]:
        """Func to executing command prompt"""
        try:
            # Update command statistics
            base_cmd = command.split()[0] if command else ""
            self.command_stats[base_cmd] = self.command_stats.get(base_cmd, 0) + 1
            
            # Handle variable expansion
            command = self._expand_variables(command)
            
            # Handle aliases
            command = self._expand_aliases(command)
            
            # Handle pipes and redirections
            if '|' in command or '>' in command or '<' in command:
                return self._execute_complex_command(command)
            
            # Handle cd command
            if command.startswith("cd "):
                return self._handle_cd(command[3:].strip())
            
            # Handle background execution
            run_background = command.endswith('&')
            if run_background:
                command = command[:-1].strip()
            
            # Execute command
            if run_background:
                subprocess.Popen(
                    command,
                    shell=True,
                    cwd=self.current_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                return True, f"Process started in background: {command}"
            else:
                result = subprocess.run(
                    command,
                    shell=True,
                    cwd=self.current_dir,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                self.last_exit_code = result.returncode
                
                if result.returncode == 0:
                    output = result.stdout
                    self.output_buffer.append(output)
                    return True, output
                else:
                    return False, result.stderr or f"Command failed with exit code {result.returncode}"
                    
        except subprocess.TimeoutExpired:
            self.last_exit_code = 124
            return False, "Command timed out after 30 seconds"
        except Exception as e:
            self.last_exit_code = 1
            return False, f"Command execution error: {str(e)}"
    
    def _expand_variables(self, command: str) -> str:
        """Expand environment variables in command."""
        import re
        
        # Expand custom variables
        for var, value in self.env_vars.items():
            command = command.replace(f"${var}", value)
            command = command.replace(f"${{{var}}}", value)
        
        # Expand system environment variables
        for match in re.finditer(r'\$([A-Za-z_][A-Za-z0-9_]*)', command):
            var_name = match.group(1)
            var_value = os.environ.get(var_name, '')
            command = command.replace(f"${var_name}", var_value)
        
        return command
    
    def _expand_aliases(self, command: str) -> str:
        """Expand command aliases."""
        parts = command.split(None, 1)
        if parts and parts[0] in self.aliases:
            expanded = self.aliases[parts[0]]
            if len(parts) > 1:
                return f"{expanded} {parts[1]}"
            return expanded
        return command
    
    def _execute_complex_command(self, command: str) -> Tuple[bool, str]:
        """Execute commands with pipes and redirections."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.current_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            self.last_exit_code = result.returncode
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr or f"Command failed with exit code {result.returncode}"
        except Exception as e:
            self.last_exit_code = 1
            return False, str(e)
    
    def _handle_cd(self, path: str) -> Tuple[bool, str]:
        """Enhanced cd command handling with bookmarks."""
        if not path or path == "~":
            self.current_dir = str(Path.home())
            return True, f"Changed to home directory"
        
        # Handle bookmarks
        if path.startswith("@"):
            bookmark_name = path[1:]
            if bookmark_name in self.bookmarks:
                self.current_dir = self.bookmarks[bookmark_name]
                return True, f"Changed to bookmark '{bookmark_name}': {self.current_dir}"
            else:
                return False, f"Bookmark '{bookmark_name}' not found"
        
        # Handle - for previous directory
        if path == "-":
            if hasattr(self, 'prev_dir'):
                self.current_dir, self.prev_dir = self.prev_dir, self.current_dir
                return True, f"Changed to {self.current_dir}"
            else:
                return False, "No previous directory"
        
        # Normal cd handling
        target_dir = Path(path)
        if not target_dir.is_absolute():
            target_dir = Path(self.current_dir) / target_dir
        
        target_dir = target_dir.resolve()
        
        if target_dir.exists() and target_dir.is_dir():
            self.prev_dir = self.current_dir
            self.current_dir = str(target_dir)
            return True, f"Changed directory to {self.current_dir}"
        else:
            return False, f"Directory not found: {path}"
    
    def handle_special_commands(self, command: str) -> Optional[Tuple[bool, str]]:
        """Handle enhanced special interactive commands"""
        parts = command.split(None, 1)
        base_cmd = parts[0] if parts else command
        args = parts[1] if len(parts) > 1 else ""
        
        # Exit commands
        if base_cmd in ["exit", "quit", "q"]:
            session_duration = datetime.now() - self.session_start
            return True, f"Session duration: {session_duration}"
        
        # Clear screen
        elif base_cmd == "clear":
            self.clear_console()
            return True, ""
        
        # Present working directory
        elif base_cmd == "pwd":
            return True, self.current_dir
        
        # History management
        elif base_cmd == "history":
            if args:
                if args == "clear":
                    self.command_history.clear()
                    self.history_index = -1
                    return True, "History cleared"
                elif args == "stats":
                    return True, self._get_command_stats()
                elif args.startswith("search "):
                    pattern = args[7:]
                    matches = [f"{i+1}: {cmd}" for i, cmd in enumerate(self.command_history) 
                              if pattern in cmd]
                    return True, "\n".join(matches) if matches else "No matches found"
            return True, "\n".join([f"{i+1}: {cmd}" for i, cmd in enumerate(self.command_history[-20:])])
        
        # Bookmark management
        elif base_cmd == "bookmark":
            return self._handle_bookmarks(args)
        
        # Alias management
        elif base_cmd == "alias":
            return self._handle_aliases(args)
        
        # Environment variables
        elif base_cmd == "setvar":
            return self._handle_setvar(args)
        
        elif base_cmd == "getvar":
            if args in self.env_vars:
                return True, self.env_vars[args]
            return False, f"Variable '{args}' not found"
        
        # System information
        elif base_cmd == "sysinfo":
            return True, self._get_system_info()
        
        # Process management
        elif base_cmd == "ps":
            return self._handle_process_list(args)
        
        # Network utilities
        elif base_cmd == "netstat":
            return self._handle_netstat(args)
        
        # File search
        elif base_cmd == "find":
            return self._handle_find(args)
        
        # Quick navigation
        elif base_cmd == "up":
            levels = int(args) if args.isdigit() else 1
            path = "/".join([".."] * levels)
            return self._handle_cd(path)
        
        # Help system
        elif base_cmd == "help":
            return True, self._get_help_text(args)
        
        # Command timing
        elif base_cmd == "time":
            if args:
                start = time.time()
                success, output = self.execute_command(args)
                elapsed = time.time() - start
                return success, f"{output}\n\nExecution time: {elapsed:.3f}s"
        
        # Output redirection to clipboard (simulated)
        elif base_cmd == "clip":
            if self.output_buffer:
                last_output = self.output_buffer[-1]
                return True, f"Last output copied to clipboard ({len(last_output)} chars)"
            return False, "No output to copy"
        
        # Watch command (execute repeatedly)
        elif base_cmd == "watch":
            return self._handle_watch(args)
        
        # Directory stack
        elif base_cmd in ["pushd", "popd", "dirs"]:
            return self._handle_dir_stack(base_cmd, args)
        
        return None
    
    def _handle_bookmarks(self, args: str) -> Tuple[bool, str]:
        """Handle bookmark operations"""
        if not args:
            if not self.bookmarks:
                return True, "No bookmarks set"
            lines = ["Bookmarks:"]
            for name, path in self.bookmarks.items():
                lines.append(f"  @{name} -> {path}")
            return True, "\n".join(lines)
        
        parts = args.split(None, 1)
        action = parts[0]
        
        if action == "add":
            if len(parts) > 1:
                name = parts[1]
                self.bookmarks[name] = self.current_dir
                return True, f"Bookmark '@{name}' added for {self.current_dir}"
            return False, "Usage: bookmark add <name>"
        
        elif action == "remove":
            if len(parts) > 1:
                name = parts[1]
                if name in self.bookmarks:
                    del self.bookmarks[name]
                    return True, f"Bookmark '@{name}' removed"
                return False, f"Bookmark '@{name}' not found"
            return False, "Usage: bookmark remove <name>"
        
        elif action == "list":
            return self._handle_bookmarks("")
        
        return False, "Usage: bookmark [add|remove|list] [name]"
    
    def _handle_aliases(self, args: str) -> Tuple[bool, str]:
        """Handle alias operations"""
        if not args:
            if not self.aliases:
                return True, "No aliases defined"
            lines = ["Aliases:"]
            for alias, command in sorted(self.aliases.items()):
                lines.append(f"  {alias} = '{command}'")
            return True, "\n".join(lines)
        
        if '=' in args:
            alias, command = args.split('=', 1)
            alias = alias.strip()
            command = command.strip().strip('"\'')
            self.aliases[alias] = command
            return True, f"Alias '{alias}' set to '{command}'"
        
        return False, "Usage: alias [name=command]"
    
    def _handle_setvar(self, args: str) -> Tuple[bool, str]:
        """Handle environment variable settin"""
        if '=' in args:
            var, value = args.split('=', 1)
            var = var.strip()
            value = value.strip().strip('"\'')
            self.env_vars[var] = value
            return True, f"Variable '{var}' set to '{value}'"
        return False, "Usage: setvar VAR=value"
    
    def _get_system_info(self) -> str:
        """Get system information"""
        info = []
        info.append(f"Current Directory: {self.current_dir}")
        info.append(f"Home Directory: {Path.home()}")
        info.append(f"Shell: {os.environ.get('SHELL', 'Unknown')}")
        info.append(f"User: {os.environ.get('USER', 'Unknown')}")
        info.append(f"Session Duration: {datetime.now() - self.session_start}")
        info.append(f"Commands Executed: {len(self.command_history)}")
        info.append(f"Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Get disk usage for current directory
        try:
            result = subprocess.run("df -h .", shell=True, capture_output=True, text=True, cwd=self.current_dir)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    info.append(f"Disk Usage: {lines[1]}")
        except:
            pass
        
        return "\n".join(info)
    
    def _get_command_stats(self) -> str:
        """Get command usage statistics."""
        if not self.command_stats:
            return "No commands executed yet"
        
        lines = ["Command Statistics:"]
        sorted_stats = sorted(self.command_stats.items(), key=lambda x: x[1], reverse=True)
        for cmd, count in sorted_stats[:10]:
            lines.append(f"  {cmd}: {count} times")
        return "\n".join(lines)
    
    def _handle_process_list(self, args: str) -> Tuple[bool, str]:
        """List running processes."""
        try:
            if args == "aux":
                cmd = "ps aux | head -20"
            else:
                cmd = "ps -ef | head -20"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0, result.stdout
        except Exception as e:
            return False, str(e)
    
    def _handle_netstat(self, args: str) -> Tuple[bool, str]:
        """Show network statistics."""
        try:
            if sys.platform == "darwin":
                cmd = "netstat -an | head -20"
            else:
                cmd = "netstat -tuln | head -20"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0, result.stdout
        except Exception as e:
            return False, str(e)
    
    def _handle_find(self, args: str) -> Tuple[bool, str]:
        """Find files in current directory."""
        if not args:
            return False, "Usage: find <pattern>"
        
        try:
            cmd = f"find . -name '*{args}*' 2>/dev/null | head -20"
            result = subprocess.run(cmd, shell=True, cwd=self.current_dir, 
                                  capture_output=True, text=True)
            if result.stdout:
                return True, result.stdout
            return True, f"No files matching '{args}' found"
        except Exception as e:
            return False, str(e)
    
    def _handle_watch(self, args: str) -> Tuple[bool, str]:
        """Execute command repeatedly (simplified version)."""
        if not args:
            return False, "Usage: watch <command>"
        
        try:
            self.console.print(f"[{MenuConfig.COLORS['muted']}]Watching command (press Ctrl+C to stop): {args}[/]")
            for i in range(3):  # Run 3 times as example
                success, output = self.execute_command(args)
                self.console.clear()
                self.console.print(f"[{MenuConfig.COLORS['accent']}]Watch iteration {i+1}[/]")
                self.console.print(output if success else f"[red]{output}[/]")
                time.sleep(2)
            return True, "Watch completed"
        except KeyboardInterrupt:
            return True, "Watch interrupted"
    
    def _handle_dir_stack(self, cmd: str, args: str) -> Tuple[bool, str]:
        """Handle directory stack operations."""
        if not hasattr(self, 'dir_stack'):
            self.dir_stack = []
        
        if cmd == "pushd":
            path = args or str(Path.home())
            self.dir_stack.append(self.current_dir)
            success, msg = self._handle_cd(path)
            if success:
                return True, f"Pushed {self.current_dir} to stack"
            return False, msg
        
        elif cmd == "popd":
            if self.dir_stack:
                prev_dir = self.dir_stack.pop()
                self.current_dir = prev_dir
                return True, f"Popped to {self.current_dir}"
            return False, "Directory stack is empty"
        
        elif cmd == "dirs":
            if self.dir_stack:
                stack_display = " -> ".join(self.dir_stack + [self.current_dir])
                return True, f"Directory stack: {stack_display}"
            return True, f"Directory stack: {self.current_dir} (empty)"
        
        return False, "Unknown directory stack command"
    
    def _get_help_text(self, topic: str = "") -> str:
        """Get context-sensitive help."""
        if not topic:
            return """
Interactive Shell (IS) Commands:

Navigation:
  cd <path>         Change directory (use @name for bookmarks, - for previous)
  pwd               Show current directory
  up [n]            Go up n directories (default: 1)
  pushd/popd/dirs   Directory stack operations

File Operations:
  ls, ll, la        List files (aliases configured)
  find <pattern>    Find files matching pattern

Bookmarks:
  bookmark add <name>     Add bookmark for current directory
  bookmark remove <name>  Remove bookmark
  bookmark list          List all bookmarks
  cd @<name>            Go to bookmark

History:
  history              Show command history
  history clear        Clear history
  history stats        Show command statistics
  history search <text> Search in history
  !<number>           Execute command from history

Variables & Aliases:
  alias [name=cmd]     Set or list aliases
  setvar VAR=value     Set custom variable
  getvar VAR          Get variable value

System:
  sysinfo             System information
  ps [aux]            List processes
  netstat             Network connections
  time <command>      Time command execution
  watch <command>     Execute command repeatedly

Special:
  clear               Clear screen
  clip                Copy last output to clipboard
  shell/exit/quit     Exit interactive mode

Use 'help <command>' for detailed help on a specific command.
"""
        
        # Topic-specific help
        help_topics = {
            'cd': "cd: Change directory\n  cd <path>  - Change to path\n  cd @name   - Go to bookmark\n  cd -       - Go to previous directory\n  cd ~       - Go to home",
            'bookmark': "bookmark: Manage directory bookmarks\n  bookmark add <name>    - Add current dir as bookmark\n  bookmark remove <name> - Remove bookmark\n  bookmark list         - List all bookmarks",
            'history': "history: Command history management\n  history         - Show recent commands\n  history clear   - Clear all history\n  history stats   - Show command usage stats\n  history search  - Search in history",
            'alias': "alias: Manage command aliases\n  alias           - List all aliases\n  alias name=cmd  - Create new alias",
        }
        
        return help_topics.get(topic, f"No specific help for '{topic}'. Use 'help' for general help.")
    
    def run(self) -> bool:
        """Run the prompt loop"""
        self.console.print(f"\n[{MenuConfig.COLORS['success']}]═══ Interactive Shell Mode ═══[/]")
        self.console.print(f"[{MenuConfig.COLORS['muted']}]Type 'help' for commands, 'exit' to return to menu[/]")
        self.console.print(f"[{MenuConfig.COLORS['muted']}]Session started at {self.session_start.strftime('%H:%M:%S')}[/]\n")
        
        # Initialize directory stack
        self.dir_stack = []
        self.prev_dir = self.current_dir
        
        while True:
            try:
                self.display_prompt()
                command = input().strip()
                
                if not command:
                    continue
                
                # Add to history if not duplicate of last command
                if not self.command_history or self.command_history[-1] != command:
                    self.command_history.append(command)
                    # Maintain max history size
                    if len(self.command_history) > self.max_history:
                        self.command_history = self.command_history[-self.max_history:]
                    self.history_index = len(self.command_history)
                
                # Handle special commands first
                special_result = self.handle_special_commands(command)
                if special_result is not None:
                    success, message = special_result
                    if command in ["exit", "quit", "q"]:
                        self.console.print(f"[{MenuConfig.COLORS['muted']}]{message}[/]")
                        return True
                    if message:
                        if success:
                            self.console.print(message)
                        else:
                            self.renderer.display_error(message)
                    continue
                
                # Handle history execution
                if command.startswith("!"):
                    try:
                        index = int(command[1:]) - 1
                        if 0 <= index < len(self.command_history):
                            command = self.command_history[index]
                            self.console.print(f"[dim]Executing: {command}[/]")
                        else:
                            self.renderer.display_error("History index out of range")
                            continue
                    except ValueError:
                        self.renderer.display_error("Invalid history index")
                        continue
                
                # Execute the command
                success, output = self.execute_command(command)
                
                if output:
                    if success:
                        self.console.print(output)
                    else:
                        self.renderer.display_error(output)
                        
            except KeyboardInterrupt:
                self.console.print("\n[yellow]^C[/] Command interrupted")
                self.last_exit_code = 130
            except EOFError:
                self.console.print("\n[dim]EOF received, exiting...[/]")
                return True
            except Exception as e:
                self.renderer.display_error(f"Unexpected error: {str(e)}")
                self.last_exit_code = 1
                
        return True

class MenuSystem:
    def __init__(self) -> None:
        self.console = Console(highlight=False)
        self.renderer = MenuRenderer(self.console)
        self.validator = MenuValidator()
        self.sort_by_name = False
        self.interactive_prompt = InteractivePrompt(self.console, self.renderer)
    
    def show_menu(self) -> Optional[int]:
        try:
            self.renderer.display_header()
            self.renderer.display_menu_table(MenuConfig.MENU_OPTIONS, self.sort_by_name)        
            self.console.print(f"\n[{MenuConfig.COLORS['muted']}]Commands: [/]"
                             f"[{MenuConfig.COLORS['highlight']}]0-14[/] [dim]select tool[/] | "
                             f"[{MenuConfig.COLORS['highlight']}]sort[/] [dim]toggle sort[/] | "
                             f"[{MenuConfig.COLORS['highlight']}]shell[/] [dim]interactive mode[/] | "
                             f"[{MenuConfig.COLORS['highlight']}]exit/quit[/] [dim]exit app[/]")
            
            return self._get_user_input()
            
        except KeyboardInterrupt:
            self.console.print(f"\n[{MenuConfig.COLORS['muted']}]Interrupted[/]")
            return 15
        except Exception as e:
            self.renderer.display_error(f"System error: {str(e)}")
            return None
    
    def _get_user_input(self) -> Optional[int]:
        """Get and validate user input with clean error handling."""
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                self.renderer.display_prompt()
                choice = input().strip().lower()
                
                # Handle special commands
                if choice in ['exit', 'quit', 'q']:
                    return 15
                elif choice in ['sort', 's']:
                    self.sort_by_name = not self.sort_by_name
                    sort_status = "name" if self.sort_by_name else "ID"
                    self.renderer.display_info(f"Sorted by {sort_status}")
                    time.sleep(0.8)
                    return self.show_menu()  # Redisplay menu
                elif choice in ['help', 'h', '?']:
                    self._display_help()
                    continue
                elif choice in ['shell', 'interactive', 'i']:
                    self.interactive_prompt.run()
                
                # Validate numeric choice
                is_valid, result = self.validator.validate_choice(choice, len(MenuConfig.MENU_OPTIONS))
                
                if is_valid:
                    return result
                else:
                    self.renderer.display_error(result)
                    if attempt < max_attempts - 1:
                        time.sleep(1)
                        
            except EOFError:
                self.console.print(f"\n[{MenuConfig.COLORS['muted']}]EOF received[/]")
                return 15
            except Exception as e:
                self.renderer.display_error(f"Input error: {str(e)}")
        
        self.renderer.display_error("Max attempts exceeded")
        return 15
    
    def _display_help(self) -> None:
        """Display help information."""
        help_text = [
            "Available commands:",
            "• 0-14    Select tool by number",
            "• sort    Toggle sorting (ID/Name)",
            "• shell   Enter interactive command mode",
            "• exit    Exit application",
            "• help    Show this help"
        ]
        
        for line in help_text:
            self.console.print(f"[{MenuConfig.COLORS['muted']}]{line}[/]")
        
        input(f"\n[{MenuConfig.COLORS['muted']}]Press ENTER to continue...[/]")
    
    def get_option_by_id(self, option_id: int) -> Optional[MenuOption]:
        """Retrieve menu option by ID."""
        return next((opt for opt in MenuConfig.MENU_OPTIONS if opt.id == option_id), None)
    
    def handle_option_selection(self, option_id: int) -> None:
        """Handle option selection with clean feedback."""
        option = self.get_option_by_id(option_id)
        if option:
            self.renderer.display_tool_selected(option)
            
            # Simulate tool loading
            if option.id != 0:
                self.renderer.display_loading(f"Initializing {option.name}")
                self.renderer.display_info("Tool would execute here")
        else:
            self.renderer.display_error(f"Tool {option_id} not found")
    
    def run(self) -> None:
        """Main application loop."""
        try:
            while True:
                choice = self.show_menu()
                
                if choice is None:
                    break
                elif choice == 15:
                    self.renderer.display_exit_message()
                    break
                else:
                    self.handle_option_selection(choice)
                    
        except KeyboardInterrupt:
            self.renderer.display_exit_message()
        except Exception as e:
            self.renderer.display_error(f"Fatal error: {str(e)}")
            sys.exit(1)

def main() -> None:
    """Main entry point."""
    menu_system = MenuSystem()
    menu_system.run()


if __name__ == "__main__":
    main()