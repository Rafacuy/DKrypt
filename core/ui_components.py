#!/usr/bin/env python3

import time
from typing import Optional, List, Dict, Any, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text


class ProgressTracker:
    def __init__(self, console: Console):
        self.console = console
        self.progress = None
        self.task_id = None
    
    def start(self, total: int, description: str = "Processing"):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console
        )
        self.task_id = self.progress.add_task(description, total=total)
        return self.progress
    
    def update(self, advance: int = 1, new_description: str = None):
        if self.progress and self.task_id is not None:
            if new_description:
                self.progress.update(self.task_id, description=new_description)
            self.progress.update(self.task_id, advance=advance)
    
    def stop(self):
        if self.progress:
            self.progress.stop()


class TableBuilder:
    def __init__(self, title: str = None, show_header: bool = True):
        self.table = Table(title=title, show_header=show_header, header_style="bold cyan")
        self.columns = []
    
    def add_column(self, name: str, style: str = None, justify: str = "left", no_wrap: bool = False):
        self.table.add_column(name, style=style, justify=justify, no_wrap=no_wrap)
        self.columns.append(name)
        return self
    
    def add_row(self, *values):
        self.table.add_row(*values)
        return self
    
    def add_rows(self, rows: List[tuple]):
        for row in rows:
            self.table.add_row(*row)
        return self
    
    def build(self) -> Table:
        return self.table


class PanelBuilder:
    def __init__(self, content: str, title: str = None, style: str = "cyan"):
        self.content = content
        self.title = title
        self.style = style
    
    def build(self) -> Panel:
        return Panel(self.content, title=self.title, style=self.style)


class StatusIndicator:
    STATUS_SYMBOLS = {
        "success": "✓",
        "error": "✗",
        "warning": "⚠",
        "info": "ℹ",
        "pending": "⏳",
        "running": "▶"
    }
    
    STATUS_COLORS = {
        "success": "green",
        "error": "red",
        "warning": "yellow",
        "info": "cyan",
        "pending": "yellow",
        "running": "blue"
    }
    
    @staticmethod
    def get_indicator(status: str) -> Text:
        symbol = StatusIndicator.STATUS_SYMBOLS.get(status, "?")
        color = StatusIndicator.STATUS_COLORS.get(status, "white")
        return Text(symbol, style=color)
    
    @staticmethod
    def format_status_message(status: str, message: str) -> Text:
        indicator = StatusIndicator.get_indicator(status)
        color = StatusIndicator.STATUS_COLORS.get(status, "white")
        text = Text()
        text.append(indicator)
        text.append(" ")
        text.append(message, style=color)
        return text


class OutputFormatter:
    def __init__(self, console: Console):
        self.console = console
    
    def print_status(self, status: str, message: str):
        formatted = StatusIndicator.format_status_message(status, message)
        self.console.print(formatted)
    
    def print_module_header(self, module_name: str, description: str = ""):
        header = f"[bold cyan]{module_name}[/bold cyan]"
        if description:
            header += f" [dim]{description}[/dim]"
        self.console.print(f"\n{header}\n")
    
    def print_config_table(self, config: Dict[str, Any]):
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")
        table.add_column("Status", style="green")
        
        for key, value in config.items():
            status = "[green]SET[/green]" if value else "[yellow]DEFAULT[/yellow]"
            table.add_row(key.upper(), str(value), status)
        
        self.console.print(table)
    
    def print_error_with_suggestions(self, error: str, suggestions: List[str] = None):
        self.print_status("error", error)
        
        if suggestions:
            self.console.print("\n[bold yellow]Suggestions:[/bold yellow]")
            for suggestion in suggestions:
                self.console.print(f"  [cyan]→[/cyan] {suggestion}")
    
    def print_module_list(self, modules: Dict[str, Dict]):
        table = Table(title="[bold]Available Modules[/bold]", show_header=True, header_style="bold cyan")
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Category", style="magenta", justify="center")
        table.add_column("Description", style="green")
        
        for module_key, module_info in modules.items():
            table.add_row(
                module_key,
                module_info.get('category', 'unknown'),
                module_info.get('description', '')
            )
        
        self.console.print(table)
    
    def print_command_history(self, history_entries: List[Any]):
        table = Table(title="[bold]Command History[/bold]", show_header=True, header_style="bold cyan")
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Time", style="yellow", no_wrap=True)
        table.add_column("Status", style="magenta", justify="center")
        table.add_column("Duration", style="green", justify="right")
        
        for entry in history_entries:
            status = "[green]✓[/green]" if entry.status == "success" else "[red]✗[/red]" if entry.status == "error" else "[yellow]●[/yellow]"
            timestamp = entry.timestamp.split("T")[1][:8] if hasattr(entry, 'timestamp') and entry.timestamp else "N/A"
            
            if hasattr(entry, 'execution_time'):
                duration = f"{entry.execution_time:.2f}s" if entry.execution_time > 0 else "N/A"
            elif hasattr(entry, 'duration'):
                duration = f"{entry.duration:.2f}s" if entry.duration > 0 else "N/A"
            else:
                duration = "N/A"
            
            table.add_row(entry.module, timestamp, status, duration)
        
        self.console.print(table)
    
    def print_suggestion_box(self, title: str, suggestions: List[Tuple[str, float]]):
        if not suggestions:
            return
        
        content = "[bold]Did you mean?[/bold]\n"
        for i, (suggestion, score) in enumerate(suggestions[:5], 1):
            confidence = int(score * 100)
            content += f"{i}. [cyan]{suggestion}[/cyan] ({confidence}%)\n"
        
        panel = Panel(content.strip(), title=title, style="yellow")
        self.console.print(panel)
    
    def print_options_table(self, module_options: Dict[str, Dict]):
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Required", style="magenta", justify="center")
        table.add_column("Default", style="yellow")
        table.add_column("Description", style="green")
        
        for opt_name, opt_info in module_options.items():
            required = "[red]YES[/red]" if opt_info.get('required', False) else "[green]NO[/green]"
            default = str(opt_info.get('default', 'N/A'))
            description = opt_info.get('description', '')
            table.add_row(opt_name, required, default, description)
        
        self.console.print(table)


class InteractivePrompt:
    def __init__(self, console: Console):
        self.console = console
    
    def prompt_yes_no(self, message: str, default: bool = True) -> bool:
        default_str = "Y/n" if default else "y/N"
        response = self.console.input(f"\n[cyan]{message}[/cyan] [{default_str}]: ").strip().lower()
        
        if not response:
            return default
        
        return response in ['y', 'yes']
    
    def prompt_choice(self, message: str, choices: List[str]) -> Optional[str]:
        self.console.print(f"\n[cyan]{message}[/cyan]")
        for i, choice in enumerate(choices, 1):
            self.console.print(f"  {i}. {choice}")
        
        while True:
            response = self.console.input("[cyan]Enter choice[/cyan] (1-{}): ".format(len(choices))).strip()
            try:
                idx = int(response) - 1
                if 0 <= idx < len(choices):
                    return choices[idx]
            except ValueError:
                pass
            self.console.print("[red]Invalid choice. Try again.[/red]")
    
    def prompt_multiline(self, message: str, prompt: str = "> ") -> str:
        self.console.print(f"[cyan]{message}[/cyan] (Ctrl+D or empty line to finish)")
        lines = []
        try:
            while True:
                line = self.console.input(prompt)
                if not line:
                    break
                lines.append(line)
        except EOFError:
            pass
        return "\n".join(lines)


class ContextMenu:
    def __init__(self, console: Console):
        self.console = console
    
    def show_module_context_menu(self, module: str, current_options: Dict[str, Any]) -> Optional[str]:
        menu_items = [
            ("Show Options", "options"),
            ("Set Option", "set"),
            ("Run Module", "run"),
            ("View Info", "info"),
            ("Back to Main", "back"),
            ("Exit", "exit")
        ]
        
        self.console.print(f"\n[bold cyan]Module: {module}[/bold cyan]")
        for i, (label, _) in enumerate(menu_items, 1):
            self.console.print(f"  {i}. {label}")
        
        try:
            choice = int(self.console.input("[cyan]Select[/cyan]: "))
            if 1 <= choice <= len(menu_items):
                return menu_items[choice - 1][1]
        except (ValueError, IndexError):
            pass
        
        return None
    
    def show_main_menu_options(self) -> Optional[str]:
        menu_items = [
            ("Use Module", "use"),
            ("Show Modules", "show modules"),
            ("Search Module", "search"),
            ("View History", "history"),
            ("View Help", "help"),
            ("Exit", "exit")
        ]
        
        self.console.print("\n[bold cyan]Main Menu[/bold cyan]")
        for i, (label, _) in enumerate(menu_items, 1):
            self.console.print(f"  {i}. {label}")
        
        try:
            choice = int(self.console.input("[cyan]Select[/cyan]: "))
            if 1 <= choice <= len(menu_items):
                return menu_items[choice - 1][1]
        except (ValueError, IndexError):
            pass
        
        return None
