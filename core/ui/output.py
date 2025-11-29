#!/usr/bin/env python3
"""
DKrypt Output Formatting System
Standardized output, response formatting, and export capabilities
"""

import json
import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn


class OutputFormat(Enum):
    """Supported output formats"""
    JSON = "json"
    CSV = "csv"
    TABLE = "table"
    TEXT = "text"


@dataclass
class CommandResponse:
    """Standardized response object for all operations"""
    status: str  # "success", "error", "warning"
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None
    duration_ms: Optional[float] = None
    error_code: Optional[str] = None
    module: Optional[str] = None
    target: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        # Remove None values for cleaner output
        return {k: v for k, v in result.items() if v is not None}
    
    def to_json(self, indent=2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def is_success(self) -> bool:
        """Check if operation was successful"""
        return self.status == "success"


class OutputFormatter:
    """Handles formatting and exporting results"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.output_dir = Path(".dkrypt/outputs")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def print_response(self, response: CommandResponse, verbose=False):
        """
        Print response in user-friendly format
        
        Args:
            response: CommandResponse object
            verbose: Include additional details
        """
        status_color = {
            "success": "green",
            "error": "red",
            "warning": "yellow"
        }.get(response.status, "white")
        
        # Print main message
        self.console.print(
            f"[bold {status_color}]{'✓' if response.status == 'success' else '⨯'} {response.message}[/bold {status_color}]"
        )
        
        # Print additional details
        if verbose or response.error_code:
            panel_content = []
            
            if response.error_code:
                panel_content.append(f"[red]Error Code: {response.error_code}[/red]")
            
            if response.module:
                panel_content.append(f"[cyan]Module: {response.module}[/cyan]")
            
            if response.target:
                panel_content.append(f"[cyan]Target: {response.target}[/cyan]")
            
            if response.duration_ms:
                panel_content.append(f"[yellow]Duration: {response.duration_ms:.2f}ms[/yellow]")
            
            if response.data:
                panel_content.append(f"[dim]Data entries: {len(response.data)}[/dim]")
            
            if panel_content:
                self.console.print(
                    Panel("\n".join(panel_content), title="Details", expand=False)
                )
    
    def export_json(self, data: Any, filename: str, pretty=True) -> Path:
        """
        Export data to JSON file
        
        Args:
            data: Data to export
            filename: Output filename
            pretty: Pretty print JSON
            
        Returns:
            Path to created file
        """
        output_path = self.output_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2 if pretty else None, default=str)
        
        return output_path
    
    def export_csv(self, data: List[Dict[str, Any]], filename: str) -> Path:
        """
        Export data to CSV file
        
        Args:
            data: List of dictionaries
            filename: Output filename
            
        Returns:
            Path to created file
        """
        if not data:
            raise ValueError("No data to export")
        
        output_path = self.output_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Get fieldnames from first record
        fieldnames = list(data[0].keys())
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        
        return output_path
    
    def export_text(self, data: List[str], filename: str) -> Path:
        """
        Export data to text file
        
        Args:
            data: List of strings
            filename: Output filename
            
        Returns:
            Path to created file
        """
        output_path = self.output_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(str(item) for item in data))
        
        return output_path
    
    def print_table(self, title: str, headers: List[str], rows: List[List[Any]]):
        """
        Print formatted table
        
        Args:
            title: Table title
            headers: Column headers
            rows: Table rows
        """
        table = Table(title=title)
        
        for header in headers:
            table.add_column(header, style="cyan")
        
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        
        self.console.print(table)
    
    def create_progress_bar(self, description: str = "Processing") -> Progress:
        """
        Create a progress bar
        
        Args:
            description: Progress description
            
        Returns:
            Progress object
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        )
    
    def print_error_panel(self, title: str, message: str, details: Optional[Dict] = None):
        """
        Print error in panel format
        
        Args:
            title: Error title
            message: Error message
            details: Optional error details
        """
        content = f"[bold red]{message}[/bold red]"
        
        if details:
            content += "\n\n[dim]Details:[/dim]"
            for key, value in details.items():
                content += f"\n  {key}: {value}"
        
        self.console.print(Panel(content, title=f"[red]{title}[/red]", expand=False))
    
    def print_success_panel(self, title: str, message: str, details: Optional[Dict] = None):
        """
        Print success message in panel format
        
        Args:
            title: Success title
            message: Success message
            details: Optional details
        """
        content = f"[bold green]{message}[/bold green]"
        
        if details:
            content += "\n\n[dim]Details:[/dim]"
            for key, value in details.items():
                content += f"\n  {key}: {value}"
        
        self.console.print(Panel(content, title=f"[green]{title}[/green]", expand=False))


# Global formatter instance
formatter = OutputFormatter()
