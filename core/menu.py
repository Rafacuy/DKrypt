# core/menu.py

import sys
import shutil
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass
from rich.console import Console, Group
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
import time


@dataclass
class MenuOption:
    """Represents a single menu option with its properties."""
    id: int
    name: str
    description: str
    category: str = "general"
    enabled: bool = True


class MenuConfig:
    """Configuration constants for the menu system."""
    
    # Application metadata
    APP_NAME = "DKrypt"
    APP_TAGLINE = "Integrated Security Toolkit"
    VERSION = "1.2.8"
    STATUS = "STABLE"
    COPYRIGHT = "© 2025 DKrypt Security"
    
    # Visual styling
    COLORS = {
        'primary': '#FF6B6B',
        'secondary': '#118AB2', 
        'accent': '#FFD166',
        'success': '#06D6A0',
        'warning': '#EF476F',
        'muted': '#6C757D',
        'background': '#2D3047'
    }
    
    # Layout settings
    MIN_TERMINAL_WIDTH = 60
    PREFERRED_WIDTH = 80
    COLUMN_SPACING = 4
    PANEL_PADDING = (1, 2)
    
    # Menu options with descriptions
    MENU_OPTIONS = [
        MenuOption(1, "Subdomain Scanner", "Comprehensively discover target subdomains", "reconnaissance"),
        MenuOption(2, "SSL/TLS Inspector", "Analyze website security certificates", "analysis"),
        MenuOption(3, "SQLI Scanner", "Detect SQLi injection vulnerability on a website", "vulnerability"),
        MenuOption(4, "XSS Scanner", "Detect Cross-Site-Scripting Vulnerability on a website", "vulnerability"),
        MenuOption(5, "Security Header Audit", "Evaluate HTTP security header implementation", "analysis"),
        MenuOption(6, "Website Crawler", "Extract and analyze website content", "intelligence"),
        MenuOption(7, "Admin Page Finder", "Locate hidden administrative interfaces", "discovery"),
        MenuOption(8, "Directory Bruteforcer", "Search for hidden directories and files", "discovery"),
        MenuOption(9, "Port Scanner", "Identify open ports and running services", "reconnaissance"),
        MenuOption(10, "WAF Bypass Tester", "Test Web Application Firewall bypass techniques", "evasion"),
        MenuOption(11, "CORS Misconfig Auditor", "Identify Cross-Origin Resource Sharing issues", "vulnerability"),
        MenuOption(12, "HTTP Desync Tester", "Test for HTTP request smuggling vulnerabilities", "vulnerability"),
        MenuOption(13, "Exit", "Terminate the application", "system")
    ]


class MenuValidator:
    """Handles input validation and error checking."""
    
    @staticmethod
    def validate_choice(choice: str, max_options: int) -> Tuple[bool, Union[int, str]]:
        """
        Validate user menu choice.
        
        Args:
            choice: Raw user input
            max_options: Maximum valid option number
            
        Returns:
            Tuple of (is_valid, validated_choice_or_error_message)
        """
        if not choice:
            return False, "Empty input. Please enter a number between 1 and {}.".format(max_options)
        
        choice = choice.strip()
        
        if not choice.isdigit():
            return False, f"Invalid input '{choice}'. Please enter a number between 1 and {max_options}."
        
        choice_int = int(choice)
        if not 1 <= choice_int <= max_options:
            return False, f"Option {choice_int} is out of range. Please select 1-{max_options}."
        
        return True, choice_int
    
    @staticmethod
    def check_terminal_compatibility() -> Tuple[bool, str]:
        """
        Check if terminal meets minimum requirements.
        
        Returns:
            Tuple of (is_compatible, warning_message)
        """
        try:
            width = shutil.get_terminal_size().columns
            if width < MenuConfig.MIN_TERMINAL_WIDTH:
                return False, (f"Terminal width ({width} cols) is below minimum requirement "
                             f"({MenuConfig.MIN_TERMINAL_WIDTH} cols). Layout may be distorted.")
            return True, ""
        except Exception:
            return False, "Unable to determine terminal size. Display issues may occur."


class MenuRenderer:
    """Handles all menu rendering and display logic."""
    
    def __init__(self, console: Console):
        self.console = console
        self.terminal_width = self._get_safe_terminal_width()
        
    def _get_safe_terminal_width(self) -> int:
        """Get terminal width with fallback to default."""
        try:
            return min(shutil.get_terminal_size().columns, MenuConfig.PREFERRED_WIDTH)
        except Exception:
            return MenuConfig.PREFERRED_WIDTH
    
    def _create_header(self) -> Text:
        """Create the stylized application header."""
        header = Text(f" {MenuConfig.APP_NAME} ", style=f"bold {MenuConfig.COLORS['primary']}")
        header.stylize(f"gradient(45, {MenuConfig.COLORS['primary']}, {MenuConfig.COLORS['accent']}) bold")
        return header
    
    def _create_subtitle(self) -> Text:
        """Create the application subtitle with version info."""
        subtitle_text = (f"{MenuConfig.APP_TAGLINE}\n"
                        f"Version {MenuConfig.VERSION} ({MenuConfig.STATUS}) • "
                        f"{MenuConfig.COPYRIGHT}")
        return Text(subtitle_text, style=f"italic {MenuConfig.COLORS['muted']}", justify="center")
    
    def _create_menu_table(self, options: List[MenuOption]) -> Table:
        """
        Create a formatted table for menu options in two columns.
        
        Args:
            options: List of menu options to display
            
        Returns:
            Rich Table object with formatted menu
        """
        table = Table.grid(padding=1)
        table.add_column(justify="left", width=35)
        table.add_column(justify="left", width=35)
        
        # Group options in pairs for two-column layout
        for i in range(0, len(options), 2):
            left_option = options[i]
            left_text = f"[{left_option.id:2d}] {left_option.name}"
            
            right_text = ""
            if i + 1 < len(options):
                right_option = options[i + 1]
                right_text = f"[{right_option.id:2d}] {right_option.name}"
            
            # Apply color styling based on category
            left_styled = Text(left_text, style=self._get_option_style(left_option))
            right_styled = Text(right_text, style=self._get_option_style(options[i + 1]) if i + 1 < len(options) else "")
            
            table.add_row(left_styled, right_styled)
        
        return table
    
    def _get_option_style(self, option: MenuOption) -> str:
        """Get appropriate styling for menu option based on category."""
        style_map = {
            'reconnaissance': f"bold {MenuConfig.COLORS['secondary']}",
            'analysis': f"bold {MenuConfig.COLORS['success']}",
            'discovery': f"bold {MenuConfig.COLORS['accent']}",
            'vulnerability': f"bold {MenuConfig.COLORS['warning']}",
            'evasion': f"bold {MenuConfig.COLORS['primary']}",
            'intelligence': f"bold {MenuConfig.COLORS['muted']}",
            'system': f"bold red"
        }
        return style_map.get(option.category, f"bold {MenuConfig.COLORS['secondary']}")
    
    def _create_footer(self) -> Text:
        """Create the menu footer with instructions."""
        return Text(
            f"Select option 1-{len(MenuConfig.MENU_OPTIONS)} • Press ENTER to confirm",
            style=f"italic {MenuConfig.COLORS['muted']}",
            justify="center"
        )
    
    def display_loading(self, message: str = "Initializing security toolkit...", duration: float = 0.8):
        """Display a loading animation."""
        with self.console.status(f"[bold {MenuConfig.COLORS['success']}]{message}"):
            time.sleep(duration)
    
    def display_menu(self) -> None:
        """Render the complete menu interface."""
        
        # Create menu components
        header = self._create_header()
        subtitle = self._create_subtitle()
        menu_table = self._create_menu_table(MenuConfig.MENU_OPTIONS)
        footer = self._create_footer()
        
        # Center the table
        centered_table = Align.center(menu_table)
        
        panel_content = Group(
            Text("\n"),
            subtitle,
            Text("\n"),
            centered_table
        )
        
        # Display the complete menu
        self.console.print()
        self.console.print(Panel(
            panel_content,
            title=header,
            subtitle=footer,
            border_style=MenuConfig.COLORS['secondary'],
            padding=MenuConfig.PANEL_PADDING,
            width=min(self.terminal_width, MenuConfig.PREFERRED_WIDTH)
        ))
    
    def display_error(self, message: str) -> None:
        """Display an error message with appropriate styling."""
        self.console.print(f"\n[bold {MenuConfig.COLORS['warning']}]⚠ Error:[/] {message}")
    
    def display_warning(self, message: str) -> None:
        """Display a warning message."""
        self.console.print(f"[{MenuConfig.COLORS['warning']}]⚠ Warning:[/] {message}")


class MenuSystem:
    """Main menu system controller."""
    
    def __init__(self):
        self.console = Console()
        self.renderer = MenuRenderer(self.console)
        self.validator = MenuValidator()
        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize the menu system and perform compatibility checks."""
        # Check terminal compatibility
        is_compatible, warning = self.validator.check_terminal_compatibility()
        if not is_compatible:
            self.renderer.display_warning(warning)
            time.sleep(2)
    
    def show_menu(self) -> Optional[int]:
        """
        Display the menu and handle user interaction.
        
        Returns:
            Selected menu option number, or None if error occurred
        """
        try:
            # Display loading animation
            self.renderer.display_loading()
            
            # Show the menu
            self.renderer.display_menu()
            
            # Get user input with validation
            return self._get_user_choice()
            
        except KeyboardInterrupt:
            self.console.print(f"\n[{MenuConfig.COLORS['warning']}]Operation cancelled by user.[/]")
            return 12  # Exit option
        except Exception as e:
            self.renderer.display_error(f"Unexpected error occurred: {str(e)}")
            return None
    
    def _get_user_choice(self) -> Optional[int]:
        """
        Get and validate user menu choice with retry logic.
        
        Returns:
            Validated menu choice or None if max retries exceeded
        """
        max_retries = 3
        retries = 0
        
        while retries < max_retries:
            try:
                # Use Rich's Prompt for better UX
                choice = Prompt.ask(
                    f"[blink bold {MenuConfig.COLORS['warning']}]>>>[/] Select option",
                    console=self.console
                ).strip()
                
                # Validate the choice
                is_valid, result = self.validator.validate_choice(choice, len(MenuConfig.MENU_OPTIONS))
                
                if is_valid:
                    return result
                else:
                    self.renderer.display_error(result)
                    retries += 1
                    
            except EOFError:
                self.console.print(f"\n[{MenuConfig.COLORS['muted']}]Input stream closed. Exiting...[/]")
                return 12  # Exit option
            except Exception as e:
                self.renderer.display_error(f"Input error: {str(e)}")
                retries += 1
        
        self.renderer.display_error("Maximum retry attempts exceeded. Exiting...")
        return 12  # Exit option
    
    def get_option_info(self, option_id: int) -> Optional[MenuOption]:
        """
        Get detailed information about a specific menu option.
        
        Args:
            option_id: Menu option ID to retrieve
            
        Returns:
            MenuOption object or None if not found
        """
        for option in MenuConfig.MENU_OPTIONS:
            if option.id == option_id:
                return option
        return None
    
    def display_option_details(self, option_id: int) -> None:
        """Display detailed information about a selected option."""
        option = self.get_option_info(option_id)
        if option:
            self.console.print(f"\n[bold {MenuConfig.COLORS['success']}]Selected:[/] {option.name}")
            self.console.print(f"[{MenuConfig.COLORS['muted']}]Description:[/] {option.description}")
        else:
            self.renderer.display_error(f"Option {option_id} not found")


def main() -> None:
    """Main entry point for testing the menu system."""
    menu = MenuSystem()
    
    while True:
        choice = menu.show_menu()
        
        if choice is None:
            break
        elif choice == 12:  # Exit option
            menu.console.print(f"\n[bold {MenuConfig.COLORS['success']}]Thank you for using {MenuConfig.APP_NAME}![/]")
            break
        else:
            menu.display_option_details(choice)
            input(f"\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(0)
    except Exception as e:
        console = Console()
        console.print(f"[bold red]Fatal error:[/] {str(e)}")
        sys.exit(1)
