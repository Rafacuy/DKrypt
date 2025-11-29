# DKrypt Architecture

Technical overview of DKrypt's system design and architecture.

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Core Components](#core-components)
- [Module System](#module-system)
- [Data Flow](#data-flow)
- [Design Patterns](#design-patterns)

---

## Overview

DKrypt follows a modular, layered architecture designed for:

- **Extensibility**: Easy to add new modules
- **Maintainability**: Clear separation of concerns
- **Testability**: Comprehensive test coverage
- **Performance**: Async operations and efficient resource usage

### Architecture Layers

```
┌─────────────────────────────────────────┐
│         CLI Interface Layer             │
│  (Typer, Interactive Shell, Parsers)    │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│         Core Framework Layer            │
│  (Validation, Config, Logging, Utils)   │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│         Module Execution Layer          │
│  (Security Modules, Scanners, Tools)    │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│         Output & Reporting Layer        │
│  (Formatters, Exporters, Storage)       │
└─────────────────────────────────────────┘
```

---

## Project Structure

### Directory Layout

```
DKrypt-CLI/
├── core/                       # Core framework components
│   ├── cli/                   # CLI-related components
│   │   ├── interactive_cli.py # Interactive shell implementation
│   │   ├── parsers.py         # Argument parsers and command registration
│   │   ├── command_engine.py  # Command parsing, validation, suggestions
│   │   └── menu.py            # Menu system
│   │
│   ├── validation/            # Input validation
│   │   └── validators.py      # Validator classes for all input types
│   │
│   ├── ui/                    # User interface components
│   │   ├── banner.py          # ASCII art and branding
│   │   ├── output.py          # Output formatting and display
│   │   └── ui_components.py   # Reusable UI widgets
│   │
│   ├── utils/                 # Utility functions
│   │   ├── utils.py           # General utilities
│   │   ├── randomizer.py      # User-agent and header randomization
│   │   ├── retry.py           # Retry logic with exponential backoff
│   │   └── help.py            # Help system
│   │
│   ├── config/                # Configuration
│   │   └── config.json        # Randomizer configuration (referers, IPs, browsers)
│   │
│   ├── config.py              # Configuration management
│   ├── logger.py              # Logging framework
│   ├── exceptions.py          # Custom exception hierarchy
│   ├── diagnostics.py         # System diagnostics
│   ├── module_registry.py     # Module registration and discovery
│   ├── result_manager.py      # Result storage and retrieval
│   └── workspace.py           # Workspace management
│
├── modules/                    # Security testing modules
│   ├── sqli_scan.py           # SQL injection scanner
│   ├── subdomain.py           # Subdomain enumeration
│   ├── port_scanner.py        # Port scanning
│   ├── xss/                   # XSS scanner (modular)
│   │   ├── scanner.py
│   │   ├── models.py
│   │   └── report.py
│   ├── crawler_engine/        # Web crawler
│   ├── waf_bypass/            # WAF bypass testing
│   ├── http_desync/           # HTTP desync testing
│   └── ...                    # Other modules
│
├── tests/                      # Test suite
│   ├── test_validators.py
│   ├── test_command_engine.py
│   ├── test_cli.py
│   └── ...
│
├── wordlists/                  # Curated wordlists
├── docs/                       # Documentation
├── dkrypt.py                   # Main entry point
└── dkrypt_main.py              # Typer application
```

---

## Core Components

### 1. CLI Layer (`core/cli/`)

#### Interactive CLI (`interactive_cli.py`)

- Implements interactive shell using `cmd` module
- Provides tab completion and command history
- Manages module state and options
- Handles user input and command routing

**Key Classes:**
- `InteractiveCLI`: Main interactive shell class

#### Parsers (`parsers.py`)

- Registers all module commands with Typer
- Defines command-line arguments and options
- Handles argument validation and type coercion
- Routes commands to appropriate modules

**Key Functions:**
- `register_commands(app)`: Registers all module commands

#### Command Engine (`command_engine.py`)

- Parses and validates commands
- Provides intelligent suggestions
- Manages command history
- Validates module options

**Key Classes:**
- `CommandValidator`: Validates module options
- `CommandSuggester`: Provides command suggestions
- `CommandParser`: Parses command-line input
- `CommandHistory`: Manages command history

### 2. Validation Layer (`core/validation/`)

#### Validators (`validators.py`)

- Validates all user input
- Provides type-safe validation
- Returns meaningful error messages

**Key Classes:**
- `Validator`: Main validator class with methods for:
  - URL validation
  - Domain validation
  - IP address validation
  - Port validation
  - File path validation
  - Integer/range validation
  - Choice validation

### 3. UI Layer (`core/ui/`)

#### Banner (`banner.py`)

- Displays ASCII art logo
- Shows version and status information
- Provides branding

#### Output (`output.py`)

- Formats output for console display
- Handles colored output using Rich
- Provides consistent formatting

#### UI Components (`ui_components.py`)

- Reusable UI widgets
- Progress bars
- Tables
- Panels

### 4. Utils Layer (`core/utils/`)

#### Randomizer (`randomizer.py`)

- Generates random user agents
- Rotates HTTP headers
- Provides IP address randomization
- Uses configuration from `core/config/config.json`

**Key Classes:**
- `HeaderFactory`: Generates realistic HTTP headers
- `IPRandomizer`: Generates random IP addresses

#### Retry (`retry.py`)

- Implements retry logic with exponential backoff
- Handles transient failures
- Configurable retry attempts and delays

#### Help (`help.py`)

- Provides contextual help
- Displays module information
- Shows usage examples

### 5. Core Modules

#### Config (`config.py`)

- Loads and manages configuration
- Validates configuration
- Provides configuration access

#### Logger (`logger.py`)

- Centralized logging
- File and console output
- Log rotation
- Different log levels

#### Exceptions (`exceptions.py`)

- Custom exception hierarchy
- Structured error information
- Error codes and details

**Exception Classes:**
- `DKryptException`: Base exception
- `ValidationError`: Input validation errors
- `ConfigurationError`: Configuration errors
- `ModuleExecutionError`: Module execution errors
- `NetworkError`: Network-related errors
- `TimeoutError`: Timeout errors

---

## Module System

### Module Structure

Each module follows a consistent structure:

```python
# modules/example_module.py

import asyncio
from typing import Dict, Any
from core.logger import logger
from core.exceptions import ModuleExecutionError

class ExampleModule:
    """Module description"""
    
    def __init__(self, options: Dict[str, Any]):
        self.options = options
        self.results = []
    
    async def run(self):
        """Main execution method"""
        try:
            # Module logic here
            pass
        except Exception as e:
            logger.error(f"Module error: {e}")
            raise ModuleExecutionError(str(e), module="example")
    
    def export_results(self, format: str = "json"):
        """Export results in specified format"""
        pass

# Entry point for CLI
def main(options: Dict[str, Any]):
    module = ExampleModule(options)
    asyncio.run(module.run())
    return module.results
```

### Module Registration

Modules are registered in `core/cli/parsers.py`:

```python
@app.command("example")
def example_cmd(
    url: str = typer.Option(..., help="Target URL"),
    threads: int = typer.Option(20, help="Thread count")
):
    """Example module description"""
    from modules import example_module
    example_module.main({"url": url, "threads": threads})
```

---

## Data Flow

### 1. Command Execution Flow

```
User Input
    ↓
CLI Parser (Typer/Interactive)
    ↓
Argument Validation (Validators)
    ↓
Module Selection (Module Registry)
    ↓
Module Execution
    ↓
Result Collection
    ↓
Output Formatting
    ↓
Export/Display
```

### 2. Interactive Mode Flow

```
User starts interactive shell
    ↓
Display banner and prompt
    ↓
User selects module (use <module>)
    ↓
Load module configuration
    ↓
User sets options (set <option> <value>)
    ↓
Validate options
    ↓
User runs module (run)
    ↓
Execute module
    ↓
Display results
    ↓
Return to prompt
```

### 3. Validation Flow

```
User Input
    ↓
CommandValidator.validate_module_options()
    ↓
Check required options
    ↓
Validate each option value
    ↓
Return validation result + errors + suggestions
```

---

## Design Patterns

### 1. Command Pattern

Used in interactive CLI for command handling:

```python
class InteractiveCLI(cmd.Cmd):
    def do_use(self, arg):
        """Select module"""
        pass
    
    def do_set(self, arg):
        """Set option"""
        pass
    
    def do_run(self, arg):
        """Execute module"""
        pass
```

### 2. Factory Pattern

Used in `HeaderFactory` for generating HTTP headers:

```python
class HeaderFactory:
    def generate_headers(self, profile: str) -> Dict[str, str]:
        """Generate headers based on profile"""
        pass
```

### 3. Strategy Pattern

Used for different export formats:

```python
class Exporter:
    def export(self, data, format: str):
        if format == "json":
            return self._export_json(data)
        elif format == "html":
            return self._export_html(data)
        elif format == "csv":
            return self._export_csv(data)
```

### 4. Singleton Pattern

Used for configuration and logger:

```python
class Config:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
```

---

## Performance Considerations

### 1. Async Operations

Modules use `asyncio` for concurrent operations:

```python
async def scan_multiple_targets(targets):
    tasks = [scan_target(t) for t in targets]
    results = await asyncio.gather(*tasks)
    return results
```

### 2. Rate Limiting

Prevents overwhelming targets:

```python
from tenacity import retry, wait_fixed

@retry(wait=wait_fixed(1))
async def make_request(url):
    # Request logic
    pass
```

### 3. Resource Management

Proper cleanup and resource management:

```python
async with aiohttp.ClientSession() as session:
    async with session.get(url) as response:
        return await response.text()
```

---

## Testing Architecture

### Test Structure

```
tests/
├── test_validators.py      # Validation tests
├── test_command_engine.py  # Command engine tests
├── test_cli.py             # CLI tests
├── test_exceptions.py      # Exception tests
└── test_bug_fixes.py       # Regression tests
```

### Test Coverage

- **Unit Tests**: Test individual components
- **Integration Tests**: Test component interactions
- **Regression Tests**: Prevent bug reintroduction

---

## Security Considerations

### 1. Input Validation

All user input is validated before use:

```python
url = Validator.validate_url(user_input)
```

### 2. Error Handling

Sensitive information is not exposed in errors:

```python
try:
    # Operation
except Exception as e:
    logger.error(f"Operation failed", exc_info=True)
    raise ModuleExecutionError("Operation failed")
```

### 3. Logging

Sensitive data is not logged:

```python
logger.info(f"Scanning target: {sanitize_url(url)}")
```

---

## Extension Points

### Adding a New Module

1. Create module file in `modules/`
2. Implement module class with `run()` method
3. Register command in `core/cli/parsers.py`
4. Add tests in `tests/`
5. Update documentation

### Adding a New Validator

1. Add method to `Validator` class in `core/validation/validators.py`
2. Add tests in `tests/test_validators.py`
3. Use in module option validation

---

<p align="center">
<a href="../../README.md">Back to Main README</a>
</p>
