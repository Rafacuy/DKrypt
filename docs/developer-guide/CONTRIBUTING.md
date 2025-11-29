# Contributing to DKrypt

First off, thank you for considering contributing to DKrypt! We welcome contributions from everyone. This document provides guidelines to ensure a smooth and effective contribution process.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

There are many ways to contribute, from writing documentation to submitting new modules.

### Reporting Bugs
If you find a bug, please ensure it hasn't already been reported by searching the GitHub Issues. If you can't find an open issue addressing the problem, [open a new one](https://github.com/Rafacuy/DKrypt/issues/new). Be sure to include:
- A clear and descriptive title.
- A detailed description of the problem, including the exact command you ran.
- Steps to reproduce the bug.
- The expected behavior and what happened instead.
- Your operating system, Python version, and DKrypt version.

### Suggesting Enhancements
If you have an idea for a new feature or an improvement to an existing one:
- Open a new issue and use the "Feature Request" template.
- Clearly explain the feature and why it would be valuable to DKrypt users.
- Provide a use-case or example if possible.

### Submitting Pull Requests
This is the best way to contribute code.

1. **Fork the repository** to your own GitHub account.
2. **Clone your fork** to your local machine: `git clone https://github.com/YourUsername/DKrypt.git`
3. **Create a new branch** for your changes: `git checkout -b feature/my-new-feature` or `fix/bug-name`.
4. **Set up your development environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   pip install -r requirements.txt
   ```
5. **Make your changes.** Follow the code style guidelines below.
6. **Add tests** for your changes in the `tests/` directory. We strive for high test coverage.
7. **Ensure all tests pass:** Run `pytest` from the root directory.
8. **Commit your changes** with a clear and descriptive commit message. We follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.
   - Example: `feat(sqli): add new detection method for blind SQLi`
   - Example: `fix(xss): correctly handle nested forms`
   - Example: `docs(contributing): update guidelines for adding modules`
9. **Push your branch** to your fork: `git push origin feature/my-new-feature`
10. **Open a pull request** to the `main` branch of the `Rafacuy/DKrypt` repository.
11. **Provide a clear description** of the changes in the pull request. Link to any relevant issues.

## Development Guidelines

### Code Style
- We use **Black** for code formatting and **Flake8** for linting. Before committing, please run:
  ```bash
  black .
  flake8 .
  ```
- All code must be compatible with **Python 3.10+**.
- Use type hints wherever possible.
- Write clear, readable, and well-commented code, especially for complex logic.

### Adding a New Module
Adding a new security module is a great way to contribute. Here is the general process:

1. **Create your module file:** Add a new Python file in the `modules/` directory (e.g., `modules/new_scanner.py`). This file should contain the core logic for your tool. It's best to have a main function like `run_scan(...)` that takes all necessary parameters.

2. **Integrate with the CLI:** Open `core/cli/parsers.py`.
   - **Import your main function:** Add `from modules import new_scanner` at the top.
   - **Create a new Typer command:** Follow the existing structure to add a new `@app.command()` function.
     ```python
     @app.command("new-scanner", help="A brief, helpful description of your new scanner.")
     def new_scanner_cmd(
         # Use typer.Option and typer.Argument to define your CLI arguments
         target: str = typer.Option(..., "--target", help="The target for the new scanner."),
         verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output.")
     ):
         from core.utils import header_banner
         header_banner(tool_name="New Scanner")
         # Call your module's main function
         new_scanner.run_scan(target, verbose)
     ```

3. **Add Documentation:**
   - Add a section for your new module in `docs/user-guide/MODULES.md` with a description and example usage.
   - Add an entry for the command in `docs/user-guide/CLI-REFERENCE.md`.
   - Update the module table in the main `README.md`.

4. **Add Tests:**
   - Create a new test file in `tests/` (e.g., `tests/test_new_scanner.py`).
   - Write unit and integration tests for your module. Use `pytest` and mock external services where appropriate.

## Final Word
Your contributions are essential for making DKrypt a world-class security tool. Thank you for your time and effort!
