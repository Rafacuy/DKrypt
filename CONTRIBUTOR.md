# DKrypt Contributor Guide

Welcome to the DKrypt project! We appreciate your interest in contributing to our penetration testing framework. This guide will help you get started with setting up your development environment, understanding the project structure, and making your first contribution.

## Table of Contents
- [DKrypt Contributor Guide](#dkrypt-contributor-guide)
  - [Table of Contents](#table-of-contents)
  - [1. Getting Started](#1-getting-started)
    - [Prerequisites](#prerequisites)
    - [Cloning the Repository](#cloning-the-repository)
    - [Setting Up Your Environment](#setting-up-your-environment)
  - [2. Project Structure](#2-project-structure)
  - [3. Contributing Guidelines](#3-contributing-guidelines)
    - [Coding Style](#coding-style)
    - [Adding New Modules](#adding-new-modules)
    - [Writing Tests](#writing-tests)
    - [Commit Messages](#commit-messages)
    - [Pull Request Process](#pull-request-process)
  - [4. Reporting Bugs / Suggesting Features](#4-reporting-bugs--suggesting-features)
  - [5. Contact and Supports](#5-contact-and-supports)

---

## 1. Getting Started

### Prerequisites
Before you begin, ensure you have the following installed:

*   **Python 3.10+**: Download from [python.org](https://www.python.org/downloads/)
*   **pip**: Python's package installer (usually comes with Python).
*   **git**: Version control system. Download from [git-scm.com](https://git-scm.com/downloads).

### Cloning the Repository
First, clone the DKrypt repository to your local machine:

```bash
git clone https://github.com/Rafacuy/DKrypt.git 
cd DKrypt
```

### Setting Up Your Environment
It's highly recommended to use a virtual environment to manage dependencies.

1.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    ```
2.  **Activate the virtual environment:**
    *   **Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    *   **macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 2. Project Structure

Here's an overview of the main directories and their purposes:

*   `core/`: Contains core functionalities like CLI parsing (`cli.py`), menu system (`menu.py`), and utility functions (`utils.py`).
*   `modules/`: Houses all the individual penetration testing modules (e.g., `sqli_scan.py`, `xss/`, `port_scanner.py`). Each module should ideally be self-contained or have its own subdirectory for related files.
*   `wordlists/`: Stores wordlists used by various modules (e.g., `subdomain.txt`, `directory-brute.txt`).
*   `reports/`: Default location for saving scan reports and results.
*   `dkrypt.py`: The main entry point of the application, handling the TUI and CLI modes.
*   `requirements.txt`: Lists all Python dependencies.

## 3. Contributing Guidelines

### Coding Style
*   Adhere to **PEP 8** for Python code style.
*   Maintain consistency with the existing codebase's formatting, naming conventions, and architectural patterns.
*   Use clear and descriptive variable and function names.
*   Add comments sparingly, focusing on *why* complex logic is implemented, not *what* it does.

### Adding New Modules
If you're adding a new penetration testing module:

1.  Create a new Python file or directory within the `modules/` directory.
2.  Implement the module's logic.
3.  **Integrate with `core/cli.py`:**
    *   Import your module at the top of `core/cli.py`.
    *   Create a new `add_yourmodule_parser(subparsers)` function to define its CLI arguments using `argparse`.
    *   Call your `add_yourmodule_parser` function within `create_parser()`.
    *   Add an `elif` condition in `run_cli()` to execute your module's main function when selected.
4.  **Integrate with `dkrypt.py` (TUI - if applicable):**
    *   Import your module.
    *   Add an option to the `MenuSystem` in `core/menu.py`.
    *   Add an `elif` condition in `run_tui()` to call your module's main function.
5.  Update `CLI-guide.md` with documentation for your new module.

### Writing Tests
While a dedicated testing framework isn't currently set up, we encourage writing unit tests for new features or bug fixes. Consider creating a `tests/` directory and using Python's `unittest` or `pytest` to ensure your code works as expected.

### Commit Messages
*   Write clear, concise, and descriptive commit messages.
*   Start with a verb in the imperative mood (e.g., "Fix: ", "Add: ", "Refactor: ").
*   Keep the subject line under 50 characters.
*   Provide a more detailed body if necessary, explaining the *why* behind the change.

### Pull Request Process
1.  **Fork** the repository.
2.  **Create a new branch** for your feature or bug fix (`git checkout -b feature/your-feature-name` or `bugfix/issue-description`).
3.  **Make your changes**, adhering to the coding style and guidelines.
4.  **Test your changes** thoroughly.
5.  **Commit your changes** with a clear commit message.
6.  **Push your branch** to your forked repository.
7.  **Open a Pull Request** to the `main` branch of the original DKrypt repository.
    *   Provide a clear title and description of your changes.
    *   Reference any related issues.

## 4. Reporting Bugs / Suggesting Features

If you find a bug or have a feature suggestion, please open an issue on the [GitHub Issues page](https://github.com/Rafacuy/DKrypt/issues). Please provide as much detail as possible, including steps to reproduce bugs, expected behavior, and screenshots if applicable.

## 5. Contact and Supports

If you have any questions or need further assistance, feel free to reach out to the project maintainers via GitHub issues or discussions.
