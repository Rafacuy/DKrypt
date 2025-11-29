# DKrypt Testing Guide

A comprehensive test suite is crucial for maintaining the quality, reliability, and stability of the DKrypt framework. This guide outlines how to run and write tests for the project.

## Testing Philosophy

We aim for a high level of test coverage to ensure that all core functionalities work as expected and that new changes do not introduce regressions. Our tests are built using the [pytest](https://docs.pytest.org/) framework.

Tests are divided into several categories:
-   **Unit Tests:** Testing individual functions and classes in isolation.
-   **Integration Tests:** Testing how different components of the framework work together.
-   **CLI Tests:** Testing the command-line interface to ensure commands, arguments, and outputs are correct.
-   **Bug Fix Tests:** Specific tests that replicate a reported bug and verify that it has been fixed.

## Setting Up the Test Environment

1.  Ensure you have checked out the repository and created a virtual environment.
2.  Install the required dependencies, including the testing tools:
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: `pytest` and related plugins are included in `requirements.txt`)*

## Running Tests

You can run the entire test suite from the root directory of the project.

### Running All Tests
To run all tests, simply execute `pytest`:
```bash
pytest
```
You should see output indicating the collection of tests and the status of each one (passing, failing, or skipped).

### Running Specific Tests
You can run a specific test file, or even a specific test function within a file.

- **Run a specific file:**
  ```bash
  pytest tests/test_cli.py
  ```
- **Run a specific test function by name:**
  ```bash
  pytest -k "test_sqli_command"
  ```
- **Run tests in verbose mode** to see more details:
  ```bash
  pytest -v
  ```

## Test Structure

All tests are located in the `tests/` directory. The file naming convention is `test_*.py`.

- `test_core_modules.py`: Tests for the core, non-CLI components of the framework.
- `test_cli.py`: Tests for the main Typer-based CLI commands and their arguments.
- `test_validators.py`: Tests for the input validation functions.
- `test_exceptions.py`: Tests for custom exception handling.
- `test_bug_fixes.py`: A collection of tests for specific bug fixes.

## Writing New Tests

When you contribute code, you are expected to add tests that cover your changes.

### General Guidelines
-   Name your test file starting with `test_`.
-   Name your test functions starting with `test_`.
-   Use descriptive names for your test functions (e.g., `test_subdomain_scanner_with_api_only_mode`).
-   Use `pytest`'s features like `fixtures` for setup/teardown code and `parametrize` for running the same test with different inputs.
-   Use the `mocker` fixture (from `pytest-mock`) to patch external dependencies like network requests or file system access. This makes your tests faster and more reliable.

### Example: Writing a Test for a New Validator

Let's say you've added a new validator in `core/validators.py` to check for valid IP addresses.

```python
# in core/validators.py
def is_valid_ip(ip: str) -> bool:
    # ... your implementation ...
```

You would then add a corresponding test in `tests/test_validators.py`:

```python
# in tests/test_validators.py
from core.validators import is_valid_ip

def test_is_valid_ip_with_valid_ipv4():
    """Test that a valid IPv4 address passes validation."""
    assert is_valid_ip("192.168.1.1") is True

def test_is_valid_ip_with_invalid_ipv4():
    """Test that an invalid IPv4 address fails validation."""
    assert is_valid_ip("999.999.999.999") is False

def test_is_valid_ip_with_valid_ipv6():
    """Test that a valid IPv6 address passes validation."""
    assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

def test_is_valid_ip_with_non_ip_string():
    """Test that a random string fails validation."""
    assert is_valid_ip("this-is-not-an-ip") is False
```
This ensures your new function is tested against both valid and invalid inputs.
