#!/usr/bin/env python3
"""
Central module registry for DKrypt CLI commands.

This registry keeps module option definitions and command wiring in one place,
making it easy to add or adjust modules without duplicating option logic.
The registry is designed to scale to dozens (or hundreds) of modules by
describing each module with a small, declarative spec.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

import typer
from rich.console import Console

from modules import (
    cors_scan,
    dir_bruteforcer,
    graphql_introspect,
    header_audit,
    jscrawler,
    port_scanner,
    py_obfuscator,
    sqli_scan,
    ssl_inspector,
    subdomain,
    tracepulse,
)
from modules.crawler_engine import crawler_utils
from modules.http_desync import main_runner
from modules.waf_bypass import tui
from modules.xss import scanner

console = Console()


# ---------------------------------------------------------------------------
# Option and module specs
# ---------------------------------------------------------------------------


@dataclass
class OptionSpec:
    name: str
    annotation: Any = str
    help: str = ""
    default: Any = None
    param_type: str = "option"  # option | argument
    required: bool = False
    choices: Optional[Sequence[Any]] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None

    def build_typer_parameter(self) -> inspect.Parameter:
        default_value = ... if (self.required and self.param_type == "option") else self.default

        if self.param_type == "argument":
            default_value = self.default if not self.required else ...
            param_default = typer.Argument(default_value, help=self.help)
        else:
            param_default = typer.Option(
                default_value,
                help=self.help,
                show_default=self.default is not None,
            )

        return inspect.Parameter(
            name=self.name,
            kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=param_default,
            annotation=self.annotation,
        )

    def add_to_argparse(self, parser: argparse.ArgumentParser) -> None:
        if self.param_type == "argument":
            kwargs = {"help": self.help}
            if not self.required:
                kwargs["nargs"] = "?"
                kwargs["default"] = self.default
            if self.annotation not in (None, bool):
                kwargs["type"] = self.annotation
            parser.add_argument(self.name, **kwargs)
            return

        flag = f"--{self.name.replace('_', '-')}"
        kwargs: Dict[str, Any] = {"help": self.help, "dest": self.name}

        if self.annotation is bool:
            # store_true for False defaults, store_false for True defaults
            kwargs["action"] = "store_true" if not self.default else "store_false"
            kwargs["default"] = self.default
        else:
            if self.required:
                kwargs["required"] = True
            if self.annotation is not None:
                kwargs["type"] = self.annotation
            if self.default is not None:
                kwargs["default"] = self.default
            if self.choices:
                kwargs["choices"] = self.choices

        parser.add_argument(flag, **kwargs)

    def validate(self, value: Any) -> None:
        if value is None:
            return

        if self.choices and value not in self.choices:
            raise typer.BadParameter(
                f"{self.name} must be one of: {', '.join(map(str, self.choices))}"
            )

        if self.min_value is not None and value < self.min_value:
            raise typer.BadParameter(f"{self.name} must be >= {self.min_value}")

        if self.max_value is not None and value > self.max_value:
            raise typer.BadParameter(f"{self.name} must be <= {self.max_value}")


@dataclass
class ModuleSpec:
    name: str
    help: str
    options: List[OptionSpec]
    runner: Callable[[Dict[str, Any]], None]
    validators: List[Callable[[Dict[str, Any]], None]] = field(default_factory=list)

    @property
    def signature(self) -> inspect.Signature:
        return inspect.Signature([option.build_typer_parameter() for option in self.options])

    def validate(self, values: Dict[str, Any]) -> None:
        for option in self.options:
            option.validate(values.get(option.name))
        for validator in self.validators:
            validator(values)

    def build_typer_handler(self) -> Callable[..., None]:
        def command_wrapper(**kwargs: Any) -> None:
            self.validate(kwargs)
            self.runner(kwargs)

        command_wrapper.__signature__ = self.signature  # type: ignore[attr-defined]
        command_wrapper.__name__ = f"{self.name}_command"
        return command_wrapper

    def add_to_argparse(self, subparsers: argparse._SubParsersAction) -> None:
        parser = subparsers.add_parser(self.name, help=self.help)
        for option in self.options:
            option.add_to_argparse(parser)


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _ensure_url(values: Dict[str, Any], key: str = "url") -> None:
    url = values.get(key)
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = None

    if not url or not parsed or parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise typer.BadParameter(f"Invalid URL for --{key.replace('_', '-')} (use http/https)")


def _ensure_json(values: Dict[str, Any], key: str) -> None:
    raw = values.get(key)
    if raw is None:
        return
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise typer.BadParameter(f"{key} must be valid JSON: {exc}")


def _ensure_port(values: Dict[str, Any], key: str = "port") -> None:
    port = values.get(key)
    if port is None:
        return
    if not 1 <= int(port) <= 65535:
        raise typer.BadParameter(f"{key} must be between 1 and 65535")


def _ensure_positive(values: Dict[str, Any], keys: Iterable[str]) -> None:
    for key in keys:
        value = values.get(key)
        if value is None:
            continue
        if value <= 0:
            raise typer.BadParameter(f"{key.replace('_', '-')} must be positive")


# ---------------------------------------------------------------------------
# Module runners
# ---------------------------------------------------------------------------


def _log_start(tool_name: str, message: str) -> None:
    from core.utils import header_banner
    from core.logger import logger

    header_banner(tool_name=tool_name)
    logger.info(message)


def run_sqli(values: Dict[str, Any]) -> None:
    _log_start("SQLi scanner", f"Running SQLi scanner on {values['url']}")
    sqli_scan.run_sqli_scan(
        values["url"],
        values["test_forms"],
        values["test_headers"],
        values["test_apis"],
        values["export"],
    )


def run_xss(values: Dict[str, Any]) -> None:
    _log_start("XSS scanner", f"Running XSS scanner on {values['url']}")
    asyncio.run(
        scanner.run_xss_scan(
            values["url"],
            values["threads"],
            values["rate_limit"],
            values["max_payloads"],
            values["batch_size"],
            values["smart_mode"],
            values["stealth_mode"],
            values["test_headers"],
            values["verbose"],
        )
    )


def run_graphql(values: Dict[str, Any]) -> None:
    _log_start("GraphQL Introspection", f"Running GraphQL introspection on {values['url']}")

    class Args:
        def __init__(self) -> None:
            self.url = values["url"]
            self.headers = values["headers"]
            self.timeout = values["timeout"]
            self.export = values["export"]
            self.output = values["output"]
            self.verbose = values["verbose"]
            self.export_raw = values["export_raw"]
            self.no_header_factory = values["no_header_factory"]
            self.header_pool_size = values["header_pool_size"]
            self.rotate_headers = values["rotate_headers"]

    graphql_introspect.run_cli(Args())


def run_portscanner(values: Dict[str, Any]) -> None:
    _log_start("Port Scanner", "Running port scanner")

    class Args:
        def __init__(self) -> None:
            self.command = values.get("command", "single")  # Default to "single" if not provided
            self.target = values.get("target")
            self.ports = values.get("ports", "1-1024")
            self.scan_type = values.get("scan_type", "SYN")
            self.timing = values.get("timing", "normal")
            self.service_detection = values.get("service_detection", False)
            self.os_detection = values.get("os_detection", False)
            self.script_scan = values.get("script_scan", "none")
            self.custom_args = values.get("custom_args", "")
            self.verbosity = values.get("verbosity", 1)
            self.output = values.get("output", "no")
            self.file = values.get("file")

    asyncio.run(port_scanner.main_menu(Args()))


def run_waftester(values: Dict[str, Any]) -> None:
    _log_start("WAF Tester", f"Running WAF tester on {values['url']}")

    import asyncio
    from modules.waf_bypass import tui

    # Create a new event loop in a separate thread to avoid asyncio conflicts
    def run_waftester_async():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            app_waf = tui.WAFTUI()
            # Use the new interactive CLI method which has better helper functionality
            app_waf.run_interactive_cli(values=values)
        finally:
            loop.close()

    import threading
    thread = threading.Thread(target=run_waftester_async)
    thread.start()
    thread.join()


def run_subdomain(values: Dict[str, Any]) -> None:
    scan_mode = (
        "api_only"
        if values["api_only"]
        else "bruteforce_only" if values["bruteforce_only"] else "hybrid"
    )

    api_keys = json.loads(values["api_keys"]) if values.get("api_keys") else {}

    _log_start(
        "Subdomain Scanner",
        f"Running subdomain scanner on {values.get('target') or 'multiple targets'}",
    )

    class Args:
        def __init__(self) -> None:
            self.command = values.get("command", "single")  # Default to "single" if not provided
            self.target = values.get("target")
            self.scan_mode = scan_mode
            self.rate_limit = values.get("rate_limit", 200)
            self.dns_timeout = values.get("dns_timeout", 2)
            self.dns_threads = values.get("dns_threads", 200)
            self.api_keys = api_keys
            self.proxy_type = values.get("proxy_type")
            self.proxy_host = values.get("proxy_host")
            self.proxy_port = values.get("proxy_port")
            self.wordlist = values.get("wordlist", "wordlists/subdomain.txt")
            self.output_formats = values.get("output_formats", "json,csv,txt")
            self.file = values.get("file")

    asyncio.run(subdomain.main_menu(Args()))


def run_crawler(values: Dict[str, Any]) -> None:
    _log_start("Website Crawler", "Running crawler")

    class Args:
        def __init__(self) -> None:
            self.command = values.get("command", "single")  # Default to "single" if not provided
            self.url = values.get("url")
            self.depth = values.get("depth", 3)
            self.concurrency = values.get("concurrency", 10)
            self.max_urls = values.get("max_urls", 100)
            self.js_render = values.get("js_render", False)
            self.no_robots = values.get("no_robots", False)
            self.output = values.get("output")
            self.file = values.get("file")
            self.output_file = values.get("output_file")

    asyncio.run(crawler_utils.main(Args()))


def run_headers(values: Dict[str, Any]) -> None:
    _log_start(
        "Headers Audit", f"Running headers audit on {values.get('url') or 'multiple targets'}"
    )

    class Args:
        def __init__(self) -> None:
            self.command = values.get("command", "single")  # Default to "single" if not provided
            self.url = values.get("url")
            self.verbose = values.get("verbose", False)
            self.allow_private = values.get("allow_private", False)
            self.timeout = values.get("timeout", 15)
            self.file = values.get("file")

    header_audit.HeaderAuditor().run(Args())


def run_dirbrute(values: Dict[str, Any]) -> None:
    _log_start("Dirbruteforcer", f"Running directory brute forcer on {values['url']}")
    dir_bruteforcer.main(values)


def run_sslinspect(values: Dict[str, Any]) -> None:
    _log_start("SSL/TLS Inspector", f"Running SSL/TLS inspection on {values['target']}")

    class Args:
        def __init__(self) -> None:
            self.target = values["target"]
            self.export = values["export"]
            self.verbose = values["verbose"]

    ssl_inspector.run_ssl_inspector(Args())


def run_corstest(values: Dict[str, Any]) -> None:
    _log_start("CORS Tester", f"Running CORS test on {values['url']}")
    cors_scan.main(values["url"], values["export"], values["verbose"], values["custom_origin"])


def run_smuggler(values: Dict[str, Any]) -> None:
    _log_start("HTTP Desync Attack Tester", f"Running HTTP desync test on {values['url']}")

    # Create an args object that matches what the smuggler module expects
    class Args:
        def __init__(self):
            self.url = values["url"]
            self.port = values["port"]
            self.headers = values.get("headers", "")  # Adding the headers parameter that might be expected

    main_runner.run(Args())


def run_tracepulse(values: Dict[str, Any]) -> None:
    _log_start("Tracepulse", f"Running tracepulse on {values['destination']}")

    # Create an args object that matches what the tracepulse module expects
    class Args:
        def __init__(self):
            self.destination = values["destination"]
            self.protocol = values["protocol"]
            self.max_hops = values["max_hops"]
            self.port = values["port"]
            # Adding other potential parameters that the tracepulse module might expect
            self.timeout = values.get("timeout", 2)
            self.probe_delay = values.get("probe_delay", 0.1)
            self.save = values.get("save", False)
            self.output = values.get("output", "results.json")
            self.allow_private = values.get("allow_private", False)

    tracepulse.main(Args())


def run_jscrawler(values: Dict[str, Any]) -> None:
    _log_start("JS Crawler", f"Running JS crawler on {values['url']}")
    jscrawler.main(
        url=values["url"],
        output=values["output"],
        depth=values["depth"],
        selenium=values["selenium"],
        extensions=values["extensions"],
        user_agent=values["user_agent"],
    )


def run_py_obfuscator(values: Dict[str, Any]) -> None:
    _log_start("Py Obfuscator", f"Running Python obfuscator on {values['input']}")

    # Create an args object that matches what the py_obfuscator module expects
    class Args:
        def __init__(self):
            self.input = values["input"]
            self.output = values["output"]
            # Ensure level is converted to int to prevent type errors in py_obfuscator
            try:
                self.level = int(values["level"]) if values["level"] is not None else 2
            except (ValueError, TypeError):
                self.level = 2  # Default to standard protection level
            self.rename_vars = values["rename_vars"]
            self.rename_funcs = values["rename_funcs"]
            self.flow_obfuscation = values["flow_obfuscation"]
            # Adding potential additional attributes that might be expected
            self.key = values.get("key")

    py_obfuscator.main(Args())


# ---------------------------------------------------------------------------
# Registry setup
# ---------------------------------------------------------------------------


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: List[ModuleSpec] = []

    @property
    def modules(self) -> List[ModuleSpec]:
        return self._modules

    def add(self, spec: ModuleSpec) -> None:
        self._modules.append(spec)

    def register_with_typer(self, app: typer.Typer) -> None:
        for spec in self._modules:
            app.command(spec.name, help=spec.help)(spec.build_typer_handler())

    def create_argparse_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="dkrypt",
            description="DKrypt - Advanced Penetration Testing Framework",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        subparsers = parser.add_subparsers(dest="command", help="Available modules", metavar="MODULE")
        for spec in self._modules:
            spec.add_to_argparse(subparsers)
        return parser


registry = ModuleRegistry()


def _add_modules() -> None:
    registry.add(
        ModuleSpec(
            name="sqli",
            help="SQL Injection Scanner",
            options=[
                OptionSpec("url", str, "Target URL", required=True),
                OptionSpec("test_forms", bool, "Enable testing of POST forms", default=False),
                OptionSpec("test_headers", bool, "Enable testing of HTTP headers", default=False),
                OptionSpec("test_apis", bool, "Enable testing of API endpoints", default=False),
                OptionSpec(
                    "export",
                    str,
                    "Export format: html, csv, or none",
                    default="html",
                    choices=["html", "csv", "none"],
                ),
            ],
            runner=run_sqli,
            validators=[lambda values: _ensure_url(values, "url")],
        )
    )

    registry.add(
        ModuleSpec(
            name="xss",
            help="XSS Scanner",
            options=[
                OptionSpec("url", str, "Target URL", required=True),
                OptionSpec("threads", int, "Number of concurrent threads", default=20, min_value=1),
                OptionSpec("rate_limit", int, "Requests per second", default=5, min_value=1),
                OptionSpec("max_payloads", int, "Maximum XSS payloads per context", default=15, min_value=1),
                OptionSpec("batch_size", int, "Payloads per batch", default=100, min_value=1),
                OptionSpec("smart_mode", bool, "Enable smart mode", default=False),
                OptionSpec("stealth_mode", bool, "Enable stealth mode", default=False),
                OptionSpec("test_headers", bool, "Test HTTP headers", default=False),
                OptionSpec("verbose", bool, "Verbose output", default=False),
            ],
            runner=run_xss,
            validators=[lambda values: _ensure_url(values, "url")],
        )
    )

    registry.add(
        ModuleSpec(
            name="graphql",
            help="GraphQL endpoint analysis and vulnerability detection",
            options=[
                OptionSpec("url", str, "GraphQL endpoint URL", required=True),
                OptionSpec("headers", str, "Custom headers as JSON", default="{}"),
                OptionSpec("timeout", int, "Request timeout in seconds", default=30, min_value=1),
                OptionSpec("export", str, "Export formats (comma-separated)", default="json,csv,txt"),
                OptionSpec("output", Optional[str], "Output filename prefix", default=None),
                OptionSpec("verbose", bool, "Verbose output", default=False),
                OptionSpec("export_raw", bool, "Export raw response on failure", default=False),
                OptionSpec("no_header_factory", bool, "Disable HeaderFactory", default=False),
                OptionSpec("header_pool_size", Optional[int], "HeaderFactory pool size", default=None),
                OptionSpec("rotate_headers", bool, "Enable header rotation", default=False),
            ],
            runner=run_graphql,
            validators=[lambda values: _ensure_url(values, "url"), lambda values: _ensure_json(values, "headers")],
        )
    )

    registry.add(
        ModuleSpec(
            name="portscanner",
            help="Port Scanner",
            options=[
                OptionSpec("command", str, "Subcommand: single or batch", param_type="argument", required=True),
                OptionSpec("target", Optional[str], "Target host", default=None),
                OptionSpec("ports", str, "Ports to scan", default="1-1024"),
                OptionSpec("scan_type", str, "Scan type: SYN, CON, or UDP", default="SYN", choices=["SYN", "CON", "UDP"]),
                OptionSpec("timing", str, "Timing profile", default="normal"),
                OptionSpec("service_detection", bool, "Enable service detection", default=False),
                OptionSpec("os_detection", bool, "Enable OS detection", default=False),
                OptionSpec("script_scan", str, "NSE scan: default, vuln, or none", default="none"),
                OptionSpec("custom_args", str, "Custom NMAP arguments", default=""),
                OptionSpec("verbosity", int, "Verbosity level (0-2)", default=1, min_value=0, max_value=2),
                OptionSpec("output", str, "Output format: json, csv, or no", default="no"),
                OptionSpec("file", Optional[str], "File with target hosts", default=None),
            ],
            runner=run_portscanner,
        )
    )

    registry.add(
        ModuleSpec(
            name="waftester",
            help="WAF Bypass Tester",
            options=[
                OptionSpec("url", str, "Target URL", required=True),
                OptionSpec("method", str, "HTTP method", default="GET"),
                OptionSpec("packs", Optional[str], "Header packs", default=None),
                OptionSpec("custom_headers", Optional[str], "Custom headers as JSON", default=None),
                OptionSpec("concurrency", int, "Concurrent requests", default=10, min_value=1),
                OptionSpec("timeout", int, "Request timeout", default=10, min_value=1),
                OptionSpec("jitter", float, "Delay between requests", default=0.1, min_value=0),
                OptionSpec("verify_tls", bool, "Verify TLS certificates", default=False),
                OptionSpec("profile", Optional[str], "Profile name", default=None),
                OptionSpec("export", str, "Export format", default="both"),
            ],
            runner=run_waftester,
            validators=[lambda values: _ensure_url(values, "url"), lambda values: _ensure_json(values, "custom_headers")],
        )
    )

    registry.add(
        ModuleSpec(
            name="subdomain",
            help="Subdomain Enumeration",
            options=[
                OptionSpec("command", str, "Subcommand: single or batch", param_type="argument", required=True),
                OptionSpec("target", Optional[str], "Target domain", default=None),
                OptionSpec("api_only", bool, "Use only API sources", default=False),
                OptionSpec("bruteforce_only", bool, "Use only wordlist bruteforce", default=False),
                OptionSpec("rate_limit", int, "Concurrent DNS queries", default=200, min_value=1),
                OptionSpec("dns_timeout", int, "DNS timeout in seconds", default=2, min_value=1),
                OptionSpec("dns_threads", int, "DNS thread pool size", default=200, min_value=1),
                OptionSpec("api_keys", Optional[str], "API keys as JSON", default=None),
                OptionSpec("proxy_type", Optional[str], "Proxy type", default=None),
                OptionSpec("proxy_host", Optional[str], "Proxy host", default=None),
                OptionSpec("proxy_port", Optional[int], "Proxy port", default=None, min_value=1, max_value=65535),
                OptionSpec("wordlist", str, "Wordlist file", default="wordlists/subdomain.txt"),
                OptionSpec("output_formats", str, "Output formats", default="json,csv,txt"),
                OptionSpec("file", Optional[str], "File with target domains", default=None),
            ],
            runner=run_subdomain,
            validators=[lambda values: _ensure_json(values, "api_keys")],
        )
    )

    registry.add(
        ModuleSpec(
            name="crawler",
            help="Web Crawler",
            options=[
                OptionSpec("command", str, "Subcommand: single or batch", param_type="argument", required=True),
                OptionSpec("url", Optional[str], "Starting URL", default=None),
                OptionSpec("depth", int, "Crawl depth", default=3, min_value=1),
                OptionSpec("concurrency", int, "Concurrent requests", default=10, min_value=1),
                OptionSpec("max_urls", int, "Maximum URLs to crawl", default=100, min_value=1),
                OptionSpec("js_render", bool, "Enable JavaScript rendering", default=False),
                OptionSpec("no_robots", bool, "Ignore robots.txt", default=False),
                OptionSpec("output", Optional[str], "Output format", default=None),
                OptionSpec("file", Optional[str], "File with URLs", default=None),
                OptionSpec("output_file", Optional[str], "Output file path", default=None),
            ],
            runner=run_crawler,
        )
    )

    registry.add(
        ModuleSpec(
            name="headers",
            help="Header Audit",
            options=[
                OptionSpec("command", str, "Subcommand: single or batch", param_type="argument", required=True),
                OptionSpec("url", Optional[str], "Target URL", default=None),
                OptionSpec("verbose", bool, "Verbose output", default=False),
                OptionSpec("allow_private", bool, "Allow private IPs", default=False),
                OptionSpec("timeout", int, "Request timeout", default=15, min_value=1),
                OptionSpec("file", Optional[str], "File with URLs", default=None),
            ],
            runner=run_headers,
        )
    )

    registry.add(
        ModuleSpec(
            name="dirbrute",
            help="Dirbrute: Directory and file brute-forcer",
            options=[
                OptionSpec("url", str, "Base URL", required=True),
                OptionSpec("wordlist", str, "Wordlist file", default="wordlists/directory-brute.txt"),
                OptionSpec("threads", int, "Concurrent threads", default=10, min_value=1),
                OptionSpec("extensions", str, "File extensions", default=".php,.html,.js,.css,.txt,.zip,.bak,.sql"),
                OptionSpec("status_codes", str, "Valid status codes", default="200,204,301,302,403"),
                OptionSpec("timeout", int, "Request timeout", default=10, min_value=1),
                OptionSpec("delay", float, "Delay between requests", default=0.0, min_value=0),
                OptionSpec("output", Optional[str], "Output file", default=None),
                OptionSpec("verbose", bool, "Verbose output", default=False),
            ],
            runner=run_dirbrute,
            validators=[lambda values: _ensure_url(values, "url")],
        )
    )

    registry.add(
        ModuleSpec(
            name="sslinspect",
            help="SSL/TLS Certificate Inspector",
            options=[
                OptionSpec("target", str, "Target host:port", required=True),
                OptionSpec("export", str, "Export format: json or txt", default="json", choices=["json", "txt"]),
                OptionSpec("verbose", bool, "Verbose output", default=False),
            ],
            runner=run_sslinspect,
        )
    )

    registry.add(
        ModuleSpec(
            name="corstest",
            help="CORS Misconfiguration Auditor",
            options=[
                OptionSpec("url", str, "Target URL", required=True),
                OptionSpec("export", str, "Export format", default="json", choices=["json", "txt"]),
                OptionSpec("verbose", bool, "Verbose output", default=False),
                OptionSpec("custom_origin", Optional[str], "Custom origin header", default=None),
            ],
            runner=run_corstest,
            validators=[lambda values: _ensure_url(values, "url")],
        )
    )

    registry.add(
        ModuleSpec(
            name="smuggler",
            help="HTTP Request Smuggling Tester",
            options=[
                OptionSpec("url", str, "Target URL", required=True),
                OptionSpec("port", int, "Target port", default=80, min_value=1, max_value=65535),
                OptionSpec("method", str, "HTTP method", default="GET", choices=["GET", "POST"]),
                OptionSpec("verbose", bool, "Verbose output", default=False),
            ],
            runner=run_smuggler,
            validators=[lambda values: _ensure_url(values, "url")],
        )
    )

    registry.add(
        ModuleSpec(
            name="tracepulse",
            help="Network Traceroute Utility",
            options=[
                OptionSpec("destination", str, "Target host/IP", required=True),
                OptionSpec("protocol", str, "Protocol", default="icmp", choices=["icmp", "tcp", "udp"]),
                OptionSpec("max_hops", int, "Maximum hops", default=30, min_value=1),
                OptionSpec("port", int, "Target port", default=33434, min_value=1, max_value=65535),
            ],
            runner=run_tracepulse,
        )
    )

    registry.add(
        ModuleSpec(
            name="js-crawler",
            help="JavaScript File Crawler and Endpoint Extractor",
            options=[
                OptionSpec("url", str, "Target URL", required=True),
                OptionSpec("output", Optional[str], "Output file", default=None),
                OptionSpec("depth", int, "Crawl depth", default=3, min_value=1),
                OptionSpec("selenium", bool, "Use Selenium", default=False),
                OptionSpec("extensions", str, "File extensions", default=".js"),
                OptionSpec(
                    "user_agent",
                    str,
                    "User agent string for requests",
                    default=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/91.0.4472.124 Safari/537.36"
                    ),
                ),
            ],
            runner=run_jscrawler,
            validators=[lambda values: _ensure_url(values, "url")],
        )
    )

    registry.add(
        ModuleSpec(
            name="py-obfuscator",
            help="Python Code Obfuscator",
            options=[
                OptionSpec("input", str, "Input Python file", required=True),
                OptionSpec("output", Optional[str], "Output file", default=None),
                OptionSpec("level", int, "Obfuscation level (1-3)", default=2, min_value=1, max_value=3),
                OptionSpec("rename_vars", bool, "Rename variables", default=True),
                OptionSpec("rename_funcs", bool, "Rename functions", default=True),
                OptionSpec("flow_obfuscation", bool, "Apply flow obfuscation", default=True),
            ],
            runner=run_py_obfuscator,
        )
    )


_add_modules()
