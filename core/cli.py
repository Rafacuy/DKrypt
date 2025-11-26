# core/cli.py
import sys
import asyncio
import json
import time
from datetime import datetime
from rich.console import Console

from modules import (
    subdomain, ssl_inspector,
    dir_bruteforcer, header_audit, port_scanner,
    cors_scan, sqli_scan, tracepulse, 
    jscrawler, py_obfuscator, graphql_introspect
)    
from modules.crawler_engine import crawler_utils
from modules.waf_bypass import tui
from modules.http_desync import main_runner
from modules.xss import scanner
from .utils import header_banner
from .banner import display_header
from .parsers import create_parser
from .logger import logger
from .exceptions import ValidationError, ModuleExecutionError
from .output import formatter, CommandResponse

console = Console()


def run_cli():
    """Run CLI mode with proper error handling and logging"""
    display_header()
    parser = create_parser()
    
    # Check if any arguments were passed. If not, print help and exit.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
        
    args = parser.parse_args()

    if args.interactive:
        return

    if args.module is None:
        parser.print_help()
        sys.exit(0)

    start_time = time.time()
    
    try:
        if args.module == "sqli":
            header_banner(tool_name="SQLi scanner")
            logger.info(f"Running SQLi scanner on {args.url}")
            sqli_scan.run_sqli_scan(args.url, args.test_forms, args.test_headers, args.test_apis, args.export)
            
        elif args.module == "xss":
            header_banner(tool_name="XSS scanner")
            logger.info(f"Running XSS scanner on {args.url}")
            asyncio.run(scanner.run_xss_scan(
                args.url, args.threads, args.rate_limit, args.max_payloads, 
                args.batch_size, args.smart_mode, args.stealth_mode, 
                args.test_headers, args.verbose
            ))
            
        elif args.module == "portscanner":
            header_banner(tool_name="Port Scanner")
            logger.info(f"Running port scanner")
            asyncio.run(port_scanner.main_menu(args))
            
        elif args.module == "waftester":
            header_banner(tool_name="WAF Tester")
            logger.info(f"Running WAF tester on {args.url}")
            app = tui.WAFTUI()
            app.run(args)
            
        elif args.module == "subdomain":
            header_banner(tool_name="Subdomain Scanner")
            logger.info(f"Running subdomain scanner on {args.target if hasattr(args, 'target') else 'multiple targets'}")
            
            # Handle scan mode flags
            if hasattr(args, 'api_only') and args.api_only:
                args.scan_mode = 'api_only'
            elif hasattr(args, 'bruteforce_only') and args.bruteforce_only:
                args.scan_mode = 'bruteforce_only'  
            else:
                args.scan_mode = 'hybrid'
            
            # Set performance parameters
            if not hasattr(args, 'rate_limit'):
                args.rate_limit = 200
            if not hasattr(args, 'dns_timeout'):
                args.dns_timeout = 2
            if not hasattr(args, 'dns_threads'):
                args.dns_threads = 200
                
            # Parse API keys if provided
            api_keys = {}
            if hasattr(args, 'api_keys') and args.api_keys:
                try:
                    api_keys = json.loads(args.api_keys)
                except json.JSONDecodeError:
                    raise ValidationError("Invalid JSON format for API keys", field="api_keys")
            args.api_keys = api_keys
            
            # Parse output formats
            if hasattr(args, 'output_formats') and args.output_formats:
                output_formats = [fmt.strip().lower() for fmt in args.output_formats.split(',')]
                valid_formats = ['json', 'csv', 'txt']
                output_formats = [fmt for fmt in output_formats if fmt in valid_formats]
                if not output_formats:
                    output_formats = ['json', 'csv', 'txt'] 
            else:
                output_formats = ['json', 'csv', 'txt']
            args.output_formats = output_formats
            
            # Validate proxy configuration
            if hasattr(args, 'proxy_type') and args.proxy_type and not hasattr(args, 'proxy_host'):
                raise ValidationError("--proxy-host is required when --proxy-type is specified", field="proxy_host")
            
            asyncio.run(subdomain.main_menu(args))
            
        elif args.module == "crawler":
            header_banner(tool_name="Website Crawler")
            logger.info(f"Running crawler")
            asyncio.run(crawler_utils.main(args))
            
        elif args.module == "headers":
            header_banner(tool_name="Headers Audit")
            logger.info(f"Running headers audit on {args.url if hasattr(args, 'url') else 'multiple targets'}")
            header_audit.HeaderAuditor().run(args)
            
        elif args.module == "graphql":
            header_banner(tool_name="GraphQL Introspection")
            logger.info(f"Running GraphQL introspection on {args.url}")
            graphql_introspect.run_cli(args)    
            
        elif args.module == "dirbrute":
            header_banner(tool_name="Dirbruteforcer")
            logger.info(f"Running directory brute forcer on {args.url}")
            dir_bruteforcer.main(args)
            
        elif args.module == "sslinspect":
            header_banner(tool_name="SSL/TLS Inspector")
            logger.info(f"Running SSL/TLS inspection on {args.target}")
            ssl_inspector.run_ssl_inspector(args)
            
        elif args.module == "corstest":
            header_banner(tool_name="CORS Tester")
            logger.info(f"Running CORS test on {args.url}")
            cors_scan.main(args)
            
        elif args.module == "smuggler":
            header_banner(tool_name="HTTP Desync Attack Tester")
            logger.info(f"Running HTTP desync test on {args.url}")
            main_runner.run(args)
            
        elif args.module == "tracepulse":
            header_banner(tool_name="Tracepulse")
            logger.info(f"Running tracepulse on {args.destination}")
            tracepulse.main(args)
            
        elif args.module == "js-crawler":
            header_banner("JS Crawler")
            logger.info(f"Running JS crawler on {args.url}")
            jscrawler.main(args)
            
        elif args.module == "py-obfuscator":
            header_banner("Py Obfuscator")
            logger.info(f"Running Python obfuscator on {args.input}")
            py_obfuscator.main(args)
            
        else:
            console.print(f"[red]Unknown module: {args.module}[/red]")
            logger.error(f"Unknown module: {args.module}")
            sys.exit(1)
        
        # Log successful completion
        elapsed_time = time.time() - start_time
        logger.info(f"Module {args.module} completed successfully in {elapsed_time:.2f}s")
        
    except ValidationError as e:
        console.print(f"\n[bold red]Validation Error: {e.message}[/bold red]")
        if e.field:
            console.print(f"[dim]Field: {e.field}[/dim]")
        logger.error(f"Validation error in {e.field}: {e.message}")
        sys.exit(1)
        
    except ModuleExecutionError as e:
        console.print(f"\n[bold red]Module Error: {e.message}[/bold red]")
        logger.error(f"Module {e.details.get('module')} failed: {e.message}")
        sys.exit(1)
        
    except Exception as e:
        elapsed_time = time.time() - start_time
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        logger.error(f"Unhandled exception in {args.module}: {str(e)}", exc_info=True)
        console.print("[dim]Check logs at .dkrypt/logs/ for more details[/dim]")
        sys.exit(1)