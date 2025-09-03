# modules/waf_bypass/tui.py
"""
Main entry point for the WAF Bypass Tester application.
This file contains the Terminal User Interface (TUI) and runs the main application loop.
"""

import asyncio
import time
import json
import os
import sys
from urllib.parse import urlparse
from typing import List, Dict, Optional

from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from .waf_runner import WAFBypassTester, TestResult
from engine.baseline import BaselineCapture
from .waf_utils import ScanResults, PROFILES_DIR, console, clear_console
from core.utils import clear_console, header_banner

class WAFTUI:
    """Terminal User Interface"""
    
    def __init__(self):
        self.tester = WAFBypassTester()
        self.url: Optional[str] = None
        self.method: str = "GET"
        self.selected_packs: List[str] = []
        self.custom_headers: List[Dict[str, str]] = []
    
    def run(self):
        """Main application entry point"""
        try:
            self._main_loop()
        except KeyboardInterrupt:
            console.print("\n[bold yellow]👋 Goodbye![/bold yellow]")
        except Exception as e:
            console.print(f"\n[bold red]❌ Error: {e}[/bold red]")
    
    def _main_loop(self):
        """Main application loop"""
        clear_console()
        header_banner(tool_name="WAF Bypass Tester")
        
        if not self._configure_target():
            return
        
        while True:
            self._show_dashboard()
            choice = Prompt.ask(
                "Choose an action",
                choices=["1", "2", "3", "4", "5", "6", "s", "q"],
                default="s"
            )
            
            if choice == "1":
                self._select_header_packs()
            elif choice == "2":
                self._manage_custom_headers()
            elif choice == "3":
                self._configure_settings()
            elif choice == "4":
                self._load_profile()
            elif choice == "5":
                self._save_profile()
            elif choice == "6":
                self._view_results()
            elif choice.lower() == "s":
                asyncio.run(self._start_pipeline())
            elif choice.lower() == "q":
                break
    
    def _show_header(self):
        """Display application header"""
        clear_console()
        header_text = Text("WAF Bypass Tester", style="bold cyan")
        console.print(Panel(header_text, border_style="blue"))
    
    def _configure_target(self) -> bool:
        """Configure target URL and method"""
        self.url = Prompt.ask(
            "[bold]🎯 Target URL[/bold]",
            default="https://example.com/admin"
        )
        
        if not (self.url.startswith("http://") or self.url.startswith("https://")):
            self.url = "https://" + self.url
        
        self.method = Prompt.ask(
            "[bold]📡 HTTP Method[/bold]",
            choices=["GET", "POST", "PUT", "DELETE"],
            default="GET"
        )
        
        return True
    
    def _show_dashboard(self):
        """Display main dashboard"""
        self._show_header()
        
        # Target info
        console.print(f"🎯 [bold]Target:[/bold] {self.url} ([cyan]{self.method}[/cyan])")
        
        # Configuration status
        config_table = Table.grid(padding=(0, 2))
        config_table.add_column(style="bold")
        config_table.add_column()
        
        packs_status = f"[green]{len(self.selected_packs)} packs[/green]" if self.selected_packs else "[dim]None[/dim]"
        custom_status = f"[green]{len(self.custom_headers)} headers[/green]" if self.custom_headers else "[dim]None[/dim]"
        
        config_table.add_row("Header Packs:", packs_status)
        config_table.add_row("Custom Headers:", custom_status)
        config_table.add_row("Concurrency:", f"{self.tester.config['max_concurrency']}")
        config_table.add_row("TLS Verify:", f"{'✅' if self.tester.config['verify_tls'] else '❌'}")
        
        console.print(Panel(config_table, title="Configuration", border_style="blue"))
        
        # Actions menu
        actions = Table.grid(padding=(0, 1))
        actions.add_column(style="yellow bold")
        actions.add_column()
        
        actions.add_row("[1]", "Select Header Packs")
        actions.add_row("[2]", "Manage Custom Headers")
        actions.add_row("[3]", "Configure Settings")
        actions.add_row("[4]", "Load Profile")
        actions.add_row("[5]", "Save Profile")
        actions.add_row("[6]", "View Last Results")
        actions.add_row("")
        actions.add_row("[S]", "[bold green]🚀 START TEST[/bold green]")
        actions.add_row("[Q]", "Quit")
        
        console.print(Panel(actions, title="Actions", border_style="green"))
    
    def _select_header_packs(self):
        """Select predefined header packs"""
        console.print("\n--- [bold]Header Pack Selection[/bold] ---")
        console.print("[dim]Available packs with their purposes:[/dim]\n")
        
        pack_info = {
            'identity_spoof': 'IP spoofing and client identity manipulation',
            'routing_path': 'Host and path routing bypass attempts',
            'parser_tricks': 'Content-type and encoding manipulation',
            'tool_evasion': 'User-agent and request fingerprint evasion',
            'advanced_evasion': 'Advanced techniques to bypass WAF header parser',
            'api_gateway': 'API gateway & cloud environment bypass using custom headers',
            'cdn_headers': 'CDN & Cache bypass using cache mechanism',
            'protocol_anomalies': 'HTTP anomaly protocol',
            'mobile_headers': 'Mobile device headers'
        }
        
        table = Table()
        table.add_column("Pack", style="cyan bold")
        table.add_column("Description")
        table.add_column("Selected", justify="center")
        
        for pack, desc in pack_info.items():
            selected = "✅" if pack in self.selected_packs else "❌"
            table.add_row(pack, desc, selected)
        
        console.print(table)
        
        selection = Prompt.ask(
            "\n[bold]Enter pack names (comma-separated) or 'all'[/bold]",
            default=",".join(self.selected_packs)
        )
        
        if selection.lower() == "all":
            self.selected_packs = list(pack_info.keys())
        else:
            selected = [p.strip() for p in selection.split(",") if p.strip() in pack_info]
            self.selected_packs = selected
        
        console.print(f"[green]✅ Selected: {self.selected_packs}[/green]")
        time.sleep(1)
    
    def _manage_custom_headers(self):
        """Manage custom header definitions"""
        while True:
            console.print("\n--- [bold]Custom Headers[/bold] ---")
            
            if not self.custom_headers:
                console.print("[dim]No custom headers defined.[/dim]")
            else:
                table = Table()
                table.add_column("#", style="cyan")
                table.add_column("Header", style="magenta")
                table.add_column("Value")
                
                for i, header in enumerate(self.custom_headers, 1):
                    key, value = list(header.items())[0]
                    table.add_row(str(i), key, value)
                
                console.print(table)
            
            action = Prompt.ask(
                "\n[bold]Action[/bold]",
                choices=["a", "d", "c", "b"],
                default="b"
            )
            
            if action == "a":  # Add
                key = Prompt.ask("Header name (e.g., X-Custom-Bypass)")
                value = Prompt.ask(f"Value for {key}")
                if key and value:
                    self.custom_headers.append({key: value})
                    console.print(f"[green]✅ Added {key}[/green]")
            
            elif action == "d":  # Delete
                if self.custom_headers:
                    choices = [str(i) for i in range(1, len(self.custom_headers) + 1)]
                    idx = int(Prompt.ask("Enter number to delete", choices=choices))
                    deleted = self.custom_headers.pop(idx - 1)
                    console.print(f"[red]🗑️ Deleted {list(deleted.keys())[0]}[/red]")
            
            elif action == "c":  # Clear
                if Confirm.ask("[yellow]Clear all custom headers?[/yellow]"):
                    self.custom_headers.clear()
                    console.print("[red]🗑️ All custom headers cleared[/red]")
            
            elif action == "b":  # Back
                break
    
    def _configure_settings(self):
        """Configure advanced settings"""
        console.print("\n--- [bold]Advanced Settings[/bold] ---")
        
        settings_table = Table()
        settings_table.add_column("Setting", style="bold")
        settings_table.add_column("Current Value", style="cyan")
        settings_table.add_column("Description")
        
        settings_table.add_row("Max Concurrency", str(self.tester.config['max_concurrency']), "Parallel requests")
        settings_table.add_row("Timeout", f"{self.tester.config['timeout']}s", "Request timeout")
        settings_table.add_row("Jitter", f"{self.tester.config['jitter']}s", "Random delay between requests")
        settings_table.add_row("TLS Verify", str(self.tester.config['verify_tls']), "Verify SSL certificates")
        
        console.print(settings_table)
        
        if Confirm.ask("\n[bold]Modify settings?[/bold]"):
            self.tester.config['max_concurrency'] = int(Prompt.ask(
                "Max Concurrency", default=str(self.tester.config['max_concurrency'])
            ))
            self.tester.config['timeout'] = int(Prompt.ask(
                "Timeout (seconds)", default=str(self.tester.config['timeout'])
            ))
            self.tester.config['jitter'] = float(Prompt.ask(
                "Jitter (seconds)", default=str(self.tester.config['jitter'])
            ))
            self.tester.config['verify_tls'] = Confirm.ask(
                "Verify TLS certificates?", default=self.tester.config['verify_tls']
            )
            
            console.print("[green]✅ Settings updated[/green]")
        
        time.sleep(1)
    
    def _save_profile(self):
        """Save current configuration to profile"""
        if not self.url:
            console.print("[red]❌ No target configured[/red]")
            return
        
        profile_name = Prompt.ask(
            "Profile name",
            default=urlparse(self.url).netloc.replace('.', '_')
        )
        
        if not profile_name:
            return
        
        profile_data = {
            "url": self.url,
            "method": self.method,
            "selected_packs": self.selected_packs,
            "custom_headers": self.custom_headers,
            "config": self.tester.config
        }
        
        filepath = os.path.join(PROFILES_DIR, f"{profile_name}.json")
        with open(filepath, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        console.print(f"[green]✅ Profile saved: {filepath}[/green]")
        time.sleep(1)
    
    def _load_profile(self):
        """Load configuration from profile"""
        profiles = [f.replace('.json', '') for f in os.listdir(PROFILES_DIR) if f.endswith('.json')]
        
        if not profiles:
            console.print("[yellow]⚠️ No profiles found[/yellow]")
            time.sleep(1)
            return
        
        profile_name = Prompt.ask("Select profile", choices=profiles)
        filepath = os.path.join(PROFILES_DIR, f"{profile_name}.json")
        
        with open(filepath, 'r') as f:
            profile_data = json.load(f)
        
        self.url = profile_data.get("url")
        self.method = profile_data.get("method", "GET")
        self.selected_packs = profile_data.get("selected_packs", [])
        self.custom_headers = profile_data.get("custom_headers", [])
        
        if "config" in profile_data:
            self.tester.config.update(profile_data["config"])
        
        console.print(f"[green]✅ Profile '{profile_name}' loaded[/green]")
        time.sleep(1)
    
    async def _start_pipeline(self):
        """Execute the complete testing pipeline"""
        if not self.selected_packs and not self.custom_headers:
            console.print("[red]❌ No tests configured! Select header packs or add custom headers.[/red]")
            time.sleep(2)
            return
        
        try:
            results = await self.tester.run_pipeline(
                self.url,
                self.method,
                self.selected_packs,
                self.custom_headers
            )
            
            self._display_pipeline_results(results)
            
        except Exception as e:
            console.print(f"[bold red]❌ Pipeline failed: {e}[/bold red]")
            time.sleep(2)
    
    def _display_pipeline_results(self, results: ScanResults):
        """Display comprehensive pipeline results"""
        console.print("\n" + "="*60)
        console.print("🎉 [bold green]Pipeline Complete![/bold green]")
        console.print("="*60)
        
        # WAF Fingerprint Summary
        waf = results.waf_fingerprint
        if waf.detected:
            vendor_text = f" - {waf.vendor.upper()}" if waf.vendor else ""
            console.print(f"🛡️ [bold red]WAF Detected{vendor_text}[/bold red] (Confidence: {waf.confidence:.1%})")
            console.print(f"   Blocking Behavior: {waf.blocking_behavior}")
        else:
            console.print("🔓 [bold green]No WAF Detected[/bold green]")
        
        # Results Summary
        total_tests = len(results.tests)
        bypasses_found = sum(1 for t in results.tests if t.bypass_confirmed)
        high_scores = sum(1 for t in results.tests if t.bypass_score >= 50)
        
        summary_table = Table.grid(padding=(0, 2))
        summary_table.add_column(style="bold")
        summary_table.add_column()
        
        summary_table.add_row("Total Tests:", str(total_tests))
        summary_table.add_row("High Scores (≥50):", f"[yellow]{high_scores}[/yellow]")
        summary_table.add_row("Confirmed Bypasses:", f"[red]{bypasses_found}[/red]" if bypasses_found else f"[green]{bypasses_found}[/green]")
        
        console.print(Panel(summary_table, title="📊 Summary", border_style="blue"))
        
        # Top Results Table
        top_results = sorted(results.tests, key=lambda x: x.bypass_score, reverse=True)[:10]
        
        results_table = Table(title="🏆 Top 10 Results by Score")
        results_table.add_column("ID", style="cyan")
        results_table.add_column("Test Name")
        results_table.add_column("Score", justify="right")
        results_table.add_column("Status", justify="center")
        results_table.add_column("Confirmed", justify="center")
        results_table.add_column("Key Signals")
        
        for result in top_results:
            score_style = "red" if result.bypass_score >= 70 else "yellow" if result.bypass_score >= 50 else "dim"
            confirmed_icon = "🔥" if result.bypass_confirmed else "❓" if result.bypass_score >= 50 else "❌"
            
            try:
                test_name = result.name.encode('ascii', 'ignore').decode('ascii')

                test_id = str(result.test_id).encode('ascii', 'ignore').decode('ascii')

                clean_signals = []
                for signal in result.contributing_signals[:2]:
                    clean_signal = signal.encode('ascii', 'ignore').decode('ascii')
                    clean_signals.append(clean_signal)
                signals = "; ".join(clean_signals)
                if len(result.contributing_signals) > 2:
                    signals += f" (+{len(result.contributing_signals) - 2} more)"
            
            except Exception as e:
                test_name = "Error processing name"
                test_id = "N/A"
                signals = f"Error: {e}"
            
            results_table.add_row(
                result.test_id,
                result.name[:30] + "..." if len(result.name) > 30 else result.name,
                f"[{score_style}]{result.bypass_score:.1f}[/{score_style}]",
                str(result.status_code),
                confirmed_icon,
                signals[:50] + "..." if len(signals) > 50 else signals
            )
        
        console.print(results_table)
        
        # Action prompt
        if bypasses_found > 0:
            console.print(f"\n[bold red]⚠️ {bypasses_found} confirmed bypass(es) detected![/bold red]")
        
        action = Prompt.ask(
            "\n[bold]Next action[/bold]",
            choices=["d", "e", "j", "c", "m"],
            default="m"
        )
        
        if action == "d":
            self._detailed_results_view(results)
        elif action == "e":
            self._export_results(results)
        elif action == "j":
            self._export_results(results, format="json")
        elif action == "c":
            self._export_results(results, format="csv")
        # elif action == "m": return to main menu
    
    def _detailed_results_view(self, results: ScanResults):
        """Show detailed drill-down view"""
        while True:
            # Show all results
            table = Table(title="📋 All Test Results")
            table.add_column("ID", style="cyan")
            table.add_column("Name")
            table.add_column("Score", justify="right")
            table.add_column("Status")
            table.add_column("Confirmed")
            
            for result in sorted(results.tests, key=lambda x: x.bypass_score, reverse=True):
                score_style = "red" if result.bypass_score >= 70 else "yellow" if result.bypass_score >= 50 else "dim"
                confirmed = "🔥" if result.bypass_confirmed else "❓" if result.bypass_score >= 50 else "❌"
                
                table.add_row(
                    result.test_id,
                    result.name[:40] + "..." if len(result.name) > 40 else result.name,
                    f"[{score_style}]{result.bypass_score:.1f}[/{score_style}]",
                    str(result.status_code),
                    confirmed
                )
            
            console.print(table)
            
            choices = [r.test_id for r in results.tests] + ["b"]
            selection = Prompt.ask(
                "\n[bold]Select test ID for details (or 'b' for back)[/bold]",
                choices=choices,
                default="b"
            )
            
            if selection == "b":
                break
            
            # Show detailed view
            result = next((r for r in results.tests if r.test_id == selection), None)
            if result:
                self._show_test_details(result, results.baseline[0] if results.baseline else None)
    
    def _show_test_details(self, result: TestResult, baseline: Optional[BaselineCapture]):
        """Show detailed information for a single test"""
        console.print(f"\n📋 [bold]Test Details: {result.name}[/bold]")
        
        # Test info
        info_table = Table.grid(padding=(0, 2))
        info_table.add_column(style="bold")
        info_table.add_column()
        
        info_table.add_row("Test ID:", result.test_id)
        info_table.add_row("Headers:", str(result.headers))
        info_table.add_row("Bypass Score:", f"[red]{result.bypass_score:.1f}/100[/red]" if result.bypass_score >= 50 else f"{result.bypass_score:.1f}/100")
        info_table.add_row("Confirmed:", "🔥 YES" if result.bypass_confirmed else "❌ No")
        info_table.add_row("Replay Count:", str(result.replay_count))
        
        console.print(Panel(info_table, title="Test Information"))
        
        # Comparison table
        if baseline:
            comp_table = Table()
            comp_table.add_column("Metric", style="bold")
            comp_table.add_column("Baseline", style="dim")
            comp_table.add_column("Test Result", style="cyan")
            comp_table.add_column("Change")
            
            comp_table.add_row(
                "Status Code",
                str(baseline.status_code),
                str(result.status_code),
                "🔥" if baseline.status_code != result.status_code else "➖"
            )
            
            length_change = result.content_length - baseline.content_length
            comp_table.add_row(
                "Content Length",
                f"{baseline.content_length}B",
                f"{result.content_length}B",
                f"{'📈' if length_change > 0 else '📉' if length_change < 0 else '➖'} ({length_change:+d}B)"
            )
            
            time_change = result.response_time - baseline.response_time
            comp_table.add_row(
                "Response Time",
                f"{baseline.response_time*1000:.0f}ms",
                f"{result.response_time*1000:.0f}ms",
                f"{'🐌' if time_change > 0.5 else '⚡' if time_change < -0.1 else '➖'} ({time_change*1000:+.0f}ms)"
            )
            
            comp_table.add_row(
                "Body Hash",
                baseline.body_hash,
                result.body_hash,
                "🔄" if baseline.body_hash != result.body_hash else "➖"
            )
            
            console.print(Panel(comp_table, title="📊 Baseline Comparison"))
        
        # Contributing signals
        if result.contributing_signals:
            signals_text = "\n".join([f"• {signal}" for signal in result.contributing_signals])
            console.print(Panel(signals_text, title="🔍 Contributing Signals", border_style="yellow"))
        
        # Response preview
        preview = result.body_snippet[:300] + "..." if len(result.body_snippet) > 300 else result.body_snippet
        console.print(Panel(preview, title="📄 Response Preview", border_style="dim"))
        
        Prompt.ask("\n[dim]Press Enter to continue...[/dim]", default="")
    
    def _export_results(self, results: ScanResults, format: str = "both"):
        """Export results in specified format"""
        if format in ["both", "json"]:
            json_path = self.tester.export_json(results)
            console.print(f"[green]✅ JSON exported: {json_path}[/green]")
        
        if format in ["both", "csv"]:
            csv_path = self.tester.export_csv(results)
            console.print(f"[green]✅ CSV exported: {csv_path}[/green]")
        
        time.sleep(2)
    
    def _view_results(self):
        """View last results if available"""
        if not self.tester.last_results:
            console.print("[yellow]⚠️ No results available. Run a scan first.[/yellow]")
            time.sleep(2)
            return
        
        self._display_pipeline_results(self.tester.last_results)


if __name__ == "__main__":
    ui = WAFTUI()
    ui.run()
