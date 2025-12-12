# modules/http_desync/exports/result_saver.py
import json
import csv
import time
import sys
from pathlib import Path
from typing import List, Dict, Any
from rich.console import Console
sys.path.append("..")
from modules.http_desync.engine.payload_generator import TestResult

console = Console()

class ResultSaver:
    """
    Handles saving scan results to various file formats.
    """
    
    @staticmethod
    def save_results_to_file(results: List[TestResult], target_url: str, port: int, 
                           target_info: Dict[str, Any], output_dir: str = "reports/desync_results"):
        """
        Save scan results to formatted text, JSON, or CSV file.
        
        Args:
            results: List of TestResult objects
            target_url: Target URL that was scanned
            port: Target port
            target_info: Dictionary containing target information
            output_dir: Directory to save reports
        """
        try:
            # Create reports directory if it doesn't exist
            reports_dir = Path(output_dir)
            reports_dir.mkdir(parents=True, exist_ok=True)

            timestamp = time.strftime("%Y%m%d_%H%M%S")

            # Save in all formats for CLI mode
            for format_choice in ["json", "txt", "csv"]:  # Save all formats
                filename = reports_dir / f"desync_scan_results_{timestamp}.{format_choice}"

                if format_choice == "txt":
                    ResultSaver._save_txt_file(filename, results, target_url, port, target_info)
                elif format_choice == "json":
                    ResultSaver._save_json_file(filename, results, target_url, port, target_info)
                elif format_choice == "csv":
                    ResultSaver._save_csv_file(filename, results)

                console.print(f"[green]✅ Results saved to: {filename}[/green]")

            # Return the main JSON filename as reference
            main_filename = reports_dir / f"desync_scan_results_{timestamp}.json"
            return main_filename

        except Exception as e:
            console.print(f"[red]❌ Failed to save results: {e}[/red]")
            raise

    @staticmethod
    def _save_txt_file(filename: Path, results: List[TestResult], target_url: str, 
                      port: int, target_info: Dict[str, Any]):
        """Save results as formatted text file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("HTTP DESYNC SCANNER RESULTS\n")
            f.write("=" * 80 + "\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {target_url}:{port}\n")
            f.write(f"Total Tests: {len(results)}\n")
            f.write("=" * 80 + "\n\n")

            # Target information
            f.write("TARGET INFORMATION:\n")
            f.write("-" * 40 + "\n")
            for key, value in target_info.items():
                if isinstance(value, dict):
                    f.write(f"{key}:\n")
                    for subkey, subvalue in value.items():
                        f.write(f"  {subkey}: {subvalue}\n")
                else:
                    f.write(f"{key}: {value}\n")
            f.write("\n")

            # Results
            f.write("DETAILED RESULTS:\n")
            f.write("-" * 40 + "\n")

            for i, result in enumerate(results, 1):
                f.write(f"{i}. {result.payload_type} ({result.protocol})\n")
                # Remove rich formatting for file output
                status_clean = ResultSaver._clean_rich_formatting(result.status)
                conf_clean = ResultSaver._clean_rich_formatting(result.confidence)

                f.write(f"   Status: {status_clean}\n")
                f.write(f"   Confidence: {conf_clean}\n")
                f.write(f"   Response Time: {result.response_time:.2f}s\n")
                f.write(f"   Details: {result.details}\n")
                f.write("\n")

    @staticmethod
    def _save_json_file(filename: Path, results: List[TestResult], target_url: str, 
                       port: int, target_info: Dict[str, Any]):
        """Save results as JSON file"""
        results_data = {
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": f"{target_url}:{port}",
            "target_info": target_info,
            "results": [
                {
                    "payload_type": result.payload_type,
                    "protocol": result.protocol,
                    "status": ResultSaver._clean_rich_formatting(result.status),
                    "confidence": ResultSaver._clean_rich_formatting(result.confidence),
                    "response_time": result.response_time,
                    "details": result.details
                }
                for result in results
            ]
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _save_csv_file(filename: Path, results: List[TestResult]):
        """Save results as CSV file"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Payload Type', 'Protocol', 'Status', 'Confidence',
                'Response Time', 'Details'
            ])

            for result in results:
                # Clean formatting for CSV
                status_clean = ResultSaver._clean_rich_formatting(result.status)
                conf_clean = ResultSaver._clean_rich_formatting(result.confidence)

                writer.writerow([
                    result.payload_type,
                    result.protocol,
                    status_clean,
                    conf_clean,
                    f"{result.response_time:.2f}s",
                    result.details
                ])

    @staticmethod
    def _clean_rich_formatting(text: str) -> str:
        """Remove rich formatting tags from text"""
        clean_text = text
        formatting_tags = [
            '[bold red]', '[/bold red]', '[bold yellow]', '[/bold yellow]',
            '[green]', '[/green]', '[blue]', '[/blue]', '[red]', '[/red]',
            '[yellow]', '[/yellow]'
        ]
        
        for tag in formatting_tags:
            clean_text = clean_text.replace(tag, '')
            
        return clean_text