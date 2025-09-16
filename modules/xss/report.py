# modules/xss/report.py
import json
import html
import os
import pathlib
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse
from typing import List

from rich.console import Console

# Local imports
from models import XSSVulnerability

console = Console()

class ReportGenerator:
    """Generate XSS scan reports"""
    
    def __init__(self):
        self.timestamp = datetime.now()
        
    def generate_html_report(self, vulnerabilities: List[XSSVulnerability], target: str) -> str:
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Scan Report - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .vulnerability {{ background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .critical {{ border-left: 5px solid #e74c3c; }}
                .high {{ border-left: 5px solid #e67e22; }}
                .medium {{ border-left: 5px solid #f39c12; }}
                .low {{ border-left: 5px solid #3498db; }}
                .evidence {{ background: #ecf0f1; padding: 10px; border-radius: 3px; margin: 10px 0; font-family: monospace; overflow-x: auto; }}
                .remediation {{ background: #d4edda; padding: 15px; border-radius: 3px; margin: 10px 0; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-box {{ background: white; padding: 15px; border-radius: 5px; text-align: center; flex: 1; margin: 0 10px; }}
                .payload {{ background: #fff3cd; padding: 5px; border-radius: 3px; font-family: monospace; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #34495e; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>XSS Vulnerability Scan Report</h1>
                <p>Target: {target}</p>
                <p>Scan Date: {date}</p>
                <p>Total Vulnerabilities: {total}</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>Critical</h3>
                    <p style="color: #e74c3c; font-size: 24px;">{critical}</p>
                </div>
                <div class="stat-box">
                    <h3>High</h3>
                    <p style="color: #e67e22; font-size: 24px;">{high}</p>
                </div>
                <div class="stat-box">
                    <h3>Medium</h3>
                    <p style="color: #f39c12; font-size: 24px;">{medium}</p>
                </div>
                <div class="stat-box">
                    <h3>Low</h3>
                    <p style="color: #3498db; font-size: 24px;">{low}</p>
                </div>
            </div>
            
            <h2>Vulnerability Details</h2>
            {vulnerabilities}
            
            <div class="header" style="margin-top: 40px;">
                <h3>Recommendations</h3>
                <ol>
                    <li>Implement Content Security Policy (CSP) headers</li>
                    <li>Use proper input validation and output encoding</li>
                    <li>Employ template engines with automatic escaping</li>
                    <li>Regular security testing and code reviews</li>
                    <li>Keep all frameworks and libraries up to date</li>
                </ol>
            </div>
        </body>
        </html>
        """
        
        # Count vulnerabilities by severity
        severity_counts = defaultdict(int)
        for vuln in vulnerabilities:
            severity_counts[vuln.severity.value[2]] += 1
        
        # Generate vulnerability details
        vuln_html = ""
        for vuln in sorted(vulnerabilities, key=lambda x: x.cvss_score, reverse=True):
            vuln_html += f"""
            <div class="vulnerability {vuln.severity.value[2]}">
                <h3>XSS in {html.escape(vuln.parameter)} parameter</h3>
                <table>
                    <tr><th>URL</th><td>{html.escape(vuln.url)}</td></tr>
                    <tr><th>Method</th><td>{vuln.method}</td></tr>
                    <tr><th>Parameter</th><td>{html.escape(vuln.parameter)}</td></tr>
                    <tr><th>Context</th><td>{vuln.context.value}</td></tr>
                    <tr><th>CVSS Score</th><td>{vuln.cvss_score}</td></tr>
                    <tr><th>Severity</th><td>{vuln.severity.value[2].upper()}</td></tr>
                </table>
                
                <h4>Payload:</h4>
                <div class="payload">{html.escape(vuln.payload)}</div>
                
                <h4>Evidence:</h4>
                <div class="evidence">{html.escape(vuln.evidence)}</div>
                
                <h4>Remediation:</h4>
                <div class="remediation">{html.escape(vuln.remediation)}</div>
            </div>
            """
        
        return html_template.format(
            target=html.escape(target),
            date=self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            total=len(vulnerabilities),
            critical=severity_counts.get('critical', 0),
            high=severity_counts.get('high', 0),
            medium=severity_counts.get('medium', 0),
            low=severity_counts.get('low', 0),
            vulnerabilities=vuln_html
        )
    
    def generate_json_report(self, vulnerabilities: List[XSSVulnerability], target: str) -> str:
        """Generate JSON report"""
        report = {
            'scan_info': {
                'target': target,
                'timestamp': self.timestamp.isoformat(),
                'total_vulnerabilities': len(vulnerabilities)
            },
            'summary': {
                'by_severity': {},
                'by_context': {}
            },
            'vulnerabilities': []
        }
        
        # Generate summary
        for vuln in vulnerabilities:
            # By severity
            severity = vuln.severity.value[2]
            report['summary']['by_severity'][severity] = report['summary']['by_severity'].get(severity, 0) + 1
            
            # By context
            context = vuln.context.value
            report['summary']['by_context'][context] = report['summary']['by_context'].get(context, 0) + 1
            
            # Add vulnerability
            report['vulnerabilities'].append(vuln.to_dict())
        
        return json.dumps(report, indent=2)
    
    def save_report(self, vulnerabilities: List[XSSVulnerability], target: str, format: str = 'both'):
        """Save report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(target).netloc.replace('.', '_')
        
        # Create reports directory if it doesn't exist
        report_dir = pathlib.Path("reports/xss")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        if format in ['html', 'both']:
            html_filename = report_dir / f"xss_report_{domain}_{timestamp}.html"
            with open(html_filename, 'w') as f:
                f.write(self.generate_html_report(vulnerabilities, target))
            console.print(f"[green]HTML report saved: {html_filename}[/green]")
        
        if format in ['json', 'both']:
            json_filename = report_dir / f"xss_report_{domain}_{timestamp}.json"
            with open(json_filename, 'w') as f:
                f.write(self.generate_json_report(vulnerabilities, target))
            console.print(f"[green]JSON report saved: {json_filename}[/green]")