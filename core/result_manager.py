#!/usr/bin/env python3

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class ScanResult:
    id: str
    module: str
    target: str
    timestamp: str
    status: str
    duration: float
    findings_count: int
    severity_distribution: Dict[str, int]
    file_path: Optional[str] = None
    metadata: Dict[str, Any] = None


class ResultManager:
    def __init__(self, base_path: str = ".dkrypt/results"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.results: List[ScanResult] = []
        self.load_results()
    
    def load_results(self):
        index_file = self.base_path / "index.json"
        if index_file.exists():
            try:
                with open(index_file) as f:
                    data = json.load(f)
                    for item in data:
                        self.results.append(ScanResult(**item))
            except:
                pass
    
    def save_results(self):
        index_file = self.base_path / "index.json"
        with open(index_file, 'w') as f:
            json.dump([asdict(r) for r in self.results], f, indent=2)
    
    def add_result(self, module: str, target: str, status: str, 
                   duration: float, findings: int = 0, 
                   severity: Dict[str, int] = None, metadata: Dict = None) -> str:
        result_id = f"{module}_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        result = ScanResult(
            id=result_id,
            module=module,
            target=target,
            timestamp=datetime.now().isoformat(),
            status=status,
            duration=duration,
            findings_count=findings,
            severity_distribution=severity or {},
            metadata=metadata or {}
        )
        
        self.results.append(result)
        self.save_results()
        return result_id
    
    def get_recent_results(self, module: str = None, limit: int = 10) -> List[ScanResult]:
        filtered = self.results
        if module:
            filtered = [r for r in filtered if r.module == module]
        return sorted(filtered, key=lambda x: x.timestamp, reverse=True)[:limit]
    
    def correlate_results(self, target: str) -> Dict[str, Any]:
        target_results = [r for r in self.results if r.target == target]
        
        return {
            "target": target,
            "total_scans": len(target_results),
            "modules_used": list(set(r.module for r in target_results)),
            "total_findings": sum(r.findings_count for r in target_results),
            "severity_aggregated": self._aggregate_severity(target_results),
            "timeline": [{"module": r.module, "time": r.timestamp, "findings": r.findings_count} 
                        for r in sorted(target_results, key=lambda x: x.timestamp)]
        }
    
    def _aggregate_severity(self, results: List[ScanResult]) -> Dict[str, int]:
        aggregated = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for result in results:
            for severity, count in result.severity_distribution.items():
                if severity in aggregated:
                    aggregated[severity] += count
        return aggregated
    
    def export_report(self, target: str, format: str = "json") -> str:
        correlation = self.correlate_results(target)
        
        if format == "json":
            return json.dumps(correlation, indent=2)
        elif format == "html":
            return self._generate_html_report(correlation)
        elif format == "txt":
            return self._generate_txt_report(correlation)
        
        return json.dumps(correlation, indent=2)
    
    def _generate_txt_report(self, data: Dict) -> str:
        report = f"Scan Report for {data['target']}\n"
        report += f"Generated: {datetime.now().isoformat()}\n"
        report += "=" * 60 + "\n\n"
        
        report += f"Total Scans: {data['total_scans']}\n"
        report += f"Total Findings: {data['total_findings']}\n"
        report += f"Modules Used: {', '.join(data['modules_used'])}\n\n"
        
        report += "Severity Distribution:\n"
        for severity, count in data['severity_aggregated'].items():
            if count > 0:
                report += f"  {severity.upper()}: {count}\n"
        
        report += "\nTimeline:\n"
        for entry in data['timeline']:
            report += f"  {entry['module']:15} {entry['time']:20} {entry['findings']} findings\n"
        
        return report
    
    def _generate_html_report(self, data: Dict) -> str:
        html = f"""
        <html>
        <head>
            <title>DKrypt Scan Report - {data['target']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
                .severity {{ display: flex; gap: 20px; margin: 10px 0; }}
                .critical {{ color: #d32f2f; font-weight: bold; }}
                .high {{ color: #f57c00; font-weight: bold; }}
                .medium {{ color: #fbc02d; }}
                .low {{ color: #388e3c; }}
            </style>
        </head>
        <body>
            <h1>Scan Report: {data['target']}</h1>
            <p>Generated: {datetime.now().isoformat()}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Total Scans: {data['total_scans']}</p>
                <p>Total Findings: {data['total_findings']}</p>
                <p>Modules: {', '.join(data['modules_used'])}</p>
            </div>
            
            <h2>Severity Distribution</h2>
            <div class="severity">
                <div class="critical">Critical: {data['severity_aggregated'].get('critical', 0)}</div>
                <div class="high">High: {data['severity_aggregated'].get('high', 0)}</div>
                <div class="medium">Medium: {data['severity_aggregated'].get('medium', 0)}</div>
                <div class="low">Low: {data['severity_aggregated'].get('low', 0)}</div>
            </div>
        </body>
        </html>
        """
        return html


class WorkflowEngine:
    def __init__(self, result_manager: ResultManager):
        self.result_manager = result_manager
        self.workflows: Dict[str, List[Dict]] = {}
        self.load_workflows()
    
    def load_workflows(self):
        workflows_file = Path(".dkrypt/workflows.json")
        if workflows_file.exists():
            try:
                with open(workflows_file) as f:
                    self.workflows = json.load(f)
            except:
                pass
    
    def save_workflows(self):
        workflows_file = Path(".dkrypt/workflows.json")
        workflows_file.parent.mkdir(parents=True, exist_ok=True)
        with open(workflows_file, 'w') as f:
            json.dump(self.workflows, f, indent=2)
    
    def create_workflow(self, name: str, steps: List[Dict[str, Any]]) -> bool:
        if name in self.workflows:
            return False
        
        self.workflows[name] = steps
        self.save_workflows()
        return True
    
    def get_workflow(self, name: str) -> Optional[List[Dict]]:
        return self.workflows.get(name)
    
    def list_workflows(self) -> List[str]:
        return list(self.workflows.keys())
    
    def delete_workflow(self, name: str) -> bool:
        if name in self.workflows:
            del self.workflows[name]
            self.save_workflows()
            return True
        return False


class ThreatIntelligence:
    def __init__(self, result_manager: ResultManager):
        self.result_manager = result_manager
    
    def analyze_patterns(self) -> Dict[str, Any]:
        results = self.result_manager.results
        
        if not results:
            return {"status": "no_data"}
        
        patterns = {
            "most_common_module": self._get_most_common(results, "module"),
            "average_findings_per_scan": self._calculate_average_findings(results),
            "critical_targets": self._identify_critical_targets(results),
            "module_effectiveness": self._calculate_effectiveness(results),
            "risk_score": self._calculate_risk_score(results)
        }
        
        return patterns
    
    def _get_most_common(self, results: List[ScanResult], field: str) -> str:
        if not results:
            return "N/A"
        modules = [getattr(r, field) for r in results]
        return max(set(modules), key=modules.count)
    
    def _calculate_average_findings(self, results: List[ScanResult]) -> float:
        if not results:
            return 0.0
        return sum(r.findings_count for r in results) / len(results)
    
    def _identify_critical_targets(self, results: List[ScanResult]) -> List[str]:
        target_severity = {}
        for result in results:
            critical = result.severity_distribution.get("critical", 0)
            if critical > 0:
                target_severity[result.target] = critical
        
        return [target for target, _ in sorted(target_severity.items(), key=lambda x: x[1], reverse=True)][:5]
    
    def _calculate_effectiveness(self, results: List[ScanResult]) -> Dict[str, float]:
        module_stats = {}
        for result in results:
            if result.module not in module_stats:
                module_stats[result.module] = {"total": 0, "found": 0}
            
            module_stats[result.module]["total"] += 1
            if result.findings_count > 0:
                module_stats[result.module]["found"] += 1
        
        effectiveness = {}
        for module, stats in module_stats.items():
            effectiveness[module] = (stats["found"] / stats["total"]) * 100 if stats["total"] > 0 else 0
        
        return effectiveness
    
    def _calculate_risk_score(self, results: List[ScanResult]) -> int:
        total_critical = sum(r.severity_distribution.get("critical", 0) for r in results)
        total_high = sum(r.severity_distribution.get("high", 0) for r in results)
        
        risk = (total_critical * 10) + (total_high * 5)
        return min(100, max(0, risk // 10))
