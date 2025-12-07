#!/usr/bin/env python3
"""
DKrypt Enhanced Suggestion Engine
Advanced fuzzy matching, user pattern learning, and intelligent auto-completion
"""

import difflib
import json
import os
import re
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
from collections import Counter, defaultdict


@dataclass
class SuggestionResult:
    """Represents a suggestion with metadata"""
    value: str
    score: float
    source: str = "fuzzy"
    context: str = ""


class UsagePatternTracker:
    """Tracks user command patterns for intelligent suggestions"""
    
    def __init__(self, db_path: str = ".dkrypt/usage_patterns.json"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.patterns: Dict[str, Any] = self._load_patterns()
        self._dirty = False
        
    def _load_patterns(self) -> Dict[str, Any]:
        """Load patterns from disk"""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {
            "module_usage": {},
            "command_sequences": [],
            "option_values": {},
            "last_updated": 0
        }
    
    def save(self) -> None:
        """Save patterns to disk"""
        if self._dirty:
            self.patterns["last_updated"] = time.time()
            try:
                with open(self.db_path, 'w') as f:
                    json.dump(self.patterns, f, indent=2)
                self._dirty = False
            except IOError:
                pass
    
    def record_module_use(self, module: str) -> None:
        """Record module usage for frequency analysis"""
        if module not in self.patterns["module_usage"]:
            self.patterns["module_usage"][module] = 0
        self.patterns["module_usage"][module] += 1
        self._dirty = True
        
    def record_command_sequence(self, commands: List[str], max_len: int = 3) -> None:
        """Record command sequences for predictive suggestions"""
        sequences = self.patterns["command_sequences"]
        sequences.append(commands[-max_len:] if len(commands) > max_len else commands)
        if len(sequences) > 1000:
            sequences = sequences[-500:]
        self.patterns["command_sequences"] = sequences
        self._dirty = True
    
    def record_option_value(self, module: str, option: str, value: str) -> None:
        """Record option values for auto-completion"""
        key = f"{module}:{option}"
        if key not in self.patterns["option_values"]:
            self.patterns["option_values"][key] = []
        values = self.patterns["option_values"][key]
        if value not in values:
            values.append(value)
        if len(values) > 50:
            self.patterns["option_values"][key] = values[-25:]
        self._dirty = True
        
    def get_frequent_modules(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get most frequently used modules"""
        usage = self.patterns.get("module_usage", {})
        sorted_modules = sorted(usage.items(), key=lambda x: x[1], reverse=True)
        return sorted_modules[:limit]
    
    def get_option_history(self, module: str, option: str) -> List[str]:
        """Get historical values for an option"""
        key = f"{module}:{option}"
        return self.patterns.get("option_values", {}).get(key, [])
    
    def predict_next_command(self, recent_commands: List[str]) -> Optional[str]:
        """Predict next command based on sequences"""
        sequences = self.patterns.get("command_sequences", [])
        if not sequences or not recent_commands:
            return None
        
        recent = recent_commands[-2:]
        predictions = Counter()
        
        for seq in sequences:
            for i in range(len(seq) - len(recent)):
                if seq[i:i+len(recent)] == recent and i + len(recent) < len(seq):
                    predictions[seq[i + len(recent)]] += 1
        
        if predictions:
            return predictions.most_common(1)[0][0]
        return None


class EnhancedSuggester:
    """Advanced suggestion engine with fuzzy matching and pattern learning"""
    
    def __init__(self, modules_config: Dict[str, Dict]):
        self.modules_config = modules_config
        self.all_modules = list(modules_config.keys())
        self.all_commands = self._build_command_list()
        self.pattern_tracker = UsagePatternTracker()
        
        self._module_keywords = self._build_keyword_index()
        self._suggestion_cache: Dict[str, List[SuggestionResult]] = {}
        self._cache_ttl = 60
        self._cache_timestamps: Dict[str, float] = {}
    
    def _build_command_list(self) -> List[str]:
        """Build comprehensive command list"""
        return [
            "use", "show", "set", "unset", "run", "back", "search",
            "info", "options", "help", "exit", "quit", "q",
            "history", "shortcut", "workspace", "results", "export",
            "workflow", "dashboard"
        ]
    
    def _build_keyword_index(self) -> Dict[str, List[str]]:
        """Build keyword index for semantic matching"""
        index = defaultdict(list)
        
        keyword_map = {
            "sql": ["sqli", "injection", "database"],
            "xss": ["cross-site", "script", "injection"],
            "port": ["scan", "network", "service"],
            "subdomain": ["dns", "domain", "enum"],
            "dir": ["directory", "brute", "path"],
            "cors": ["cross-origin", "header"],
            "ssl": ["tls", "certificate", "https"],
            "waf": ["firewall", "bypass", "filter"],
            "graphql": ["api", "introspection", "query"],
            "crawl": ["spider", "scrape", "link"],
        }
        
        for module in self.all_modules:
            module_lower = module.lower()
            for keyword, aliases in keyword_map.items():
                if keyword in module_lower:
                    for alias in aliases:
                        index[alias].append(module)
            index[module_lower].append(module)
            
        return dict(index)
    
    def _get_cached(self, cache_key: str) -> Optional[List[SuggestionResult]]:
        """Get cached suggestions if still valid"""
        if cache_key in self._suggestion_cache:
            timestamp = self._cache_timestamps.get(cache_key, 0)
            if time.time() - timestamp < self._cache_ttl:
                return self._suggestion_cache[cache_key]
        return None
    
    def _set_cached(self, cache_key: str, results: List[SuggestionResult]) -> None:
        """Cache suggestions"""
        self._suggestion_cache[cache_key] = results
        self._cache_timestamps[cache_key] = time.time()
        
        if len(self._suggestion_cache) > 100:
            oldest = min(self._cache_timestamps.items(), key=lambda x: x[1])
            del self._suggestion_cache[oldest[0]]
            del self._cache_timestamps[oldest[0]]
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _jaro_winkler_similarity(self, s1: str, s2: str) -> float:
        """Calculate Jaro-Winkler similarity between two strings"""
        if s1 == s2:
            return 1.0
        
        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0
        
        match_distance = max(len1, len2) // 2 - 1
        if match_distance < 0:
            match_distance = 0
        
        s1_matches = [False] * len1
        s2_matches = [False] * len2
        matches = 0
        transpositions = 0
        
        for i in range(len1):
            start = max(0, i - match_distance)
            end = min(i + match_distance + 1, len2)
            for j in range(start, end):
                if s2_matches[j] or s1[i] != s2[j]:
                    continue
                s1_matches[i] = True
                s2_matches[j] = True
                matches += 1
                break
        
        if matches == 0:
            return 0.0
        
        k = 0
        for i in range(len1):
            if not s1_matches[i]:
                continue
            while not s2_matches[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1
        
        jaro = (matches / len1 + matches / len2 + 
                (matches - transpositions / 2) / matches) / 3
        
        prefix = 0
        for i in range(min(len1, len2, 4)):
            if s1[i] == s2[i]:
                prefix += 1
            else:
                break
        
        return jaro + prefix * 0.1 * (1 - jaro)
    
    def _compute_similarity(self, query: str, target: str) -> float:
        """Compute combined similarity score"""
        query_lower = query.lower()
        target_lower = target.lower()
        
        if query_lower == target_lower:
            return 1.0
        
        if target_lower.startswith(query_lower):
            return 0.95 + (len(query) / len(target)) * 0.05
        
        if query_lower in target_lower:
            return 0.85 + (len(query) / len(target)) * 0.1
        
        jaro = self._jaro_winkler_similarity(query_lower, target_lower)
        seq_ratio = difflib.SequenceMatcher(None, query_lower, target_lower).ratio()
        
        max_len = max(len(query), len(target))
        lev_dist = self._levenshtein_distance(query_lower, target_lower)
        lev_score = 1.0 - (lev_dist / max_len) if max_len > 0 else 0.0
        
        return max(jaro * 0.4 + seq_ratio * 0.35 + lev_score * 0.25, 0.0)
    
    def suggest_module(self, query: str, threshold: float = 0.4, 
                       max_results: int = 5) -> List[Tuple[str, float]]:
        """
        Suggest modules with advanced matching
        
        Args:
            query: User input to match
            threshold: Minimum similarity score
            max_results: Maximum number of suggestions
            
        Returns:
            List of (module_name, score) tuples
        """
        if not query:
            frequent = self.pattern_tracker.get_frequent_modules(max_results)
            if frequent:
                return [(m, 0.5) for m, _ in frequent]
            return [(m, 0.5) for m in self.all_modules[:max_results]]
        
        cache_key = f"module:{query}:{threshold}"
        cached = self._get_cached(cache_key)
        if cached:
            return [(r.value, r.score) for r in cached]
        
        results = []
        query_lower = query.lower()
        
        if query_lower in self._module_keywords:
            for module in self._module_keywords[query_lower]:
                results.append(SuggestionResult(
                    value=module,
                    score=0.9,
                    source="keyword"
                ))
        
        for module in self.all_modules:
            score = self._compute_similarity(query, module)
            if score >= threshold:
                existing = next((r for r in results if r.value == module), None)
                if existing:
                    existing.score = max(existing.score, score)
                else:
                    results.append(SuggestionResult(
                        value=module,
                        score=score,
                        source="fuzzy"
                    ))
        
        freq_modules = dict(self.pattern_tracker.get_frequent_modules(10))
        for result in results:
            if result.value in freq_modules:
                boost = min(0.1, freq_modules[result.value] * 0.01)
                result.score = min(1.0, result.score + boost)
        
        results.sort(key=lambda x: x.score, reverse=True)
        results = results[:max_results]
        
        self._set_cached(cache_key, results)
        return [(r.value, r.score) for r in results]
    
    def suggest_command(self, query: str, threshold: float = 0.4,
                       max_results: int = 5) -> List[Tuple[str, float]]:
        """
        Suggest commands with advanced matching
        
        Args:
            query: User input to match
            threshold: Minimum similarity score
            max_results: Maximum number of suggestions
            
        Returns:
            List of (command, score) tuples
        """
        if not query:
            return [(cmd, 0.5) for cmd in self.all_commands[:max_results]]
        
        results = []
        
        for cmd in self.all_commands:
            score = self._compute_similarity(query, cmd)
            if score >= threshold:
                results.append((cmd, score))
        
        module_suggestions = self.suggest_module(query, threshold, max_results)
        for module, score in module_suggestions:
            results.append((module, score * 0.9))
        
        results.sort(key=lambda x: x[1], reverse=True)
        
        seen = set()
        unique = []
        for item, score in results:
            if item not in seen:
                seen.add(item)
                unique.append((item, score))
        
        return unique[:max_results]
    
    def suggest_options(self, module: str, partial: str = "") -> List[str]:
        """
        Suggest options for a module with intelligent matching
        
        Args:
            module: Module name
            partial: Partial option name to match
            
        Returns:
            List of option suggestions
        """
        if module not in self.modules_config:
            return []
        
        module_opts = self.modules_config[module].get("options", {})
        opt_names = [opt.upper() for opt in module_opts.keys()]
        
        if not partial:
            required = [opt for opt, info in module_opts.items() 
                       if info.get('required', False)]
            optional = [opt for opt in opt_names if opt not in required]
            return [opt.upper() for opt in required] + optional
        
        partial_upper = partial.upper()
        
        exact = [opt for opt in opt_names if opt == partial_upper]
        prefix = [opt for opt in opt_names 
                  if opt.startswith(partial_upper) and opt != partial_upper]
        
        fuzzy = []
        for opt in opt_names:
            if opt not in exact and opt not in prefix:
                score = self._compute_similarity(partial_upper, opt)
                if score >= 0.4:
                    fuzzy.append((opt, score))
        
        fuzzy.sort(key=lambda x: x[1], reverse=True)
        
        return exact + prefix + [opt for opt, _ in fuzzy]
    
    def suggest_option_values(self, module: str, option: str, 
                              partial: str = "") -> List[str]:
        """
        Suggest values for an option based on history and constraints
        
        Args:
            module: Module name
            option: Option name
            partial: Partial value to match
            
        Returns:
            List of value suggestions
        """
        suggestions = []
        
        if module in self.modules_config:
            opt_info = self.modules_config[module].get("options", {}).get(option.upper(), {})
            
            if "choices" in opt_info:
                choices = opt_info["choices"]
                if partial:
                    suggestions = [c for c in choices 
                                   if c.lower().startswith(partial.lower())]
                else:
                    suggestions = list(choices)
        
        history = self.pattern_tracker.get_option_history(module, option)
        for val in reversed(history):
            if val not in suggestions:
                if not partial or val.lower().startswith(partial.lower()):
                    suggestions.append(val)
        
        return suggestions[:10]
    
    def suggest_contextual(self, command: str, module: str = "",
                          partial: str = "") -> List[str]:
        """
        Provide contextual suggestions based on current state
        
        Args:
            command: Current command context
            module: Current module (if any)
            partial: Partial input
            
        Returns:
            List of contextual suggestions
        """
        if command == "use":
            return [m for m, _ in self.suggest_module(partial)]
        
        elif command == "set":
            if module:
                return self.suggest_options(module, partial)
            return []
        
        elif command == "show":
            options = ["modules", "options", "workspaces", "history"]
            if partial:
                return [o for o in options if o.startswith(partial.lower())]
            return options
        
        elif command == "search":
            return [m for m, _ in self.suggest_module(partial)]
        
        elif command == "workspace":
            options = ["list", "create", "switch", "delete"]
            if partial:
                return [o for o in options if o.startswith(partial.lower())]
            return options
        
        elif command == "results":
            options = ["list", "show", "analyze", "export"]
            if partial:
                return [o for o in options if o.startswith(partial.lower())]
            return options
        
        elif command == "workflow":
            options = ["list", "create", "run", "delete"]
            if partial:
                return [o for o in options if o.startswith(partial.lower())]
            return options
        
        elif command == "shortcut":
            options = ["create", "list", "run"]
            if partial:
                return [o for o in options if o.startswith(partial.lower())]
            return options
        
        elif command == "export":
            options = ["json", "html", "txt"]
            if partial:
                return [o for o in options if o.startswith(partial.lower())]
            return options
        
        return []
    
    def record_usage(self, module: str = None, option: str = None, 
                     value: str = None, command: str = None) -> None:
        """
        Record usage patterns for learning
        
        Args:
            module: Module name if used
            option: Option name if set
            value: Value if provided
            command: Command used
        """
        if module:
            self.pattern_tracker.record_module_use(module)
            
        if module and option and value:
            self.pattern_tracker.record_option_value(module, option, value)
    
    def save_patterns(self) -> None:
        """Save learned patterns to disk"""
        self.pattern_tracker.save()
    
    def get_module_description(self, module: str) -> str:
        """Get module description"""
        if module not in self.modules_config:
            return "Module not found"
        return self.modules_config[module].get("description", "No description available")
    
    def get_module_option_info(self, module: str, option: str) -> Dict[str, Any]:
        """Get detailed option information"""
        if module not in self.modules_config:
            return {}
        
        opt_info = self.modules_config[module].get("options", {}).get(option.upper(), {})
        
        return {
            'name': option.upper(),
            'required': opt_info.get('required', False),
            'default': opt_info.get('default', 'None'),
            'description': opt_info.get('description', ''),
            'validator': opt_info.get('validator', ''),
            'choices': opt_info.get('choices', []),
        }
