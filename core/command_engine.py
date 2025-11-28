#!/usr/bin/env python3

import difflib
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CommandMetadata:
    timestamp: str
    module: str
    options: Dict[str, Any]
    status: str = "pending"
    result_summary: str = ""
    execution_time: float = 0.0


class CommandHistory:
    def __init__(self, max_entries: int = 100):
        self.entries: List[CommandMetadata] = []
        self.max_entries = max_entries
        self.shortcuts: Dict[str, Dict[str, Any]] = {}
        
    def add_entry(self, module: str, options: Dict[str, Any]) -> None:
        entry = CommandMetadata(
            timestamp=datetime.now().isoformat(),
            module=module,
            options=options.copy()
        )
        self.entries.append(entry)
        if len(self.entries) > self.max_entries:
            self.entries.pop(0)
    
    def update_status(self, module: str, status: str, summary: str = "", duration: float = 0.0) -> None:
        for entry in reversed(self.entries):
            if entry.module == module and entry.status == "pending":
                entry.status = status
                entry.result_summary = summary
                entry.execution_time = duration
                break
    
    def get_recent(self, count: int = 10) -> List[CommandMetadata]:
        return self.entries[-count:]
    
    def add_shortcut(self, name: str, module: str, options: Dict[str, Any]) -> None:
        self.shortcuts[name] = {"module": module, "options": options}
    
    def get_shortcut(self, name: str) -> Optional[Dict[str, Any]]:
        return self.shortcuts.get(name)


from .validators import Validator, ValidationError


class CommandValidator:
    def __init__(self, modules_config: Dict[str, Dict]):
        self.modules_config = modules_config
        self.validator = Validator()

    def validate_module_options(self, module: str, options: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors = []

        if module not in self.modules_config:
            return False, [f"Module '{module}' not found"]

        module_opts = self.modules_config[module].get("options", {})

        for opt_name, opt_value in options.items():
            opt_info = module_opts.get(opt_name.upper())

            if not opt_info:
                # Check if this might be a typo by using difflib
                possible_opts = list(module_opts.keys())
                suggestions = difflib.get_close_matches(opt_name.upper(), possible_opts, n=3, cutoff=0.5)
                if suggestions:
                    errors.append(f"Unknown option '{opt_name}' for module '{module}'. Did you mean: {', '.join(suggestions)}?")
                else:
                    errors.append(f"Unknown option '{opt_name}' for module '{module}'")
                continue

            validator_name = opt_info.get('validator')
            if validator_name:
                try:
                    validator_func = getattr(self.validator, validator_name)

                    # Prepare arguments for validator function
                    validator_args = {}
                    if 'choices' in opt_info:
                        validator_args['choices'] = opt_info['choices']
                    if 'min_val' in opt_info:
                        validator_args['min_val'] = opt_info['min_val']
                    if 'max_val' in opt_info:
                        validator_args['max_val'] = opt_info['max_val']

                    # Check if validator supports allow_empty parameter
                    if 'allow_empty' in validator_func.__code__.co_varnames:
                        validator_args['allow_empty'] = True  # or determine from opt_info if needed
                    else:
                        # If the validator doesn't support allow_empty but value is empty, skip validation
                        if not opt_value and opt_info.get('required', False) is False:
                            continue  # Skip validation for non-required empty values unless validator supports it

                    # Dynamically call validator with appropriate args
                    validator_func(opt_value, **validator_args)

                except ValidationError as e:
                    errors.append(f"Option '{opt_name.upper()}': {e.message}")
                    if 'choices' in opt_info:
                        errors.append(f"  Valid options: {', '.join(opt_info['choices'])}")
                except AttributeError:
                    errors.append(f"Invalid validator '{validator_name}' for option '{opt_name.upper()}'")
                except Exception as e:
                    errors.append(f"Unexpected error validating '{opt_name.upper()}': {str(e)}")

        return len(errors) == 0, errors


class CommandSuggester:
    def __init__(self, modules_config: Dict[str, Dict]):
        self.modules_config = modules_config
        self.all_modules = list(modules_config.keys())
        self.all_commands = self._build_command_list()
        self.command_context_suggestions = {
            'set': self._suggest_options_for_context,
            'use': self._suggest_modules_for_context,
            'show': self._suggest_show_options,
            'run': self._suggest_run_context,
            'search': self._suggest_modules_for_context,
        }

    def _build_command_list(self) -> List[str]:
        commands = [
            "use", "show", "set", "unset", "run", "back", "search",
            "info", "options", "help", "exit", "quit", "q",
            "history", "shortcut", "workspace", "results", "export",
            "workflow", "dashboard"
        ]
        commands.extend(self.all_modules)
        return commands

    def _suggest_modules_for_context(self, partial_input: str) -> List[str]:
        """Suggest modules based on partial input"""
        return difflib.get_close_matches(
            partial_input.lower(),
            self.all_modules,
            n=5,
            cutoff=0.3
        )

    def _suggest_options_for_context(self, module: str, partial_input: str = "") -> List[str]:
        """Suggest options for a specific module"""
        if module not in self.modules_config:
            return []

        module_opts = self.modules_config[module].get("options", {})
        opt_names = [opt.upper() for opt in module_opts.keys()]

        if not partial_input:
            return opt_names

        return difflib.get_close_matches(
            partial_input.upper(),
            opt_names,
            n=5,
            cutoff=0.3
        )

    def _suggest_show_options(self, partial_input: str = "") -> List[str]:
        """Suggest options for show command"""
        show_options = ["modules", "options", "workspaces", "history"]
        if not partial_input:
            return show_options
        return difflib.get_close_matches(
            partial_input.lower(),
            show_options,
            n=5,
            cutoff=0.3
        )

    def _suggest_run_context(self, partial_input: str = "") -> List[str]:
        """Suggest run command context"""
        if not partial_input:
            return ["run"]  # Only one option for run command
        return ["run"] if "run".startswith(partial_input.lower()) else []

    def suggest_module(self, user_input: str, threshold: float = 0.6, max_suggestions: int = 5) -> List[Tuple[str, float]]:
        """
        Advanced module suggestion with improved scoring
        """
        # Exact match first
        if user_input in self.all_modules:
            return [(user_input, 1.0)]

        # Find close matches using multiple algorithms
        matches = []

        # Exact substring matches
        substring_matches = [module for module in self.all_modules if user_input.lower() in module.lower()]

        # Difflib matches
        difflib_matches = difflib.get_close_matches(
            user_input.lower(),
            self.all_modules,
            n=max_suggestions * 2,  # Get more matches to allow for filtering
            cutoff=threshold * 0.7  # Lower cutoff to get more matches
        )

        # Combine and score matches
        all_matches = list(set(substring_matches + difflib_matches))

        scored_matches = []
        for match in all_matches:
            # Calculate multiple similarity scores and take the best one
            seq_score = difflib.SequenceMatcher(None, user_input.lower(), match).ratio()
            token_score = difflib.SequenceMatcher(None, user_input.lower(), match.lower()).ratio()

            # Prefer matches that start with the input
            prefix_score = 1.0 if match.lower().startswith(user_input.lower()) else 0.8

            # Weight the final score
            final_score = max(seq_score, token_score) * prefix_score

            if final_score >= threshold:
                scored_matches.append((match, final_score))

        # Sort by score and return top suggestions
        return sorted(scored_matches, key=lambda x: x[1], reverse=True)[:max_suggestions]

    def suggest_command(self, user_input: str, threshold: float = 0.6, max_suggestions: int = 5) -> List[Tuple[str, float]]:
        """
        Advanced command suggestion with improved scoring
        """
        # Exact match first
        if user_input in self.all_commands:
            return [(user_input, 1.0)]

        # Find close matches using multiple strategies
        matches = []

        # Substring matches for partial command completion
        substring_matches = [cmd for cmd in self.all_commands if user_input.lower() in cmd.lower()]

        # Difflib matches
        difflib_matches = difflib.get_close_matches(
            user_input.lower(),
            self.all_commands,
            n=max_suggestions * 2,
            cutoff=threshold * 0.7
        )

        # Combine matches
        all_matches = list(set(substring_matches + difflib_matches))

        scored_matches = []
        for match in all_matches:
            # Calculate similarity scores
            seq_score = difflib.SequenceMatcher(None, user_input.lower(), match).ratio()

            # Prefer commands that start with the input (for tab completion)
            prefix_score = 1.0 if match.lower().startswith(user_input.lower()) else 0.8

            # Final score
            final_score = seq_score * prefix_score

            if final_score >= threshold:
                scored_matches.append((match, final_score))

        # Sort by score and return top suggestions
        return sorted(scored_matches, key=lambda x: x[1], reverse=True)[:max_suggestions]

    def suggest_options(self, module: str, partial_input: str = "") -> List[str]:
        """Suggest options for a specific module with improved logic"""
        if module not in self.modules_config:
            # If module not found, suggest modules instead
            return self._suggest_modules_for_context(partial_input)

        module_opts = self.modules_config[module].get("options", {})
        opt_names = [opt.upper() for opt in module_opts.keys()]

        if not partial_input:
            return opt_names

        # Prioritize exact matches, then prefix matches, then fuzzy matches
        exact_matches = [opt for opt in opt_names if opt.lower() == partial_input.lower()]
        prefix_matches = [opt for opt in opt_names if opt.lower().startswith(partial_input.lower()) and opt.lower() != partial_input.lower()]
        fuzzy_matches = difflib.get_close_matches(
            partial_input.upper(),
            opt_names,
            n=10,
            cutoff=0.3
        )

        # Combine with priority order: exact, prefix, then fuzzy
        all_suggestions = exact_matches + [opt for opt in prefix_matches if opt not in exact_matches] + \
                         [opt for opt in fuzzy_matches if opt not in exact_matches and opt not in prefix_matches]

        return all_suggestions[:10]  # Return top 10 suggestions

    def suggest_contextual(self, command: str, context: str = "", partial_input: str = "") -> List[str]:
        """
        Provide contextual suggestions based on the current command
        """
        if command in self.command_context_suggestions:
            return self.command_context_suggestions[command](context, partial_input)
        return []

    def get_module_description(self, module: str) -> str:
        """Get module description with fallback"""
        if module not in self.modules_config:
            return "Module not found"
        return self.modules_config[module].get("description", "No description available")

    def get_module_option_info(self, module: str, option: str) -> Dict[str, Any]:
        """Get detailed information about a specific option in a module"""
        if module not in self.modules_config:
            return {}

        module_opts = self.modules_config[module].get("options", {})
        opt_info = module_opts.get(option.upper(), {})

        return {
            'name': option.upper(),
            'required': opt_info.get('required', False),
            'default': opt_info.get('default', 'None'),
            'description': opt_info.get('description', ''),
            'validator': opt_info.get('validator', ''),
            'choices': opt_info.get('choices', []),
        }

    def suggest_completions(self, command: str, module: str = "", partial_input: str = "") -> List[str]:
        """
        Provide intelligent completions based on context
        """
        if command == 'set':
            if module:
                # Suggest options for the current module
                options = self.suggest_options(module, partial_input)
                return options
            else:
                # Could suggest common options or error
                return []
        elif command == 'use':
            # Suggest modules
            suggestions = self._suggest_modules_for_context(partial_input)
            return suggestions
        elif command == 'run':
            # Check if module is selected and if required options are set
            if module:
                module_info = self.modules_config.get(module, {})
                module_opts = module_info.get("options", {})

                # Return empty list since 'run' doesn't take additional arguments
                return []
        elif command == 'show':
            # Suggest what can be shown
            show_options = ['modules', 'options']
            if partial_input:
                return [opt for opt in show_options if opt.startswith(partial_input.lower())]
            return show_options
        else:
            # Default to basic command suggestions
            return self.suggest_command(command)[:5]

        return []


class CommandParser:
    def __init__(self, modules_config: Dict[str, Dict]):
        self.modules_config = modules_config
        self.history = CommandHistory()
        self.validator = CommandValidator(modules_config)
        self.suggester = CommandSuggester(modules_config)
    
    def parse_command_line(self, line: str) -> Tuple[str, str, Dict[str, Any]]:
        parts = line.strip().split()
        if not parts:
            return "", "", {}
        
        cmd = parts[0].lower()
        args = " ".join(parts[1:])
        kwargs = {}
        
        if cmd in ["set"]:
            if len(parts) >= 3:
                kwargs = {parts[1].lower(): " ".join(parts[2:])}
        elif cmd in ["use"]:
            kwargs = {"module": parts[1].lower() if len(parts) > 1 else ""}
        
        return cmd, args, kwargs
    
    def validate_and_get_suggestions(self, module: str, options: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        errors = []
        suggestions = []
        
        module_info = self.modules_config.get(module, {})
        module_opts = module_info.get("options", {})

        # 2. Validate provided options
        is_valid, validation_errors = self.validator.validate_module_options(module, options)
        if not is_valid:
            errors.extend(validation_errors)
            
            # 3. Generate suggestions based on validation errors
            for error in validation_errors:
                # Example: "Option 'SCAN_TYPE': Value must be one of: SYN, CON, UDP"
                if "must be one of" in error:
                    try:
                        opt_name = error.split("'")[1]
                        choices_str = error.split("one of: ")[1]
                        suggestions.append(f"For {opt_name}, try one of: {choices_str}")
                    except IndexError:
                        pass # Gracefully handle if parsing fails

        return len(errors) == 0, errors, suggestions
