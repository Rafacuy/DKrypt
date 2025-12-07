#!/usr/bin/env python3
"""
DKrypt Enhanced Auto-Completion Engine
Intelligent tab completion with context awareness and pattern learning
"""

import readline
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass


@dataclass
class CompletionContext:
    """Represents the current completion context"""
    command: str = ""
    module: str = ""
    subcommand: str = ""
    partial: str = ""
    cursor_pos: int = 0
    line: str = ""


class SmartCompleter:
    """
    Intelligent auto-completion engine for DKrypt CLI
    
    Features:
    - Context-aware completions
    - Multi-level completion (command -> subcommand -> options)
    - Historical pattern-based suggestions
    - Fuzzy prefix matching
    """
    
    def __init__(self, suggestor, modules_config: Dict[str, Dict]):
        self.suggestor = suggestor
        self.modules_config = modules_config
        self.current_module: Optional[str] = None
        self.current_options: Dict[str, Any] = {}
        
        self._completions: List[str] = []
        self._completion_cache: Dict[str, List[str]] = {}
        
        self._command_completers: Dict[str, Callable] = {
            "use": self._complete_use,
            "set": self._complete_set,
            "unset": self._complete_unset,
            "show": self._complete_show,
            "search": self._complete_search,
            "info": self._complete_info,
            "help": self._complete_help,
            "workspace": self._complete_workspace,
            "workflow": self._complete_workflow,
            "results": self._complete_results,
            "shortcut": self._complete_shortcut,
            "export": self._complete_export,
        }
        
        self._base_commands = [
            "use", "show", "set", "unset", "run", "back", "search",
            "info", "options", "help", "exit", "quit", "q",
            "history", "shortcut", "workspace", "results", "export",
            "workflow", "dashboard"
        ]
    
    def set_context(self, module: Optional[str] = None, 
                    options: Optional[Dict[str, Any]] = None) -> None:
        """Update the current completion context"""
        self.current_module = module
        if options is not None:
            self.current_options = options
    
    def _parse_line(self, line: str, begidx: int, endidx: int) -> CompletionContext:
        """Parse the current line into completion context"""
        ctx = CompletionContext(line=line, cursor_pos=endidx)
        
        parts = line[:endidx].split()
        text = line[begidx:endidx] if begidx < endidx else ""
        
        if not parts:
            ctx.partial = text
            return ctx
        
        ctx.command = parts[0].lower()
        ctx.partial = text
        ctx.module = self.current_module or ""
        
        if len(parts) > 1:
            ctx.subcommand = parts[1]
        
        return ctx
    
    def complete(self, text: str, state: int) -> Optional[str]:
        """
        Main completion function for readline
        
        Args:
            text: Current word being completed
            state: Completion state (0 for first call, incrementing)
            
        Returns:
            Next completion or None
        """
        if state == 0:
            line = readline.get_line_buffer()
            begidx = readline.get_begidx()
            endidx = readline.get_endidx()
            
            self._completions = self._get_completions(line, begidx, endidx, text)
        
        try:
            return self._completions[state]
        except IndexError:
            return None
    
    def _get_completions(self, line: str, begidx: int, endidx: int, 
                         text: str) -> List[str]:
        """Get completions based on current context"""
        ctx = self._parse_line(line, begidx, endidx)
        
        if begidx == 0 or not ctx.command:
            return self._complete_command(text)
        
        if ctx.command in self._command_completers:
            return self._command_completers[ctx.command](ctx, text)
        
        return []
    
    def _complete_command(self, text: str) -> List[str]:
        """Complete base commands"""
        if not text:
            return self._base_commands
        
        text_lower = text.lower()
        
        exact = [cmd for cmd in self._base_commands 
                 if cmd.startswith(text_lower)]
        
        if exact:
            return exact
        
        suggestions = self.suggestor.suggest_command(text_lower, threshold=0.3)
        return [cmd for cmd, _ in suggestions]
    
    def _complete_use(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'use' command with module names"""
        suggestions = self.suggestor.suggest_module(text, threshold=0.3)
        return [module for module, _ in suggestions]
    
    def _complete_set(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'set' command with options or values"""
        if not self.current_module:
            return []
        
        parts = ctx.line.split()
        
        if len(parts) <= 2:
            return self.suggestor.suggest_options(self.current_module, text)
        
        if len(parts) >= 2:
            option = parts[1].upper()
            return self.suggestor.suggest_option_values(
                self.current_module, option, text
            )
        
        return []
    
    def _complete_unset(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'unset' command with set options"""
        if not self.current_module:
            return []
        
        set_options = list(self.current_options.keys())
        
        if not text:
            return set_options
        
        text_upper = text.upper()
        return [opt for opt in set_options if opt.startswith(text_upper)]
    
    def _complete_show(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'show' command"""
        options = ["modules", "options", "workspaces", "history"]
        
        if not text:
            return options
        
        text_lower = text.lower()
        return [opt for opt in options if opt.startswith(text_lower)]
    
    def _complete_search(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'search' command with module suggestions"""
        suggestions = self.suggestor.suggest_module(text, threshold=0.3)
        return [module for module, _ in suggestions]
    
    def _complete_info(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'info' command with module names"""
        return self._complete_use(ctx, text)
    
    def _complete_help(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'help' command with module names"""
        return self._complete_use(ctx, text)
    
    def _complete_workspace(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'workspace' command"""
        parts = ctx.line.split()
        
        if len(parts) <= 2:
            options = ["list", "create", "switch", "delete"]
            if not text:
                return options
            text_lower = text.lower()
            return [opt for opt in options if opt.startswith(text_lower)]
        
        return []
    
    def _complete_workflow(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'workflow' command"""
        parts = ctx.line.split()
        
        if len(parts) <= 2:
            options = ["list", "create", "run", "delete"]
            if not text:
                return options
            text_lower = text.lower()
            return [opt for opt in options if opt.startswith(text_lower)]
        
        return []
    
    def _complete_results(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'results' command"""
        parts = ctx.line.split()
        
        if len(parts) <= 2:
            options = ["list", "show", "analyze", "export"]
            if not text:
                return options
            text_lower = text.lower()
            return [opt for opt in options if opt.startswith(text_lower)]
        
        return []
    
    def _complete_shortcut(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'shortcut' command"""
        parts = ctx.line.split()
        
        if len(parts) <= 2:
            options = ["create", "list", "run"]
            if not text:
                return options
            text_lower = text.lower()
            return [opt for opt in options if opt.startswith(text_lower)]
        
        return []
    
    def _complete_export(self, ctx: CompletionContext, text: str) -> List[str]:
        """Complete 'export' command"""
        parts = ctx.line.split()
        
        if len(parts) == 3:
            formats = ["json", "html", "txt"]
            if not text:
                return formats
            text_lower = text.lower()
            return [fmt for fmt in formats if fmt.startswith(text_lower)]
        
        return []


def setup_readline_completion(completer: SmartCompleter) -> None:
    """Configure readline with the smart completer"""
    readline.set_completer(completer.complete)
    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind("tab: complete")
    
    try:
        if hasattr(readline, 'backend') and 'libedit' in readline.backend:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
    except AttributeError:
        readline.parse_and_bind("tab: complete")
