#!/usr/bin/env python3
"""
Unified Command Runner for DKrypt.
Handles execution of all modules with integrated logging and result management.
"""

import asyncio
from typing import Any, Dict
from rich.console import Console

from core.logger import logger
from core.result_manager import ResultManager
from core.module_loader import get_loader, DKryptModule
from core.exceptions import DKryptException

console = Console()


class CommandRunner:
    """Unified runner for all DKrypt modules"""
    
    def __init__(self):
        self.loader = get_loader()
        self.result_manager = ResultManager()
    
    def run_module(self, module_name: str, **kwargs) -> Any:
        """Execute a module by name with given parameters"""
        # Try modern module first
        module_cls = self.loader.get_module(module_name)
        if module_cls:
            return self._run_modern_module(module_cls, **kwargs)
        
        # Try legacy module
        legacy_info = self.loader.get_legacy_module(module_name)
        if legacy_info:
            return self._run_legacy_module(legacy_info, **kwargs)
        
        raise DKryptException(
            code="MODULE_NOT_FOUND",
            message=f"Module '{module_name}' not found"
        )
    
    def _run_modern_module(self, module_cls: type[DKryptModule], **kwargs) -> Any:
        """Run a modern DKryptModule"""
        metadata = module_cls.get_metadata()
        
        # Log start
        self._log_start(metadata.name, metadata.description)
        
        try:
            # Instantiate and run
            module_instance = module_cls()
            result = module_instance.run(**kwargs)
            
            # Log success
            logger.info(f"Module {metadata.name} completed successfully")
            
            return result
            
        except Exception as e:
            logger.error(f"Module {metadata.name} failed: {str(e)}")
            raise
    
    def _run_legacy_module(self, legacy_info: Dict[str, Any], **kwargs) -> Any:
        """Run a legacy module"""
        runner = legacy_info['runner']
        description = legacy_info.get('description', '')
        
        # Log start
        self._log_start(legacy_info.get('name', 'Unknown'), description)
        
        try:
            # Check if runner is async
            if asyncio.iscoroutinefunction(runner):
                result = asyncio.run(runner(kwargs))
            else:
                result = runner(kwargs)
            
            logger.info(f"Legacy module completed successfully")
            return result
            
        except Exception as e:
            logger.error(f"Legacy module failed: {str(e)}")
            raise
    
    def _log_start(self, tool_name: str, message: str) -> None:
        """Log module start with banner"""
        try:
            from core.utils import header_banner
            header_banner(tool_name=tool_name)
        except:
            console.print(f"[bold cyan]Starting: {tool_name}[/bold cyan]")
        
        logger.info(f"Running {tool_name}: {message}")
    
    def list_available_modules(self) -> Dict[str, Any]:
        """List all available modules"""
        return self.loader.get_all_modules()


# Global runner instance
_runner = CommandRunner()


def get_runner() -> CommandRunner:
    """Get the global command runner instance"""
    return _runner


def run_module(module_name: str, **kwargs) -> Any:
    """Convenience function to run a module"""
    return _runner.run_module(module_name, **kwargs)
