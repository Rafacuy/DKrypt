#!/usr/bin/env python3
"""
Automatic Module Discovery and Registration System for DKrypt.
Scans modules/ directory and auto-registers all DKryptModule implementations.
"""

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Dict, List, Type, Any, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ModuleMetadata:
    """Metadata for a DKrypt module"""
    name: str
    description: str
    category: str = "general"
    author: str = "DKrypt Team"
    version: str = "1.0.0"


class DKryptModule(ABC):
    """Base class for all DKrypt modules"""
    
    @classmethod
    @abstractmethod
    def get_metadata(cls) -> ModuleMetadata:
        """Return module metadata"""
        pass
    
    @classmethod
    @abstractmethod
    def get_cli_options(cls) -> List[Dict[str, Any]]:
        """Return CLI options specification"""
        pass
    
    @abstractmethod
    def run(self, **kwargs) -> Any:
        """Execute the module with given parameters"""
        pass


class ModuleLoader:
    """Automatically discovers and loads DKrypt modules"""
    
    def __init__(self, modules_path: str = "modules"):
        self.modules_path = Path(modules_path)
        self._registry: Dict[str, Type[DKryptModule]] = {}
        self._legacy_modules: Dict[str, Callable] = {}
    
    def discover_modules(self) -> None:
        """Scan modules directory and register all DKryptModule implementations"""
        if not self.modules_path.exists():
            return
        
        # Import modules package
        import modules
        
        # Scan for submodules
        for importer, modname, ispkg in pkgutil.walk_packages(
            path=[str(self.modules_path)],
            prefix="modules.",
            onerror=lambda x: None
        ):
            try:
                module = importlib.import_module(modname)
                self._scan_module(module)
            except Exception:
                continue
    
    def _scan_module(self, module) -> None:
        """Scan a module for DKryptModule classes"""
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, DKryptModule) and 
                obj is not DKryptModule and
                not inspect.isabstract(obj)):
                metadata = obj.get_metadata()
                self._registry[metadata.name] = obj
    
    def register_legacy_module(self, name: str, runner: Callable, 
                               options: List[Dict[str, Any]], 
                               description: str = "") -> None:
        """Register a legacy module that doesn't use DKryptModule base class"""
        self._legacy_modules[name] = {
            'runner': runner,
            'options': options,
            'description': description
        }
    
    def get_module(self, name: str) -> Type[DKryptModule]:
        """Get a registered module by name"""
        return self._registry.get(name)
    
    def get_legacy_module(self, name: str) -> Dict[str, Any]:
        """Get a legacy module by name"""
        return self._legacy_modules.get(name)
    
    def list_modules(self) -> List[str]:
        """List all registered module names"""
        return list(self._registry.keys()) + list(self._legacy_modules.keys())
    
    def get_all_modules(self) -> Dict[str, Any]:
        """Get all modules (both new and legacy)"""
        result = {}
        for name, cls in self._registry.items():
            result[name] = {
                'type': 'modern',
                'class': cls,
                'metadata': cls.get_metadata()
            }
        for name, info in self._legacy_modules.items():
            result[name] = {
                'type': 'legacy',
                **info
            }
        return result


# Global module loader instance
_loader = ModuleLoader()


def get_loader() -> ModuleLoader:
    """Get the global module loader instance"""
    return _loader


def initialize_modules() -> None:
    """Initialize and discover all modules"""
    _loader.discover_modules()
